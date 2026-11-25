"""绑定信封、事务化发布、崩溃注入与重启恢复。

发布一个索引的持久顺序（每一步关键数据都 fsync / 原子替换）：

    0. 首次授权判定（允许在屏障前完成，以制造 TOCTOU 窗口）
    1. [屏障] 之后重新从磁盘 reload 账本并再次授权 —— 撤销先写则拒绝
    2. 同号异摘要 CAS 检查（current.json 中的摘要必须一致）
    3. journal: INTENT
    4. 最终字段原子落盘 release/indices/<id>.json
    5. journal: MATERIALIZED（此刻起物理上“历史可见”）
    6. （可注入崩溃：最终字段已落盘，但回执/current 尚未写）
    7. 原子写回执 release/receipts/<id>.receipt.json
    8. 原子更新 current.json（当前可见集合）
    9. journal: COMMIT

“重启”= 丢弃内存中的 Publisher/Ledger 对象，用磁盘文件重新构造并 recover()。
"""
from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals import ApprovalLedger, AuthorizationDenied
from .policy import get_policy
from .util import (
    append_jsonl,
    atomic_write_json,
    digest_file,
    digest_obj,
    ensure_dir,
    load_json,
    now_iso,
    read_jsonl,
    short_digest,
)

ENVELOPE_KIND = "leakguard.index/v1"
RECEIPT_KIND = "leakguard.receipt/v1"
CURRENT_NAME = "current.json"


class PublishError(RuntimeError):
    pass


class SimulatedCrash(PublishError):
    """模拟进程在“最终字段落盘后、回执写入前”被杀死。"""


class DigestConflict(PublishError):
    """同一个 index_id 试图绑定与当前指针不同的实际内容摘要（同号异摘要）。"""

    def __init__(self, index_id: str, current_digest: str, attempted_digest: str):
        self.index_id = index_id
        self.current_digest = current_digest
        self.attempted_digest = attempted_digest
        super().__init__(
            f"同号异摘要冲突 {index_id}: current={current_digest} attempted={attempted_digest}"
        )


@dataclass
class PublishResult:
    index_id: str
    content_digest: str
    source_digest: str
    file_path: Path
    decision_reason: str
    committed: bool


def build_envelope(
    *,
    index_id: str,
    source: dict[str, Any],
    tenant: str,
    purpose: str,
    policy_code: str,
    version: int = 1,
    authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造绑定四要素（租户/用途/策略代号/实际内容摘要）的发布信封。"""
    policy = get_policy(policy_code)
    body = policy.project(source)
    content_digest = digest_obj(body)
    source_digest = digest_obj(source)
    envelope: dict[str, Any] = {
        "kind": ENVELOPE_KIND,
        "index_id": index_id,
        "version": version,
        "bindings": {
            "tenant": tenant,
            "purpose": purpose,
            "policy": policy_code,
            "content_digest": content_digest,
        },
        "source_digest": source_digest,
        "body": body,
        "issued_at": now_iso(),
    }
    if authorization:
        envelope["authorization"] = authorization
    return envelope


class Publisher:
    def __init__(self, root: str | Path, ledger: ApprovalLedger | None = None):
        self.root = Path(root)
        self.release = self.root / "release"
        self.indices_dir = self.release / "indices"
        self.receipts_dir = self.release / "receipts"
        self.conflicts_dir = self.release / "conflicts"
        self.pages_dir = self.release / "pages"
        self.state_dir = self.root / "state"
        self.withdrawn_dir = self.root / "withdrawn"
        self.quarantine_dir = self.root / "quarantine"
        for d in (
            self.indices_dir,
            self.receipts_dir,
            self.conflicts_dir,
            self.pages_dir,
            self.state_dir,
            self.withdrawn_dir,
            self.quarantine_dir,
        ):
            ensure_dir(d)
        self.journal_path = self.root / "journal.jsonl"
        self.current_path = self.root / CURRENT_NAME
        self.ledger = ledger or ApprovalLedger(self.root / "approvals.jsonl")
        self._lock = threading.RLock()
        self._current: dict[str, dict[str, Any]] = load_json(self.current_path, {}) or {}

    # ------------------------------------------------------------------ #
    # 日志 / 路径
    # ------------------------------------------------------------------ #
    def _journal(self, etype: str, **fields: Any) -> dict[str, Any]:
        rec = {"type": etype, "at": now_iso(), **fields}
        append_jsonl(self.journal_path, rec)
        return rec

    def _index_rel(self, index_id: str) -> str:
        return f"release/indices/{index_id}.json"

    def _receipt_rel(self, index_id: str) -> str:
        return f"release/receipts/{index_id}.receipt.json"

    def index_path(self, index_id: str) -> Path:
        return self.root / self._index_rel(index_id)

    def receipt_path(self, index_id: str) -> Path:
        return self.root / self._receipt_rel(index_id)

    def _save_current(self) -> None:
        atomic_write_json(self.current_path, self._current)

    # ------------------------------------------------------------------ #
    # 发布
    # ------------------------------------------------------------------ #
    def publish(
        self,
        *,
        index_id: str,
        source: dict[str, Any],
        tenant: str,
        purpose: str,
        policy_code: str,
        version: int = 1,
        gate: threading.Barrier | None = None,
        materialized_barrier: threading.Barrier | None = None,
        prepared: threading.Event | None = None,
        crash_after_materialized: bool = False,
        fresh_disk_recheck: bool = True,
    ) -> PublishResult:
        # 首次授权判定（屏障前，允许先看到 active）。
        envelope = build_envelope(
            index_id=index_id,
            source=source,
            tenant=tenant,
            purpose=purpose,
            policy_code=policy_code,
            version=version,
        )
        digest = envelope["bindings"]["content_digest"]
        initial = self.ledger.authorize(
            tenant=tenant,
            purpose=purpose,
            policy=policy_code,
            index_id=index_id,
            digest=digest,
        )
        # 通知对侧：发布线程已经完成“撤销前”的首次授权判定。
        if prepared is not None:
            prepared.set()
        if not initial.allowed:
            with self._lock:
                self._journal("PUBLISH_DENIED", index_id=index_id, reason=initial.reason)
            raise AuthorizationDenied(initial.reason)

        # 屏障：与另一真实线程的“撤销先写”对齐。
        if gate is not None:
            gate.wait()

        with self._lock:
            # 关键：提交前从磁盘重放账本，确保看到屏障另一侧已 fsync 的撤销。
            if fresh_disk_recheck:
                self.ledger.reload()
            decision = self.ledger.authorize(
                tenant=tenant,
                purpose=purpose,
                policy=policy_code,
                index_id=index_id,
                digest=digest,
            )
            if not decision.allowed:
                self._journal(
                    "PUBLISH_DENIED",
                    index_id=index_id,
                    digest=digest,
                    reason=decision.reason,
                    after_gate=True,
                )
                raise AuthorizationDenied(decision.reason)

            # 同号异摘要 CAS：current 已指向不同摘要 -> 冲突，绝不覆盖胜者。
            cur = self._current.get(index_id)
            if cur is not None and cur.get("content_digest") != digest:
                conflict_file = (
                    self.conflicts_dir / f"{index_id}__{short_digest(digest)}.json"
                )
                envelope["authorization"] = _decision_dict(decision)
                atomic_write_json(conflict_file, envelope)
                self._journal(
                    "DIGEST_CONFLICT",
                    index_id=index_id,
                    current_digest=cur.get("content_digest"),
                    attempted_digest=digest,
                    artifact=str(conflict_file.relative_to(self.root)).replace("\\", "/"),
                )
                raise DigestConflict(index_id, cur.get("content_digest", "?"), digest)

            envelope["authorization"] = _decision_dict(decision)

            # 3. INTENT
            self._journal(
                "PUBLISH_INTENT",
                index_id=index_id,
                digest=digest,
                tenant=tenant,
                purpose=purpose,
                policy=policy_code,
            )

            # 4. 最终字段原子落盘
            ipath = self.index_path(index_id)
            atomic_write_json(ipath, envelope)
            file_sha = digest_file(ipath)

            # 5. MATERIALIZED —— 此后历史可见
            self._journal(
                "MATERIALIZED",
                index_id=index_id,
                digest=digest,
                file=self._index_rel(index_id),
                file_sha256=file_sha,
            )

            # 供第二个线程在精确窗口观察：字段已落盘、回执尚不存在。
            if materialized_barrier is not None:
                materialized_barrier.wait()

            # 6. 崩溃注入：回执永远不会被写。
            if crash_after_materialized:
                raise SimulatedCrash(
                    f"simulated crash after fields durable, receipt lost for {index_id}"
                )

            entry = self._commit_receipt_and_current(
                envelope=envelope,
                decision=decision,
                file_sha=file_sha,
                version=version,
            )
            self._journal("PUBLISH_COMMIT", index_id=index_id, digest=digest, entry=entry)
            return PublishResult(
                index_id=index_id,
                content_digest=digest,
                source_digest=envelope["source_digest"],
                file_path=ipath,
                decision_reason=decision.reason,
                committed=True,
            )

    def _commit_receipt_and_current(
        self,
        *,
        envelope: dict[str, Any],
        decision: Any,
        file_sha: str,
        version: int,
    ) -> dict[str, Any]:
        index_id = envelope["index_id"]
        digest = envelope["bindings"]["content_digest"]
        receipt = {
            "kind": RECEIPT_KIND,
            "index_id": index_id,
            "version": version,
            "bindings": envelope["bindings"],
            "file": self._index_rel(index_id),
            "file_sha256": file_sha,
            "authorization": _decision_dict(decision),
            "issued_at": now_iso(),
        }
        atomic_write_json(self.receipt_path(index_id), receipt)
        entry = {
            "index_id": index_id,
            "version": version,
            **envelope["bindings"],
            "source_digest": envelope["source_digest"],
            "file": self._index_rel(index_id),
            "receipt": self._receipt_rel(index_id),
            "file_sha256": file_sha,
            "authorization": _decision_dict(decision),
            "committed_at": now_iso(),
        }
        self._current[index_id] = entry
        self._save_current()
        return entry

    # ------------------------------------------------------------------ #
    # 撤销后的在线回退（不等重启）
    # ------------------------------------------------------------------ #
    def withdraw_revoked(self) -> list[str]:
        removed: list[str] = []
        with self._lock:
            for index_id in list(self._current.keys()):
                entry = self._current[index_id]
                d = self.ledger.authorize(
                    tenant=entry["tenant"],
                    purpose=entry["purpose"],
                    policy=entry["policy"],
                    index_id=index_id,
                    digest=entry["content_digest"],
                )
                if d.allowed:
                    continue
                self._withdraw_entry(index_id, entry, d.reason, event="WITHDRAWN")
                removed.append(index_id)
            if removed:
                self._save_current()
        return removed

    def _withdraw_entry(self, index_id: str, entry: dict[str, Any], reason: str, *, event: str) -> None:
        src = self.root / entry["file"]
        dest = self.withdrawn_dir / f"{index_id}__{short_digest(entry['content_digest'])}.json"
        if src.exists():
            ensure_dir(dest.parent)
            shutil.move(str(src), str(dest))
        receipt = self.receipt_path(index_id)
        if receipt.exists():
            try:
                receipt.unlink()
            except OSError:
                pass
        self._current.pop(index_id, None)
        self._journal(event, index_id=index_id, digest=entry.get("content_digest"), reason=reason,
                      archived=str(dest.relative_to(self.root)).replace("\\", "/"))

    # ------------------------------------------------------------------ #
    # 重启恢复 / 对账
    # ------------------------------------------------------------------ #
    def recover(self) -> dict[str, Any]:
        """从磁盘重新对账，返回结构化报告（含历史可见与当前集合）。"""
        with self._lock:
            self.ledger.reload()
            self._current = load_json(self.current_path, {}) or {}
            actions: dict[str, list[str]] = {
                "recovered_commit": [],
                "withdrawn_unauthorized": [],
                "quarantined_bad_file": [],
                "quarantined_orphan": [],
                "quarantined_divergent": [],
                "conflicts_parked": [],
                "receipt_repaired": [],
            }

            # 0) release/conflicts 下的候选永远不是当前版本，重启后隔离保全。
            if self.conflicts_dir.exists():
                for cf in sorted(self.conflicts_dir.glob("*.json")):
                    dest = self.quarantine_dir / "conflicts" / cf.name
                    ensure_dir(dest.parent)
                    shutil.move(str(cf), str(dest))
                    actions["conflicts_parked"].append(cf.name)

            # 1) 先校验已有 current 指针。
            for index_id in list(self._current.keys()):
                entry = self._current[index_id]
                ipath = self.root / entry["file"]
                problem = self._validate_index_file(ipath, expect_digest=entry.get("content_digest"))
                decision = self.ledger.authorize(
                    tenant=entry.get("tenant", ""),
                    purpose=entry.get("purpose", ""),
                    policy=entry.get("policy", ""),
                    index_id=index_id,
                    digest=entry.get("content_digest", ""),
                )
                if problem == "ok" and decision.allowed:
                    # 回执丢失但 current 还在：补回执（幂等）。
                    rpath = self.root / entry["receipt"]
                    if not rpath.exists():
                        env = json.loads(ipath.read_text(encoding="utf-8"))
                        self._commit_receipt_and_current(
                            envelope=env,
                            decision=decision,
                            file_sha=entry.get("file_sha256", digest_file(ipath)),
                            version=int(entry.get("version", 1)),
                        )
                        actions["receipt_repaired"].append(index_id)
                    continue
                if problem and problem.startswith("bad:"):
                    self._quarantine_file(ipath, "bad_current_" + problem.split(":", 1)[1])
                    actions["quarantined_bad_file"].append(index_id)
                    self._current.pop(index_id, None)
                else:
                    # 授权失效：有效文件移入 withdrawn，当前集合移除。
                    self._withdraw_entry(index_id, entry, decision.reason, event="RECOVERY_WITHDRAWN")
                    actions["withdrawn_unauthorized"].append(index_id)
            self._save_current()

            # 2) 扫描 release/indices 下所有实际文件，处理“字段落盘/回执丢失”等。
            for ipath in sorted(self.indices_dir.glob("*.json")):
                problem = self._validate_index_file(ipath)
                if problem and problem.startswith("bad:"):
                    reason = problem.split(":", 1)[1]
                    self._quarantine_file(ipath, "invalid_" + reason)
                    actions["quarantined_bad_file"].append(ipath.name)
                    continue

                env = json.loads(ipath.read_text(encoding="utf-8"))
                index_id = env["index_id"]
                digest = env["bindings"]["content_digest"]
                cur = self._current.get(index_id)

                if cur is not None and cur.get("content_digest") == digest:
                    continue  # 已一致提交。

                if cur is not None and cur.get("content_digest") != digest:
                    # 磁盘上出现与当前指针不同摘要的同号文件：隔离为分歧件。
                    dest = self.quarantine_dir / "divergent" / ipath.name
                    ensure_dir(dest.parent)
                    shutil.move(str(ipath), str(dest))
                    actions["quarantined_divergent"].append(ipath.name)
                    self._journal("RECOVERY_DIVERGENT", index_id=index_id, digest=digest,
                                  current_digest=cur["content_digest"])
                    continue

                # 无 current 指针：依据日志来源 + 当前授权决定补提交 / 回退 / 隔离。
                provenance = self._has_provenance(index_id, digest)
                decision = self.ledger.authorize(
                    tenant=env["bindings"]["tenant"],
                    purpose=env["bindings"]["purpose"],
                    policy=env["bindings"]["policy"],
                    index_id=index_id,
                    digest=digest,
                )
                if decision.allowed and provenance:
                    file_sha = digest_file(ipath)
                    env.setdefault("authorization", _decision_dict(decision))
                    entry = self._commit_receipt_and_current(
                        envelope=env, decision=decision, file_sha=file_sha,
                        version=int(env.get("version", 1)),
                    )
                    self._journal("RECOVERED_COMMIT", index_id=index_id, digest=digest,
                                  reason="fields_durable_receipt_lost", entry=entry)
                    actions["recovered_commit"].append(index_id)
                elif not decision.allowed:
                    entry = {
                        "content_digest": digest,
                        "tenant": env["bindings"]["tenant"],
                        "purpose": env["bindings"]["purpose"],
                        "policy": env["bindings"]["policy"],
                    }
                    dest = self.withdrawn_dir / f"{index_id}__{short_digest(digest)}.json"
                    ensure_dir(dest.parent)
                    shutil.move(str(ipath), str(dest))
                    self._journal("RECOVERY_WITHDRAWN", index_id=index_id, digest=digest,
                                  reason=decision.reason)
                    actions["withdrawn_unauthorized"].append(index_id)
                else:
                    self._quarantine_file(ipath, "orphan_no_intent")
                    actions["quarantined_orphan"].append(ipath.name)

            self._save_current()
            report = self.visibility_report()
            report["recovery_actions"] = actions
            return report

    def _validate_index_file(self, path: Path, expect_digest: str | None = None) -> str:
        if not path.exists():
            return "bad:missing"
        try:
            env = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "bad:invalid_json"
        if not isinstance(env, dict) or env.get("kind") != ENVELOPE_KIND:
            return "bad:not_envelope"
        b = env.get("bindings")
        body = env.get("body")
        if not isinstance(b, dict) or not all(
            k in b for k in ("tenant", "purpose", "policy", "content_digest")
        ):
            return "bad:missing_bindings"
        actual = digest_obj(body)
        if actual != b["content_digest"]:
            return "bad:digest_mismatch"
        if expect_digest is not None and expect_digest != b["content_digest"]:
            return "bad:entry_digest_mismatch"
        return "ok"

    def _has_provenance(self, index_id: str, digest: str) -> bool:
        for rec in read_jsonl(self.journal_path):
            if rec.get("index_id") != index_id or rec.get("digest") != digest:
                continue
            if rec.get("type") in {"PUBLISH_INTENT", "MATERIALIZED", "PUBLISH_COMMIT"}:
                return True
        return False

    def _quarantine_file(self, path: Path, reason: str) -> None:
        if not path.exists():
            return
        dest = self.quarantine_dir / reason / path.name
        ensure_dir(dest.parent)
        shutil.move(str(path), str(dest))
        self._journal("QUARANTINED", file=path.name, reason=reason,
                      archived=str(dest.relative_to(self.root)).replace("\\", "/"))

    # ------------------------------------------------------------------ #
    # 可见性报告
    # ------------------------------------------------------------------ #
    def visibility_report(self) -> dict[str, Any]:
        events = read_jsonl(self.journal_path)
        visible_types = {"MATERIALIZED", "PUBLISH_COMMIT", "RECOVERED_COMMIT"}
        history: dict[str, dict[str, Any]] = {}
        for seq, rec in enumerate(events, 1):
            iid = rec.get("index_id")
            if not iid or rec.get("type") not in visible_types:
                continue
            h = history.setdefault(
                iid,
                {"index_id": iid, "digests": [], "first_visible_event": rec["type"],
                 "first_visible_order": seq},
            )
            d = rec.get("digest")
            if d and d not in h["digests"]:
                h["digests"].append(d)
        current = load_json(self.current_path, {}) or {}
        return {
            "history_visible_ids": sorted(history),
            "history_visible": [history[k] for k in sorted(history)],
            "current_visible_ids": sorted(current.keys()),
            "current_visible": [
                {
                    "index_id": k,
                    "tenant": current[k]["tenant"],
                    "purpose": current[k]["purpose"],
                    "policy": current[k]["policy"],
                    "content_digest": current[k]["content_digest"],
                }
                for k in sorted(current)
            ],
            "current_count": len(current),
            "history_count": len(history),
        }


def _decision_dict(decision: Any) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "source_key": decision.source_key,
        "group_id": decision.group_id,
        "grant_seq": decision.grant_seq,
    }

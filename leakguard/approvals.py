"""批准账本：同源批准幂等去重、按组授权与撤销、组间隔离、JSONL 持久化。

关键不变量
----------
1. 每个来源批准由 ``source_key``（来源系统 + 来源批准单号的稳定标识）唯一确定；
   重复提交（含两个线程同时提交）只产生一条授权、计数为 1。
2. 授权归属于一个 ``group_id``（审查组）。撤销只按组写入撤销墓碑，
   A 组撤销不会改变 B 组任何授权的有效性。
3. 所有状态都可由 fsync 的 JSONL 事件日志重放得到；``reload/load`` 模拟重启后
   从磁盘重新接管，不依赖任何内存状态。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import append_jsonl, now_iso, read_jsonl


class ApprovalError(RuntimeError):
    pass


class AuthorizationDenied(ApprovalError):
    """没有覆盖该 (租户, 用途, 策略, 索引, 摘要) 的有效批准，或所在组已撤销。"""


@dataclass(frozen=True)
class AuthDecision:
    allowed: bool
    reason: str
    source_key: str | None = None
    group_id: str | None = None
    grant_seq: int | None = None


class ApprovalLedger:
    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self._lock = threading.RLock()
        self._seq = 0
        self._events: list[dict[str, Any]] = []
        self._by_source: dict[str, dict[str, Any]] = {}
        self._grants: list[dict[str, Any]] = []
        self._revoked_groups: dict[str, dict[str, Any]] = {}
        self.reload()

    # ------------------------------------------------------------------ #
    # 持久化 / 重放
    # ------------------------------------------------------------------ #
    def reload(self) -> "ApprovalLedger":
        with self._lock:
            self._seq = 0
            self._events = []
            self._by_source = {}
            self._grants = []
            self._revoked_groups = {}
            for rec in read_jsonl(self.log_path):
                self._apply(rec, persist=False)
            return self

    @classmethod
    def load(cls, log_path: str | Path) -> "ApprovalLedger":
        return cls(log_path)

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _apply(self, rec: dict[str, Any], *, persist: bool) -> dict[str, Any]:
        etype = rec["type"]
        if etype == "grant":
            source_key = rec["source_key"]
            if source_key in self._by_source:
                # 重放/并发中的重复同源事件：绝不计第二份。
                return self._by_source[source_key]
            if persist:
                rec["seq"] = self._next_seq()
                rec.setdefault("at", now_iso())
                append_jsonl(self.log_path, rec)
            else:
                self._seq = max(self._seq, int(rec.get("seq", 0)))
            self._events.append(rec)
            self._by_source[source_key] = rec
            self._grants.append(rec)
            return rec
        if etype == "revoke_group":
            gid = rec["group_id"]
            if persist:
                rec["seq"] = self._next_seq()
                rec.setdefault("at", now_iso())
                append_jsonl(self.log_path, rec)
            else:
                self._seq = max(self._seq, int(rec.get("seq", 0)))
            self._events.append(rec)
            # 重复撤销同一组幂等：保留第一次墓碑。
            self._revoked_groups.setdefault(gid, rec)
            return rec
        raise ApprovalError(f"未知账本事件类型: {etype!r}")

    # ------------------------------------------------------------------ #
    # 写操作
    # ------------------------------------------------------------------ #
    def grant(
        self,
        *,
        source_key: str,
        group_id: str,
        tenant: str,
        purpose: str,
        policy: str,
        index_ids: list[str] | tuple[str, ...] | set[str] | None = None,
        digests: list[str] | tuple[str, ...] | set[str] | None = None,
        principal: str = "synthetic-source",
    ) -> tuple[dict[str, Any], bool]:
        """登记一份来源批准。返回 (授权事件, 是否新建)。重复同源 -> created=False。"""
        with self._lock:
            existing = self._by_source.get(source_key)
            if existing is not None:
                return existing, False
            rec: dict[str, Any] = {
                "type": "grant",
                "source_key": source_key,
                "group_id": group_id,
                "tenant": tenant,
                "purpose": purpose,
                "policy": policy,
                "index_ids": sorted(index_ids) if index_ids else None,
                "digests": sorted(digests) if digests else None,
                "principal": principal,
            }
            applied = self._apply(rec, persist=True)
            return applied, True

    def revoke_group(self, group_id: str, reason: str = "") -> tuple[dict[str, Any], bool]:
        """撤销整个审查组的批准。幂等；不触碰任何其它组。"""
        with self._lock:
            if group_id in self._revoked_groups:
                return self._revoked_groups[group_id], False
            rec = {"type": "revoke_group", "group_id": group_id, "reason": reason}
            applied = self._apply(rec, persist=True)
            return applied, True

    # ------------------------------------------------------------------ #
    # 读 / 判定
    # ------------------------------------------------------------------ #
    def is_group_revoked(self, group_id: str) -> bool:
        with self._lock:
            return group_id in self._revoked_groups

    def distinct_source_count(self) -> int:
        with self._lock:
            return len(self._by_source)

    def grants_in_group(self, group_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [g for g in self._grants if g["group_id"] == group_id]

    def active_grants(self) -> list[dict[str, Any]]:
        with self._lock:
            return [g for g in self._grants if g["group_id"] not in self._revoked_groups]

    def authorize(
        self,
        *,
        tenant: str,
        purpose: str,
        policy: str,
        index_id: str,
        digest: str,
    ) -> AuthDecision:
        with self._lock:
            for g in self._grants:
                if g["group_id"] in self._revoked_groups:
                    continue
                if g["tenant"] != tenant or g["purpose"] != purpose or g["policy"] != policy:
                    continue
                ids = g.get("index_ids")
                if ids and index_id not in ids:
                    continue
                digests = g.get("digests")
                if digests and digest not in digests:
                    continue
                return AuthDecision(
                    True,
                    "active_grant",
                    source_key=g["source_key"],
                    group_id=g["group_id"],
                    grant_seq=int(g["seq"]),
                )
            # 给出更精确的拒绝原因。
            for g in self._grants:
                if g["tenant"] == tenant and g["purpose"] == purpose and g["policy"] == policy:
                    if g["group_id"] in self._revoked_groups:
                        return AuthDecision(False, f"group_revoked:{g['group_id']}")
            return AuthDecision(False, "no_matching_grant")

    def require(self, **kwargs: Any) -> AuthDecision:
        decision = self.authorize(**kwargs)
        if not decision.allowed:
            raise AuthorizationDenied(decision.reason)
        return decision

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "events": len(self._events),
                "distinct_sources": len(self._by_source),
                "grants": len(self._grants),
                "revoked_groups": sorted(self._revoked_groups),
                "groups": sorted({g["group_id"] for g in self._grants}),
            }

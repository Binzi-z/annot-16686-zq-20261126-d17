"""屏障 + 两个真实线程，确定性复现三类棘手情形，并在“重启”后报告可见性。

三个场景各自使用独立磁盘目录：
A. revoke_first            撤销事件先 fsync 落盘，发布线程过屏障后重放账本 -> 拒绝
B. receipt_lost            最终字段原子落盘，回执尚未写即“崩溃”；另一线程在屏障
                           另一侧亲眼观察到 field=present / receipt=absent；重启补提交
C. same_id_diff_digest     两个真实线程用 Barrier 同时提交同号异摘要 -> CAS 一胜一冲突

另含 same_source_concurrent：两个线程并发提交同一 source_key，仍只算一份批准。
"""
from __future__ import annotations

import threading
import traceback
from pathlib import Path
from typing import Any, Callable

from .approvals import ApprovalLedger, AuthorizationDenied
from .publisher import DigestConflict, Publisher, SimulatedCrash

TENANT = "t-lab"
PURPOSE = "lab-run"
POLICY = "POL-INDEX-MASKED-V2"


def _thread_tag() -> dict[str, Any]:
    t = threading.current_thread()
    return {"name": t.name, "ident": t.ident, "native_id": getattr(t, "native_id", None)}


def _lab_source(tag: str, *, title_suffix: str = "") -> dict[str, Any]:
    return {
        "ref": f"LAB-{tag}",
        "category": "lab",
        "title": f"lab object {tag} {title_suffix}".strip(),
        "status": "open",
        "tags": ["lab", ["nested", {"ok": True}]],
        "party": {"name": "Lab Board", "role": "test"},
        "legal_hold": "source-hold-value",
        "ssn": "000-00-0000",  # 必须被脱敏，不会出现在发布文件
    }


def _join_pair(t1: threading.Thread, t2: threading.Thread, timeout: float = 30.0) -> None:
    t1.join(timeout)
    t2.join(timeout)
    if t1.is_alive() or t2.is_alive():
        raise RuntimeError("屏障实验线程在超时后仍未结束（可能死锁）")


def _fresh_publisher(root: Path) -> Publisher:
    """模拟重启：从磁盘重新加载账本与 current，不继承任何内存状态。"""
    ledger = ApprovalLedger.load(root / "approvals.jsonl")
    return Publisher(root, ledger)


# --------------------------------------------------------------------------- #
# A. 撤销先写
# --------------------------------------------------------------------------- #
def scenario_revoke_first(base: Path) -> dict[str, Any]:
    root = base / "A_revoke_first"
    ledger = ApprovalLedger(root / "approvals.jsonl")
    iid = "LAB-A1"
    ledger.grant(
        source_key="SRC-LAB-A", group_id="grp-lab-a",
        tenant=TENANT, purpose=PURPOSE, policy=POLICY, index_ids=[iid],
    )
    publisher = Publisher(root, ledger)
    # prepared：发布线程已通过“撤销前”的首次授权；commit_gate：撤销落盘后共同放行。
    prepared = threading.Event()
    commit_gate = threading.Barrier(2)
    out: dict[str, Any] = {"scenario": "revoke_first", "index_id": iid}

    def revoker() -> None:
        out["revoker_thread"] = _thread_tag()
        # 先等发布线程完成首次（此时仍 active 的）授权判定。
        if not prepared.wait(timeout=15):
            out["revoker_prepared_timeout"] = True
        # 关键顺序：在到达提交屏障 *之前* 把撤销墓碑 fsync 落盘（撤销先写）。
        ev, created = ledger.revoke_group("grp-lab-a", reason="barrier-ordering")
        out["revoke_event"] = {"seq": ev["seq"], "created": created}
        try:
            commit_gate.wait(timeout=15)
        except threading.BrokenBarrierError:
            out["revoker_barrier_broken"] = True

    def pub() -> None:
        out["publisher_thread"] = _thread_tag()
        try:
            publisher.publish(
                index_id=iid, source=_lab_source("A"),
                tenant=TENANT, purpose=PURPOSE, policy_code=POLICY,
                prepared=prepared, gate=commit_gate,
            )
            out["publish_outcome"] = {"state": "committed"}
        except AuthorizationDenied as exc:
            out["publish_outcome"] = {"state": "denied", "reason": str(exc)}
        except Exception as exc:  # noqa: BLE001 - 实验需要回收任何异常作为证据
            out["publish_outcome"] = {
                "state": "error", "type": type(exc).__name__, "detail": str(exc),
                "trace": traceback.format_exc(limit=3),
            }

    tr = threading.Thread(target=revoker, name="A-revoker")
    tp = threading.Thread(target=pub, name="A-publisher")
    tr.start(); tp.start()
    _join_pair(tr, tp)

    out["distinct_threads"] = (
        out.get("revoker_thread", {}).get("ident")
        != out.get("publisher_thread", {}).get("ident")
        and threading.main_thread().ident
        not in (out.get("revoker_thread", {}).get("ident"),
                out.get("publisher_thread", {}).get("ident"))
    )
    out["field_file_exists_after_race"] = publisher.index_path(iid).exists()
    out["receipt_exists_after_race"] = publisher.receipt_path(iid).exists()

    restarted = _fresh_publisher(root)
    out["restart_report"] = restarted.recover()
    out["release_dir"] = str(root / "release")
    out["expect"] = "publish denied by revoke-first; nothing ever visible"
    out["passed"] = (
        out["publish_outcome"]["state"] == "denied"
        and out["publish_outcome"]["reason"].startswith("group_revoked")
        and not out["field_file_exists_after_race"]
        and out["restart_report"]["history_count"] == 0
        and out["restart_report"]["current_count"] == 0
        and out["distinct_threads"]
    )
    return out


# --------------------------------------------------------------------------- #
# B. 最终字段落盘但回执丢失
# --------------------------------------------------------------------------- #
def scenario_receipt_lost(base: Path) -> dict[str, Any]:
    root = base / "B_receipt_lost"
    ledger = ApprovalLedger(root / "approvals.jsonl")
    iid = "LAB-B1"
    ledger.grant(
        source_key="SRC-LAB-B", group_id="grp-lab-b",
        tenant=TENANT, purpose=PURPOSE, policy=POLICY, index_ids=[iid],
    )
    publisher = Publisher(root, ledger)
    mb = threading.Barrier(2)
    out: dict[str, Any] = {"scenario": "receipt_lost", "index_id": iid}

    def writer() -> None:
        out["writer_thread"] = _thread_tag()
        try:
            publisher.publish(
                index_id=iid, source=_lab_source("B"),
                tenant=TENANT, purpose=PURPOSE, policy_code=POLICY,
                materialized_barrier=mb, crash_after_materialized=True,
            )
            out["writer_outcome"] = {"state": "unexpected_return"}
        except SimulatedCrash as exc:
            out["writer_outcome"] = {"state": "simulated_crash", "detail": str(exc)}
        except Exception as exc:  # noqa: BLE001
            out["writer_outcome"] = {"state": "error", "type": type(exc).__name__, "detail": str(exc)}

    def watcher() -> None:
        # 与写线程在 MATERIALIZED 之后会合：此刻字段已 fsync，回执还没写。
        try:
            mb.wait(timeout=15)
        except threading.BrokenBarrierError:
            out["watcher_barrier_broken"] = True
            return
        ip = publisher.index_path(iid)
        rp = publisher.receipt_path(iid)
        out["watcher_thread"] = _thread_tag()
        out["crash_window_observation"] = {
            "final_fields_on_disk": ip.exists(),
            "field_bytes": ip.stat().st_size if ip.exists() else 0,
            "receipt_exists": rp.exists(),
            "current_json_exists": publisher.current_path.exists(),
        }

    tw = threading.Thread(target=writer, name="B-writer")
    to = threading.Thread(target=watcher, name="B-watcher")
    tw.start(); to.start()
    _join_pair(tw, to)

    out["distinct_threads"] = (
        out.get("writer_thread", {}).get("ident")
        != out.get("watcher_thread", {}).get("ident")
        and threading.main_thread().ident
        not in (out.get("writer_thread", {}).get("ident"),
                out.get("watcher_thread", {}).get("ident"))
    )
    out["on_disk_before_restart"] = {
        "field": publisher.index_path(iid).exists(),
        "receipt": publisher.receipt_path(iid).exists(),
        "current": publisher.current_path.exists(),
    }

    # 第一次重启：应识别“字段持久 + 日志来源 + 授权有效”，幂等补提交。
    restarted = _fresh_publisher(root)
    report1 = restarted.recover()
    out["restart_report"] = report1

    # 第二次重启：不得重复补提交/重复计数。
    again = _fresh_publisher(root)
    report2 = again.recover()
    out["second_restart_report"] = {
        "recovered_commit": report2["recovery_actions"]["recovered_commit"],
        "current_visible_ids": report2["current_visible_ids"],
        "history_count": report2["history_count"],
    }
    out["receipt_after_recovery"] = restarted.receipt_path(iid).exists()
    obs = out.get("crash_window_observation", {})
    out["release_dir"] = str(root / "release")
    out["passed"] = (
        out["writer_outcome"]["state"] == "simulated_crash"
        and obs.get("final_fields_on_disk") is True
        and obs.get("receipt_exists") is False
        and out["on_disk_before_restart"] == {"field": True, "receipt": False, "current": False}
        and report1["recovery_actions"]["recovered_commit"] == [iid]
        and report1["current_visible_ids"] == [iid]
        and iid in report1["history_visible_ids"]
        and out["receipt_after_recovery"] is True
        and report2["recovery_actions"]["recovered_commit"] == []
        and report2["current_visible_ids"] == [iid]
        and out["distinct_threads"]
    )
    return out


# --------------------------------------------------------------------------- #
# C. 同号异摘要
# --------------------------------------------------------------------------- #
def scenario_same_id_diff_digest(base: Path) -> dict[str, Any]:
    root = base / "C_same_id_diff_digest"
    ledger = ApprovalLedger(root / "approvals.jsonl")
    iid = "LAB-C1"
    ledger.grant(
        source_key="SRC-LAB-C", group_id="grp-lab-c",
        tenant=TENANT, purpose=PURPOSE, policy=POLICY,
        # 不钉死摘要：让两个不同内容都通过授权，冲突应来自同号摘要 CAS。
    )
    publisher = Publisher(root, ledger)
    barrier = threading.Barrier(2)
    outcomes: dict[str, dict[str, Any]] = {}
    out: dict[str, Any] = {"scenario": "same_id_diff_digest", "index_id": iid, "outcomes": outcomes}

    def worker(label: str, suffix: str) -> Callable[[], None]:
        def run() -> None:
            tag = _thread_tag()
            try:
                barrier.wait(timeout=15)
            except threading.BrokenBarrierError:
                outcomes[label] = {"state": "barrier_broken", "thread": tag}
                return
            try:
                res = publisher.publish(
                    index_id=iid, source=_lab_source("C", title_suffix=suffix),
                    tenant=TENANT, purpose=PURPOSE, policy_code=POLICY,
                )
                outcomes[label] = {"state": "committed", "digest": res.content_digest, "thread": tag}
            except DigestConflict as exc:
                outcomes[label] = {
                    "state": "digest_conflict",
                    "current_digest": exc.current_digest,
                    "attempted_digest": exc.attempted_digest,
                    "thread": tag,
                }
            except Exception as exc:  # noqa: BLE001
                outcomes[label] = {"state": "error", "type": type(exc).__name__, "detail": str(exc)}
        return run

    t1 = threading.Thread(target=worker("t1", "alpha-content"), name="C-pub-1")
    t2 = threading.Thread(target=worker("t2", "beta-content-different"), name="C-pub-2")
    t1.start(); t2.start()
    _join_pair(t1, t2)

    states = sorted(o.get("state") for o in outcomes.values())
    digests = {o.get("digest") or o.get("attempted_digest") for o in outcomes.values()}
    out["states"] = states
    out["distinct_digests"] = sorted(d for d in digests if d)
    threads = [o.get("thread", {}).get("ident") for o in outcomes.values()]
    out["distinct_threads"] = len(threads) == 2 and threads[0] != threads[1] and (
        threading.main_thread().ident not in threads
    )
    out["conflict_artifacts"] = sorted(
        p.name for p in (root / "release" / "conflicts").glob("*.json")
    ) if (root / "release" / "conflicts").exists() else []

    # 恢复前快照：保留真实竞态落盘的 winner + conflict，供独立验证器扫描。
    import shutil
    snapshot = base / "C_pre_recovery_snapshot"
    if snapshot.exists():
        shutil.rmtree(snapshot)
    shutil.copytree(root / "release", snapshot)
    out["pre_recovery_snapshot"] = str(snapshot)

    # 重启：隔离冲突候选，当前集合只保留唯一胜者。
    restarted = _fresh_publisher(root)
    report = restarted.recover()
    out["restart_report"] = report
    out["release_dir_before_restart"] = str(root / "release")
    out["release_dir_after_restart"] = str(root / "release")
    out["passed"] = (
        states == ["committed", "digest_conflict"]
        and len(out["distinct_digests"]) == 2
        and len(out["conflict_artifacts"]) == 1
        and report["current_count"] == 1
        and report["recovery_actions"]["conflicts_parked"]
        and out["distinct_threads"]
    )
    return out


# --------------------------------------------------------------------------- #
# 额外：同源批准的并发幂等
# --------------------------------------------------------------------------- #
def concurrent_same_source_grant(base: Path) -> dict[str, Any]:
    root = base / "D_same_source_dedup"
    ledger = ApprovalLedger(root / "approvals.jsonl")
    barrier = threading.Barrier(2)
    results: list[tuple[bool, int]] = []
    tag_lock = threading.Lock()
    threads: list[dict[str, Any]] = []

    def granter() -> None:
        t = _thread_tag()
        with tag_lock:
            threads.append(t)
        barrier.wait(timeout=15)
        _ev, created = ledger.grant(
            source_key="SRC-DUP-1", group_id="grp-dup",
            tenant=TENANT, purpose=PURPOSE, policy=POLICY,
        )
        with tag_lock:
            results.append((created, _ev["seq"]))

    t1 = threading.Thread(target=granter, name="D-grant-1")
    t2 = threading.Thread(target=granter, name="D-grant-2")
    t1.start(); t2.start()
    _join_pair(t1, t2)

    out = {
        "scenario": "same_source_concurrent_dedup",
        "results": [{"created": c, "seq": s} for c, s in results],
        "distinct_source_count": ledger.distinct_source_count(),
        "threads": threads,
    }
    # 重启后从磁盘重放，计数仍为 1，事件里也只有一条 grant。
    reloaded = ApprovalLedger.load(root / "approvals.jsonl")
    out["distinct_source_count_after_restart"] = reloaded.distinct_source_count()
    out["passed"] = (
        sorted(c for c, _ in results) == [False, True]
        and ledger.distinct_source_count() == 1
        and reloaded.distinct_source_count() == 1
        and len({t["ident"] for t in threads}) == 2
    )
    return out


def run_lab(artifacts_root: str | Path) -> dict[str, Any]:
    base = Path(artifacts_root) / "lab"
    base.mkdir(parents=True, exist_ok=True)
    report = {
        "A_revoke_first": scenario_revoke_first(base),
        "B_receipt_lost": scenario_receipt_lost(base),
        "C_same_id_diff_digest": scenario_same_id_diff_digest(base),
        "D_same_source_dedup": concurrent_same_source_grant(base),
    }
    report["all_passed"] = all(v.get("passed") for k, v in report.items() if isinstance(v, dict))
    return report

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键端到端验证（原生 Windows Python 3.12，仅标准库）。

    python run_all.py

阶段：
  1. 主导出：同源批准去重、两组独立授权、三类标记陷阱、分页/manifest
  2. 独立验证器子进程扫描“实际发布文件”（干净 release 必须 PASS）
  3. 撤销 A 组 -> A 索引回退、B 组不受影响；重启报告历史可见 vs 当前集合
  4. 独立验证器扫描四类负例，必须全部检出
  5. Barrier 双线程三场景 + 同源并发去重；C 场景恢复前后分别由验证器扫描
  6. 60000 本地对象计数 + 单次更新读写范围计量与独立磁盘差分复核

最终写 artifacts/RUN_REPORT.json；全部断言通过退出 0，否则退出 1。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from leakguard.approvals import ApprovalLedger  # noqa: E402
from leakguard.bench import run_bench  # noqa: E402
from leakguard.exporter import render_pages, write_manifest  # noqa: E402
from leakguard.lab import run_lab  # noqa: E402
from leakguard.negative import build_all_negative_fixtures  # noqa: E402
from leakguard.publisher import Publisher  # noqa: E402
from leakguard.synthdata import (  # noqa: E402
    ALPHA, ALL_CANARIES, BETA, demo_publications,
)
from leakguard.util import force_utf8_stdio  # noqa: E402

force_utf8_stdio()

ART = ROOT / "artifacts"
REPORTS = ART / "reports"
checks: list[dict[str, Any]] = []


def check(area: str, name: str, ok: bool, detail: Any = "") -> bool:
    checks.append({"area": area, "name": name, "ok": bool(ok), "detail": detail})
    flag = "PASS" if ok else "FAIL"
    print(f"  [{flag}] {area} :: {name}" + (f" — {detail}" if detail and not ok else ""))
    return bool(ok)


def run_independent_validator(
    release: Path, tag: str, *, canaries: Path | None = None,
    require_manifest: bool = False,
) -> tuple[int, dict[str, Any] | None, str]:
    REPORTS.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS / f"validator_{tag}.json"
    cmd = [
        sys.executable, str(ROOT / "verify_release.py"),
        str(release), "--report-json", str(report_path),
    ]
    if canaries is not None:
        cmd += ["--canaries", str(canaries)]
    if require_manifest:
        cmd.append("--require-manifest")
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", cwd=str(ROOT),
    )
    report: dict[str, Any] | None = None
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, report, output


def main() -> int:
    if ART.exists():
        shutil.rmtree(ART)
    REPORTS.mkdir(parents=True, exist_ok=True)

    print("=" * 78)
    print("leakguard 离线脱敏导出 + 独立验证器 + 并发恢复 + 60k 范围复核")
    print(f"Python {sys.version.split()[0]}  executable={sys.executable}")
    print("=" * 78)

    # ------------------------------------------------------------------ #
    print("\n[1/6] 主导出：批准去重 / 分组授权 / 三类标记陷阱")
    main_root = ART / "main"
    ledger = ApprovalLedger(main_root / "approvals.jsonl")
    alpha_ids = ["IDX-A1", "IDX-A2", "IDX-A3"]
    beta_ids = ["IDX-B1", "IDX-B2"]

    _g, alpha_created = ledger.grant(
        source_key=ALPHA["source_key"], group_id=ALPHA["group_id"],
        tenant=ALPHA["tenant"], purpose=ALPHA["purpose"], policy=ALPHA["policy"],
        index_ids=alpha_ids, principal="east-intake",
    )
    _g2, alpha_dup = ledger.grant(
        source_key=ALPHA["source_key"], group_id=ALPHA["group_id"],
        tenant=ALPHA["tenant"], purpose=ALPHA["purpose"], policy=ALPHA["policy"],
        index_ids=alpha_ids, principal="east-intake-retry",
    )
    _gb, beta_created = ledger.grant(
        source_key=BETA["source_key"], group_id=BETA["group_id"],
        tenant=BETA["tenant"], purpose=BETA["purpose"], policy=BETA["policy"],
        index_ids=beta_ids, principal="west-intake",
    )
    check("approval", "同源批准首次 created=True", alpha_created is True)
    check("approval", "同源重复提交 created=False（不得算两份）", alpha_dup is False)
    check("approval", "两个来源 -> distinct_sources=2", ledger.distinct_source_count() == 2,
          ledger.summary())

    publisher = Publisher(main_root, ledger)
    for item in demo_publications():
        publisher.publish(
            index_id=item["index_id"], source=item["source"],
            tenant=item["tenant"], purpose=item["purpose"], policy_code=item["policy"],
        )
    check("export", "5 份索引全部进入当前集合", publisher.visibility_report()["current_count"] == 5)

    pages = render_pages(publisher, page_size=1)
    write_manifest(publisher.release)
    check("export", "page_size=1 -> 5 个分页（制造跨页重复字典）", len(pages) == 5, len(pages))

    # 结构陷阱的导出侧断言。
    a1 = json.loads(publisher.index_path("IDX-A1").read_text(encoding="utf-8"))
    body1 = a1["body"]
    check("marker", "嵌套列表标记已被清除",
          "ZMARK-NESTED" not in json.dumps(a1, ensure_ascii=False))
    check("marker", "EMPTY 字段被重建为空字符串", body1.get("legal_hold") == ""
          and body1.get("contact") == "" and body1.get("aliases") == [])
    p1 = json.loads((publisher.pages_dir / "page_0001.json").read_text(encoding="utf-8"))
    p2 = json.loads((publisher.pages_dir / "page_0002.json").read_text(encoding="utf-8"))
    party1 = p1["items"][0]["body"]["party"]
    party2 = p2["items"][0]["body"]["party"]
    check("marker", "同一 party 字典确实跨页重复且安全字段保留",
          party1.get("name") == "East Review Board" and party2.get("name") == "East Review Board"
          and party1 is not party2)  # 反序列化后当然不是同对象，但内容一致地出现在两页
    check("marker", "跨页 XPAGE 标记在两页都已脱敏",
          party1.get("route_code") == "[REDACTED]"
          and party2.get("route_code") == "[REDACTED]")

    canary_file = main_root / "canaries.json"
    canary_file.write_text(json.dumps(ALL_CANARIES), encoding="utf-8")

    full_snapshot = main_root / "release_full_snapshot"
    shutil.copytree(publisher.release, full_snapshot)

    # ------------------------------------------------------------------ #
    print("\n[2/6] 独立验证器子进程扫描干净的实际 release（必须 PASS）")
    rc, vrep, out = run_independent_validator(
        publisher.release, "clean_before_revoke",
        canaries=canary_file, require_manifest=True,
    )
    if vrep is None:
        check("validator", "干净 release 产出 JSON 报告", False, out[-800:])
    else:
        check("validator", "退出码 0 / passed", rc == 0 and vrep["passed"] is True,
              f"rc={rc} violations={vrep.get('violation_count')}")
        env_ids = {e["index_id"] for e in vrep.get("envelopes", [])}
        canonical = [e for e in vrep.get("envelopes", [])
                     if e.get("file", "").startswith("indices") and e.get("at") == "$"]
        check("validator", "5 个不同索引编号且 indices/ 正本 5 份",
              env_ids == {"IDX-A1", "IDX-A2", "IDX-A3", "IDX-B1", "IDX-B2"}
              and len(canonical) == 5,
              f"ids={sorted(env_ids)} canonical={len(canonical)}")
        check("validator", "0 条违规", vrep.get("violation_count") == 0,
              [v["code"] for v in (vrep.get("violations") or [])][:5])

    # ------------------------------------------------------------------ #
    print("\n[3/6] 撤销 A 组 -> A 回退，B 独立授权不受影响；重启可见性报告")
    rev_ev, rev_created = ledger.revoke_group(ALPHA["group_id"], reason="review-group recall")
    removed = publisher.withdraw_revoked()
    check("revoke", "撤销事件为新建且仅回退 A 组 3 份",
          rev_created is True and sorted(removed) == sorted(alpha_ids), removed)
    alpha_decision = ledger.authorize(
        tenant=ALPHA["tenant"], purpose=ALPHA["purpose"], policy=ALPHA["policy"],
        index_id="IDX-A1", digest=a1["bindings"]["content_digest"])
    beta_decision = ledger.authorize(
        tenant=BETA["tenant"], purpose=BETA["purpose"], policy=BETA["policy"],
        index_id="IDX-B1",
        digest=json.loads(publisher.index_path("IDX-B1").read_text(encoding="utf-8"))
        ["bindings"]["content_digest"])
    check("revoke", "A 组授权被拒(group_revoked)", (not alpha_decision.allowed)
          and alpha_decision.reason.startswith("group_revoked"), alpha_decision.reason)
    check("revoke", "B 组独立授权仍 allowed", beta_decision.allowed is True, beta_decision.reason)

    remaining_index_files = sorted(p.name for p in publisher.indices_dir.glob("*.json"))
    check("revoke", "实际发布目录只剩 B1/B2 文件",
          remaining_index_files == ["IDX-B1.json", "IDX-B2.json"], remaining_index_files)

    render_pages(publisher, page_size=1)
    write_manifest(publisher.release)
    rc2, vrep2, _ = run_independent_validator(
        publisher.release, "clean_after_revoke",
        canaries=canary_file, require_manifest=True)
    check("validator", "回退重出后 release 仍通过独立验证", rc2 == 0 and bool(vrep2 and vrep2["passed"]),
          f"rc={rc2}")

    # 真正“重启”：全新对象从磁盘加载。
    restarted = Publisher(main_root, ApprovalLedger.load(main_root / "approvals.jsonl"))
    restart_report = restarted.recover()
    check("restart", "历史可见 = A1-A3+B1-B2 共 5 份",
          restart_report["history_count"] == 5
          and restart_report["history_visible_ids"] == sorted(alpha_ids + beta_ids),
          restart_report["history_visible_ids"])
    check("restart", "当前可见集合仅 B1/B2",
          restart_report["current_visible_ids"] == sorted(beta_ids),
          restart_report["current_visible_ids"])
    rc3, vrep3, _ = run_independent_validator(
        publisher.release, "clean_after_restart", require_manifest=True)
    check("validator", "重启对账后 release 仍通过验证", rc3 == 0 and bool(vrep3 and vrep3["passed"]))

    # ------------------------------------------------------------------ #
    print("\n[4/6] 独立验证器扫描负例（必须全部被检出）")
    fixtures = build_all_negative_fixtures(ART, full_snapshot)

    rc_s, rep_s, _ = run_independent_validator(fixtures["structural"], "neg_structural")
    if rep_s:
        vios = rep_s["violations"]
        nested_ok = any(v["file"] == "nested_list.json" and v["code"] == "canary_marker"
                        and v["path"].startswith("$.a[0].b[0]")
                        and v["path"].endswith(".note") for v in vios)
        xpage_files = {v["file"] for v in vios
                       if v["code"] == "canary_marker" and "XPAGE" in v["detail"]}
        empty_key_ok = any(v["file"] == "empty_field.json"
                           and v["code"] == "canary_marker_in_key" for v in vios)
        empty_name_ok = any(v["file"] == "empty_field.json" and "emptyName" in v["path"]
                            for v in vios)
        check("negative", "嵌套列表深处标记被定位", rc_s == 1 and nested_ok)
        check("negative", "跨页重复字典两页均被报出",
              {"pages/page_0001.json", "pages/page_0002.json"} <= xpage_files, sorted(xpage_files))
        check("negative", "空字段键名标记 + 空字符串键下标记被检出",
              empty_key_ok and empty_name_ok)
    else:
        check("negative", "结构探针产出报告", False)

    rc_t, rep_t, _ = run_independent_validator(fixtures["tampered_real"], "neg_tampered")
    tamper_canary = bool(rep_t and any(
        "canary" in v["code"] for v in rep_t["violations"]))
    check("negative", "真实 release 注入标记 -> 验证器 FAIL 且检出标记",
          rc_t == 1 and tamper_canary, f"rc={rc_t}")

    rc_d, rep_d, _ = run_independent_validator(fixtures["digest_tamper"], "neg_digest")
    check("negative", "正文/摘要不一致被检出",
          rc_d == 1 and bool(rep_d and any(v["code"] == "content_digest_mismatch"
                                            for v in rep_d["violations"])))

    rc_i, rep_i, _ = run_independent_validator(fixtures["same_id"], "neg_sameid")
    check("negative", "同号异摘要被检出",
          rc_i == 1 and bool(rep_i and rep_i["same_id_different_digest"]),
          rep_i.get("same_id_different_digest") if rep_i else None)

    # ------------------------------------------------------------------ #
    print("\n[5/6] Barrier 双线程三场景 + 同源并发去重")
    lab_report = run_lab(ART)
    for key, label in [
        ("A_revoke_first", "撤销先写 -> 过屏障重检 -> 拒绝且从不可见"),
        ("B_receipt_lost", "字段落盘/回执丢失 -> 重启幂等补提交"),
        ("C_same_id_diff_digest", "同号异摘要 -> 一胜一冲突并隔离"),
        ("D_same_source_dedup", "两线程同源批准 -> 只算一份"),
    ]:
        item = lab_report[key]
        check("barrier", label, bool(item.get("passed")))
        rr = item.get("restart_report")
        if rr:
            print(f"         · {key}: 历史可见={rr.get('history_visible_ids')} "
                  f"当前={rr.get('current_visible_ids')} "
                  f"恢复动作={ {k: v for k, v in (rr.get('recovery_actions') or {}).items() if v} }")

    snap = Path(lab_report["C_same_id_diff_digest"]["pre_recovery_snapshot"])
    rc_c0, rep_c0, _ = run_independent_validator(snap, "lab_C_prerecovery")
    check("validator", "验证器扫到 C 场景真实竞态产物的同号异摘要",
          rc_c0 == 1 and bool(rep_c0 and rep_c0["same_id_different_digest"]), f"rc={rc_c0}")
    c_live = ROOT / "artifacts" / "lab" / "C_same_id_diff_digest" / "release"
    rc_c1, rep_c1, _ = run_independent_validator(c_live, "lab_C_postrecovery")
    check("validator", "C 场景重启隔离冲突件后 release 干净",
          rc_c1 == 0 and bool(rep_c1 and rep_c1["passed"]), f"rc={rc_c1}")

    # ------------------------------------------------------------------ #
    print("\n[6/6] 60000 本地对象：计数 + 单次更新读写范围复核")
    bench_report = run_bench(ART, 60000)
    rv = bench_report["review"]
    check("bench", "磁盘实计对象数 = 60000",
          bench_report["counted_objects_on_disk"] == 60000,
          bench_report["counted_objects_on_disk"])
    check("bench", "独立复核全部通过（读/写仅目标分片，仅 1 对象摘要变化）",
          rv["all_checks_passed"] is True, rv["checks"])
    print(f"         目标分片 {rv['expected_shard']}，"
          f"分片对象 {bench_report['target_shard_objects']}，"
          f"解码/编码对象 {rv['meter_scope']['objects_decoded']}/"
          f"{rv['meter_scope']['objects_encoded']}")
    print(f"         计量读取文件 {rv['meter_scope']['files_read']}")
    print(f"         计量改写文件 {rv['meter_scope']['files_rewritten']}")
    print(f"         磁盘差分改动文件 {rv['disk_diff']['changed_files']}，"
          f"摘要变化对象 {rv['changed_object_keys']}")

    # ------------------------------------------------------------------ #
    total = len(checks)
    failed = [c for c in checks if not c["ok"]]
    success = not failed and lab_report["all_passed"] and rv["all_checks_passed"]

    run_report = {
        "success": success,
        "python": sys.version,
        "executable": sys.executable,
        "total_checks": total,
        "passed_checks": total - len(failed),
        "failed_checks": len(failed),
        "checks": checks,
        "main_visibility_after_restart": restart_report,
        "approval_summary": ledger.summary(),
        "lab": lab_report,
        "bench": bench_report,
    }
    (ART / "RUN_REPORT.json").write_text(
        json.dumps(run_report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print("\n" + "=" * 78)
    if success:
        print(f"全部成功：{total}/{total} 项断言通过。报告 artifacts/RUN_REPORT.json")
        print("独立验证器可单独运行：python verify_release.py artifacts/main/release "
              "--require-manifest")
        return 0
    print(f"存在失败：{len(failed)}/{total} 项未通过，详见 artifacts/RUN_REPORT.json")
    for c in failed:
        print(f"  x [{c['area']}] {c['name']} :: {c['detail']}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

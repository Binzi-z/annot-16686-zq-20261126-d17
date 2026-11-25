"""端到端：调用 run_all.main()，断言整条离线链路与 RUN_REPORT.json 全绿。

这也使得 `python -m unittest discover -s tests` 会真实执行：
导出 -> 独立验证器子进程 -> 撤销/重启 -> 四类负例 -> 屏障三场景 -> 60k 复核。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import run_all  # noqa: E402


class EndToEndRunAllTests(unittest.TestCase):
    def test_run_all_reports_success(self) -> None:
        rc = run_all.main()
        self.assertEqual(rc, 0, "run_all 未返回 0；见 artifacts/RUN_REPORT.json")
        report = json.loads((ROOT / "artifacts" / "RUN_REPORT.json").read_text("utf-8"))
        self.assertTrue(report["success"])
        self.assertEqual(report["failed_checks"], 0)
        self.assertEqual(report["passed_checks"], report["total_checks"])

        # 60k 计数与范围复核。
        bench = report["bench"]
        self.assertEqual(bench["counted_objects_on_disk"], 60000)
        self.assertTrue(bench["review"]["all_checks_passed"])
        self.assertEqual(bench["review"]["changed_object_keys"], ["obj-030000"])

        # 主流程重启可见性：历史 5，当前 2。
        vis = report["main_visibility_after_restart"]
        self.assertEqual(vis["history_count"], 5)
        self.assertEqual(vis["current_visible_ids"], ["IDX-B1", "IDX-B2"])

        # 三个屏障场景 + 同源并发去重全部通过。
        lab = report["lab"]
        self.assertTrue(lab["all_passed"])
        for key in ("A_revoke_first", "B_receipt_lost",
                    "C_same_id_diff_digest", "D_same_source_dedup"):
            self.assertTrue(lab[key]["passed"], key)


if __name__ == "__main__":
    unittest.main(verbosity=2)

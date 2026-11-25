"""关键不变量的单元测试（标准库 unittest）。

运行：python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from leakguard.approvals import ApprovalLedger, AuthorizationDenied  # noqa: E402
from leakguard.bench import (  # noqa: E402
    Meter, ShardStore, review_single_update, snapshot_file_hashes,
    snapshot_object_digests,
)
from leakguard.lab import (  # noqa: E402
    concurrent_same_source_grant, scenario_receipt_lost,
    scenario_revoke_first, scenario_same_id_diff_digest,
)
from leakguard.publisher import DigestConflict, Publisher, build_envelope  # noqa: E402
from leakguard.scanner import scan_object  # noqa: E402
from leakguard.synthdata import ALL_CANARIES, alpha_records  # noqa: E402


def _grant_basic(ledger: ApprovalLedger, iid: str = "I1") -> None:
    ledger.grant(
        source_key="S1", group_id="g1", tenant="t", purpose="p",
        policy="POL-INDEX-MASKED-V2", index_ids=[iid],
    )


class DigestAndEnvelopeTests(unittest.TestCase):
    def test_envelope_binds_four_and_digest_matches_body(self) -> None:
        env = build_envelope(
            index_id="I1", source={"ref": "r", "category": "c", "status": "open",
                                   "ssn": "123-45-6789"},
            tenant="ten", purpose="pur", policy_code="POL-INDEX-LIGHT-V1",
        )
        b = env["bindings"]
        self.assertEqual((b["tenant"], b["purpose"], b["policy"]),
                         ("ten", "pur", "POL-INDEX-LIGHT-V1"))
        self.assertRegex(b["content_digest"], r"^sha256:[0-9a-f]{64}$")
        from leakguard.util import digest_obj
        self.assertEqual(b["content_digest"], digest_obj(env["body"]))
        # 敏感字段不得进入正文。
        self.assertNotIn("ssn", json.dumps(env["body"]))

    def test_all_three_canary_positions_are_scrubbed_clean(self) -> None:
        for rec in alpha_records():
            env = build_envelope(
                index_id="X", source=rec, tenant="t", purpose="p",
                policy_code="POL-INDEX-MASKED-V2")
            text = json.dumps(env, ensure_ascii=False)
            for canary in ALL_CANARIES:
                self.assertNotIn(canary, text)
            self.assertEqual(list(scan_object(env)), [])


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "approvals.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_same_source_counts_once_and_reload_persists(self) -> None:
        led = ApprovalLedger(self.path)
        _e, created1 = led.grant(source_key="k", group_id="g", tenant="t",
                                 purpose="p", policy="POL-INDEX-LIGHT-V1")
        _e2, created2 = led.grant(source_key="k", group_id="g", tenant="t",
                                  purpose="p", policy="POL-INDEX-LIGHT-V1")
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(led.distinct_source_count(), 1)
        reloaded = ApprovalLedger.load(self.path)
        self.assertEqual(reloaded.distinct_source_count(), 1)

    def test_revoke_group_isolated_from_other_group(self) -> None:
        led = ApprovalLedger(self.path)
        # 两组授权覆盖互不相交的索引集合：A 组撤销只应令 idx-A 失守。
        led.grant(source_key="ka", group_id="ga", tenant="t", purpose="p",
                  policy="POL-INDEX-LIGHT-V1", index_ids=["idx-A"])
        led.grant(source_key="kb", group_id="gb", tenant="t", purpose="p",
                  policy="POL-INDEX-LIGHT-V1", index_ids=["idx-B"])
        led.revoke_group("ga")
        self.assertTrue(led.is_group_revoked("ga"))
        self.assertFalse(led.is_group_revoked("gb"))
        da = led.authorize(tenant="t", purpose="p", policy="POL-INDEX-LIGHT-V1",
                           index_id="idx-A", digest="d")
        db = led.authorize(tenant="t", purpose="p", policy="POL-INDEX-LIGHT-V1",
                           index_id="idx-B", digest="d")
        self.assertFalse(da.allowed)
        self.assertTrue(db.allowed)
        # B 组授权记录本身仍在且有效，未被 A 的撤销墓碑改动。
        self.assertEqual(len(led.grants_in_group("gb")), 1)
        self.assertEqual(len(led.active_grants()), 1)


class PublisherFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = ApprovalLedger(self.root / "approvals.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _pub(self) -> Publisher:
        return Publisher(self.root, self.ledger)

    def test_happy_publish_and_restart_visible(self) -> None:
        _grant_basic(self.ledger)
        p = self._pub()
        p.publish(index_id="I1", source={"ref": "r", "status": "open"},
                  tenant="t", purpose="p", policy_code="POL-INDEX-MASKED-V2")
        p2 = Publisher(self.root, ApprovalLedger.load(self.root / "approvals.jsonl"))
        rep = p2.recover()
        self.assertEqual(rep["current_visible_ids"], ["I1"])
        self.assertEqual(rep["history_visible_ids"], ["I1"])

    def test_revoke_then_recover_withdraws_but_history_remains(self) -> None:
        _grant_basic(self.ledger)
        p = self._pub()
        p.publish(index_id="I1", source={"ref": "r", "status": "open"},
                  tenant="t", purpose="p", policy_code="POL-INDEX-MASKED-V2")
        self.ledger.revoke_group("g1")
        removed = p.withdraw_revoked()
        self.assertEqual(removed, ["I1"])
        p2 = Publisher(self.root, ApprovalLedger.load(self.root / "approvals.jsonl"))
        rep = p2.recover()
        self.assertEqual(rep["current_visible_ids"], [])
        self.assertEqual(rep["history_visible_ids"], ["I1"])

    def test_same_id_diff_digest_raises_conflict(self) -> None:
        _grant_basic(self.ledger)
        p = self._pub()
        kw = dict(tenant="t", purpose="p", policy_code="POL-INDEX-MASKED-V2")
        p.publish(index_id="I1", source={"ref": "r", "title": "one", "status": "open"}, **kw)
        with self.assertRaises(DigestConflict):
            p.publish(index_id="I1", source={"ref": "r", "title": "two-different",
                                             "status": "open"}, **kw)


class LabScenariosTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_three_scenarios_and_dedup_pass(self) -> None:
        a = scenario_revoke_first(self.base)
        b = scenario_receipt_lost(self.base)
        c = scenario_same_id_diff_digest(self.base)
        d = concurrent_same_source_grant(self.base)
        self.assertTrue(a["passed"], a)
        self.assertTrue(b["passed"], b)
        self.assertTrue(c["passed"], c)
        self.assertTrue(d["passed"], d)


class BenchScopeTests(unittest.TestCase):
    def test_small_store_update_touches_one_shard_one_object(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = ShardStore(Path(tmp.name) / "store", shards=8)
        store.build(2000)
        self.assertEqual(store.count_objects(), 2000)
        before_f = snapshot_file_hashes(store.root)
        before_o = snapshot_object_digests(store)
        meter = Meter()
        key = "obj-001000"
        store.update(key, lambda o: o.update(status="verified", rev=o["rev"] + 1), meter)
        review = review_single_update(
            store=store, key=key, meter=meter,
            before_files=before_f, before_objs=before_o, expected_total=2000)
        self.assertTrue(review["all_checks_passed"], review["checks"])
        self.assertEqual(review["changed_object_keys"], [key])


class HardenedRuleCoverageTests(unittest.TestCase):
    def test_deep_scrub_removes_compound_email_key(self) -> None:
        from leakguard.scanner import deep_scrub, scan_object
        out = deep_scrub({"contact_email": "a@b.cn", "keep": "x"})
        self.assertNotIn("contact_email", out)
        self.assertEqual(out, {"keep": "x"})
        self.assertEqual(list(scan_object(out)), [])

    def test_independent_validator_detects_email_compound_key_and_phone_formats(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "verify_release_mod", ROOT / "verify_release.py")
        self.assertIsNotNone(spec and spec.loader)
        vr = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(vr)  # type: ignore[union-attr]

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rel = Path(tmp.name) / "rel"
        rel.mkdir(parents=True)
        leak = {
            "contact_email": "ops@example.com",
            "meta": {"backup_phone": "646.555.0142"},
            "voice": "+1 (646) 555-0199",
            "microphone": "blue-yeti",  # 绝不能被当成 phone 键
        }
        (rel / "leak.json").write_text(json.dumps(leak), encoding="utf-8")
        rep = vr.verify(rel, None, False)
        codes = {v["code"] for v in rep["violations"]}
        self.assertFalse(rep["passed"])
        self.assertIn("email_like", codes)
        self.assertIn("phone_like", codes)
        self.assertTrue(any(v["code"] == "sensitive_key" for v in rep["violations"]))
        # microphone 不应产生 sensitive_key 发现。
        self.assertFalse(any(
            v["code"] == "sensitive_key" and "microphone" in v["detail"]
            for v in rep["violations"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)

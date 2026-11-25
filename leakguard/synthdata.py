"""本地合成数据：三类结构陷阱 + 两个审查组 + 60k 对象生成器。

所有“敏感值/标记”都是本地人造样本，不对应任何真实个人或凭据。
三种不同标记分别放进：
- ZMARK-NESTED-* : 深层嵌套列表
- ZMARK-XPAGE-*  : 被多个分页重复引用/复制的同一个字典
- ZMARK-EMPTY-*  : 策略要求导出为空字段的源字段
"""
from __future__ import annotations

from typing import Any

CANARY_NESTED = "ZMARK-NESTED-7F3A9C21"
CANARY_XPAGE = "ZMARK-XPAGE-2B8D4E60"
CANARY_EMPTY = "ZMARK-EMPTY-91C0A5F7"

ALL_CANARIES = [CANARY_NESTED, CANARY_XPAGE, CANARY_EMPTY]

# 两个审查组各自的绑定。
ALPHA = {
    "group_id": "grp-alpha",
    "tenant": "t-court-east",
    "purpose": "case-review",
    "policy": "POL-INDEX-MASKED-V2",
    "source_key": "SRC-APPROVAL-ALPHA-2026-0001",
}
BETA = {
    "group_id": "grp-beta",
    "tenant": "t-regulator-west",
    "purpose": "audit",
    "policy": "POL-INDEX-LIGHT-V1",
    "source_key": "SRC-APPROVAL-BETA-2026-0001",
}


def shared_party_dict() -> dict[str, Any]:
    """跨页重复字典：A1/A2 引用同一个对象，内含 XPAGE 标记与敏感字段。"""
    return {
        "name": "East Review Board",
        "role": "authority",
        "route_code": CANARY_XPAGE,          # 键名不敏感，靠值模式兜底
        "contact_phone": "646-555-0142",
        "ssn": "222-33-4444",                # 敏感键，递归删除
    }


def alpha_records() -> list[dict[str, Any]]:
    party = shared_party_dict()  # 同一个实例，下面两条记录共享 -> 跨页重复字典
    a1: dict[str, Any] = {
        "ref": "CASE-2026-0001",
        "category": "civil-review",
        "title": "东岸一组索引 A1（含全部结构陷阱）",
        "status": "open",
        "tags": [
            "docket-7",
            {
                "label": "timeline",
                "entries": [
                    {"code": "T1", "detail": "filing"},
                    {
                        "code": "T2",
                        "matrix": [
                            ["x", [{"safe": "nested-ok"}]],
                            [
                                {
                                    "ssn": "999-12-3456",
                                    "note": CANARY_NESTED,
                                }
                            ],
                        ],
                    },
                ],
            },
        ],
        "party": party,
        # EMPTY 标记所在：策略把 legal_hold 重建为空字符串。
        "legal_hold": {"by": "ops", "note": CANARY_EMPTY, "ssn": "111-22-3333"},
        # 以下顶层字段不在白名单，整体丢弃。
        "ssn": "999-12-3456",
        "id_number": "EAST-ID-0001",
        "bank_account": "4111-1111-1111-1111",
        "secret_literal": "sk-live-0123456789abcdef",
        "phone": "212-555-0101",
        "email": "a1@example.invalid",
        "home_address": "1 Sensit ive Ave",
    }
    a2: dict[str, Any] = {
        "ref": "CASE-2026-0002",
        "category": "civil-review",
        "title": "东岸一组索引 A2（复用 party 字典）",
        "status": "pending",
        "tags": ["hearing", {"room": "4B"}],
        "party": party,  # 与 A1 相同的字典对象 -> 会出现在两个分页
        "legal_hold": CANARY_EMPTY + "-A2",
        "ssn": "888-22-1111",
        "email": "a2@example.invalid",
    }
    a3: dict[str, Any] = {
        "ref": "CASE-2026-0003",
        "category": "evidence-index",
        "title": "东岸一组索引 A3",
        "status": "closed",
        "tags": ["evidence", "sealed-summary"],
        "party": {"name": "Clerk Office", "role": "custodian"},
        "phone": "311-555-0199",
    }
    return [a1, a2, a3]


def beta_records() -> list[dict[str, Any]]:
    return [
        {
            "ref": "AUD-2026-1001",
            "category": "annual-audit",
            "title": "西岸监管审计 B1",
            "status": "released",
            "ssn": "777-88-9999",
            "bank_account": "4000-1234-5678-9010",
            "internal_only_note": "should-not-leave-store",
        },
        {
            "ref": "AUD-2026-1002",
            "category": "annual-audit",
            "title": "西岸监管审计 B2",
            "status": "draft",
            "email": "b2@example.invalid",
            "salary": 123456,
        },
    ]


def demo_publications() -> list[dict[str, Any]]:
    """返回主演示要发布的条目：绑定 + 索引编号 + 源对象。"""
    items: list[dict[str, Any]] = []
    for i, rec in enumerate(alpha_records(), 1):
        items.append(
            {
                "index_id": f"IDX-A{i}",
                "source": rec,
                **ALPHA,
            }
        )
    for i, rec in enumerate(beta_records(), 1):
        items.append(
            {
                "index_id": f"IDX-B{i}",
                "source": rec,
                **BETA,
            }
        )
    return items


def make_bench_object(i: int) -> dict[str, Any]:
    """60k 本地对象的确定性合成生成器（不使用随机数，便于复核）。"""
    return {
        "key": f"obj-{i:06d}",
        "ordinal": i,
        "kind": ("metric" if i % 3 == 0 else "record" if i % 3 == 1 else "artifact"),
        "rev": 1,
        "score": (i * 2654435761) % 100003,
        "status": ["new", "indexed", "verified", "archived"][i % 4],
        "tags": [f"shard-{i % 128:03d}", f"bucket-{i % 16}", "local"],
        "payload": {
            "title": f"local object {i}",
            "checksum_seed": f"{i:06d}-{(i * 31) % 9973:04d}",
            "flags": [i % 2 == 0, i % 5 == 0],
        },
    }

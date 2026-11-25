"""策略代号 -> 索引投影规则。

默认拒绝：只有显式列入 allow 的顶层字段能进入索引正文；随后再做一次
递归敏感键清理与标记模式替换（纵深防御）。empty 中声明的字段会被重建为
“空字段”，用于稳定 schema，同时保证源值（可能含标记）绝不落盘。
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from .scanner import deep_scrub


@dataclass(frozen=True)
class Policy:
    code: str
    allow: tuple[str, ...]
    empty: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def project(self, source: dict[str, Any]) -> dict[str, Any]:
        body: dict[str, Any] = {}
        for key in self.allow:
            if key in source:
                body[key] = deep_scrub(copy.deepcopy(source[key]))
        # 强制空字段：无论源字段原来携带什么，都只输出空容器/空串。
        for key, empty_value in self.empty.items():
            body[key] = copy.deepcopy(empty_value)
        return body


POLICIES: dict[str, Policy] = {
    "POL-INDEX-MASKED-V2": Policy(
        code="POL-INDEX-MASKED-V2",
        description="审查组索引：仅保留引用/分类/状态/标签，敏感与自由文本一律清空",
        allow=("ref", "category", "title", "status", "tags", "party", "page_hint"),
        empty={
            "contact": "",        # 空字符串字段（源里可能是夹带标记的对象）
            "legal_hold": "",     # 空字符串字段，EMPTY 标记的位置
            "aliases": [],        # 空列表字段
            "corrections": [],    # 空列表字段
            "extra": {},          # 空对象字段
        },
    ),
    "POL-INDEX-LIGHT-V1": Policy(
        code="POL-INDEX-LIGHT-V1",
        description="监管审计索引：更少字段，强制空出备注/联系方式",
        allow=("ref", "category", "status"),
        empty={
            "contact": "",
            "review_notes": [],
            "extra": {},
        },
    ),
}


def get_policy(code: str) -> Policy:
    try:
        return POLICIES[code]
    except KeyError as exc:
        raise KeyError(f"未知策略代号: {code!r}，可用: {sorted(POLICIES)}") from exc

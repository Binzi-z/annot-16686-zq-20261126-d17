"""构造“带毒”负例，证明独立验证器不是橡皮图章。

这些夹具只放在 artifacts/negative 下，与正式 release 隔离。
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .publisher import build_envelope
from .synthdata import CANARY_EMPTY, CANARY_NESTED, CANARY_XPAGE
from .util import atomic_write_json, ensure_dir


def build_structural_probes(root: Path) -> Path:
    rel = root / "struct" / "release"
    if rel.exists():
        shutil.rmtree(rel)
    ensure_dir(rel)

    nested = {
        "probe": "nested-list",
        "a": [
            {
                "b": [
                    [
                        {"keep": 1},
                        [{"deep": [{"note": CANARY_NESTED}]}],
                    ]
                ]
            }
        ],
    }
    atomic_write_json(rel / "nested_list.json", nested)

    pages = rel / "pages"
    ensure_dir(pages)
    repeated = {"name": "same-dict", "route_code": CANARY_XPAGE}
    for n in (1, 2):
        atomic_write_json(
            pages / f"page_{n:04d}.json",
            {"kind": "probe-page", "page": n, "row": {"dup": repeated}},
        )

    empty = {
        "probe": "empty-fields",
        "fields": {
            "blank": "",
            "nil": None,
            "arr": [],
            "obj": {},
            # 标记藏在“空值字段”的键名里（只扫值的验证器会漏）
            "keyCarrier": {CANARY_EMPTY: ""},
            # 标记放在“空字符串键”之下
            "emptyName": {"": CANARY_EMPTY},
        },
    }
    atomic_write_json(rel / "empty_field.json", empty)
    return rel


def build_tampered_real(negative_root: Path, clean_snapshot: Path) -> Path:
    dst = negative_root / "tampered_real" / "release"
    if dst.exists():
        shutil.rmtree(dst.parent)
    ensure_dir(dst.parent)
    shutil.copytree(clean_snapshot, dst)  # type: ignore[arg-type]
    # 向真实发布文件注入标记（模拟绕过导出器的篡改/泄漏）。
    target = dst / "indices" / "IDX-A1.json"
    if target.exists():
        env = json.loads(target.read_text(encoding="utf-8"))
        env["body"]["tags"].append([[{"injected": CANARY_NESTED}]])
        target.write_text(json.dumps(env, ensure_ascii=False, indent=2), encoding="utf-8")
    page1 = dst / "pages" / "page_0001.json"
    if page1.exists():
        page = json.loads(page1.read_text(encoding="utf-8"))
        page["injected_cross_page"] = {"dup": {"route_code": CANARY_XPAGE}}
        page1.write_text(json.dumps(page, ensure_ascii=False, indent=2), encoding="utf-8")
    return dst


def build_digest_tamper(root: Path) -> Path:
    rel = root / "digest_tamper" / "release"
    if rel.exists():
        shutil.rmtree(rel)
    ensure_dir(rel)
    env = build_envelope(
        index_id="TAMPER-1",
        source={"ref": "T-1", "category": "c", "title": "original", "status": "open"},
        tenant="t", purpose="p", policy_code="POL-INDEX-LIGHT-V1",
    )
    # 改正文但不更新绑定摘要。
    env["body"]["status"] = "CHANGED-AFTER-DIGEST"
    atomic_write_json(rel / "tampered.json", env)
    return rel


def build_same_id(root: Path) -> Path:
    rel = root / "same_id" / "release"
    if rel.exists():
        shutil.rmtree(rel)
    ensure_dir(rel)
    e1 = build_envelope(
        index_id="SAME-1",
        source={"ref": "S-1", "category": "c", "title": "content-alpha", "status": "open"},
        tenant="t", purpose="p", policy_code="POL-INDEX-MASKED-V2",
    )
    e2 = build_envelope(
        index_id="SAME-1",
        source={"ref": "S-1", "category": "c", "title": "content-bravo-different", "status": "open"},
        tenant="t", purpose="p", policy_code="POL-INDEX-MASKED-V2",
    )
    atomic_write_json(rel / "one.json", e1)
    atomic_write_json(rel / "two.json", e2)
    return rel


def build_all_negative_fixtures(artifacts_root: str | Path, clean_snapshot: Path) -> dict[str, Path]:
    root = Path(artifacts_root) / "negative"
    ensure_dir(root)
    return {
        "structural": build_structural_probes(root),
        "tampered_real": build_tampered_real(root, clean_snapshot),
        "digest_tamper": build_digest_tamper(root),
        "same_id": build_same_id(root),
    }

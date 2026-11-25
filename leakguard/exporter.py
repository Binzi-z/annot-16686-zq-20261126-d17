"""把当前可见索引渲染成分页实际发布文件，并写 manifest。

分页器故意在每一页放置同一个 ``page_context`` 字典，并允许同一份 party 字典
随条目跨页重复——独立验证器必须逐文件、逐处扫描，不能因为“见过这个对象”
就跳过重复出现的字典。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import atomic_write_json, digest_file, ensure_dir, iter_files, now_iso


def render_pages(publisher: Any, *, page_size: int = 1) -> list[Path]:
    """从磁盘上的 release/indices 实际文件读取并分页（不使用内存源对象）。"""
    release: Path = publisher.release
    pages_dir: Path = publisher.pages_dir
    ensure_dir(pages_dir)
    for old in pages_dir.glob("page_*.json"):
        old.unlink()

    current_ids = sorted((publisher._current or {}).keys())
    envelopes: list[dict[str, Any]] = []
    import json

    for iid in current_ids:
        ipath = publisher.index_path(iid)
        if ipath.exists():
            envelopes.append(json.loads(ipath.read_text(encoding="utf-8")))

    page_context = {
        "publisher": "leakguard-offline-export",
        "schema": "leakguard.page/v1",
        "authority_board": {"code": "BOARD-01", "channel": "offline-bundle"},
    }

    written: list[Path] = []
    total = max(1, (len(envelopes) + page_size - 1) // page_size)
    if not envelopes:
        # 即使当前集合为空，也输出一个明确的空页，证明分页产物已随回退刷新。
        total = 1
    for pno in range(total):
        chunk = envelopes[pno * page_size : (pno + 1) * page_size]
        page = {
            "kind": "leakguard.page/v1",
            "page": pno + 1,
            "page_count": total,
            "page_context": page_context,  # 每页重复的同一字典
            "item_count": len(chunk),
            "items": chunk,
        }
        path = pages_dir / f"page_{pno + 1:04d}.json"
        atomic_write_json(path, page)
        written.append(path)
    return written


def write_manifest(release_dir: str | Path) -> dict[str, Any]:
    """为 release 树中除 manifest.json 外的所有文件建立哈希清单。"""
    base = Path(release_dir)
    files_meta: list[dict[str, Any]] = []
    for p in iter_files(base, suffixes={".json"}):
        rel = p.relative_to(base).as_posix()
        if rel == "manifest.json":
            continue
        files_meta.append(
            {"path": rel, "bytes": p.stat().st_size, "sha256": digest_file(p)}
        )
    manifest = {
        "kind": "leakguard.manifest/v1",
        "generated_at": now_iso(),
        "file_count": len(files_meta),
        "files": sorted(files_meta, key=lambda m: m["path"]),
    }
    atomic_write_json(base / "manifest.json", manifest)
    return manifest

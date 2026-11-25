"""60000 条本地对象 + 单次更新“实际读取/改写范围”的计量与独立复核。

存储：按 key 的 SHA-256 稳定分片的 JSONL（128 个分片）。一次定点更新的真实范围
应当且仅当是：
- 读取：目标所在的 1 个分片（解码该分片全部约 N/128 个对象以定位 key）；
- 改写：原子重写这 1 个分片（编码该分片全部对象），但逐对象摘要差分证明
  真正发生内容变化的只有目标 1 个对象；
- 磁盘树前后哈希差分独立证明：除该分片外没有任何文件被增/删/改。

计量器只包装本存储自己的读写；“复核”则是另一遍独立的全树扫描，
不引用计量器的自述数字，两者互相印证。
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .synthdata import make_bench_object
from .util import atomic_write_bytes, digest_obj


@dataclass
class Meter:
    files_read: set[str] = field(default_factory=set)
    files_rewritten: set[str] = field(default_factory=set)
    read_bytes: int = 0
    rewritten_bytes: int = 0
    read_calls: int = 0
    rewrite_calls: int = 0
    objects_decoded: int = 0
    objects_encoded: int = 0

    def read_file(self, rel: str, data: bytes, objects: int) -> None:
        self.files_read.add(rel)
        self.read_bytes += len(data)
        self.read_calls += 1
        self.objects_decoded += objects

    def rewrite_file(self, rel: str, data: bytes, objects: int) -> None:
        self.files_rewritten.add(rel)
        self.rewritten_bytes += len(data)
        self.rewrite_calls += 1
        self.objects_encoded += objects

    def scope(self) -> dict[str, Any]:
        return {
            "files_read": sorted(self.files_read),
            "files_rewritten": sorted(self.files_rewritten),
            "file_count_read": len(self.files_read),
            "file_count_rewritten": len(self.files_rewritten),
            "read_bytes": self.read_bytes,
            "rewritten_bytes": self.rewritten_bytes,
            "read_calls": self.read_calls,
            "rewrite_calls": self.rewrite_calls,
            "objects_decoded": self.objects_decoded,
            "objects_encoded": self.objects_encoded,
        }


class ShardStore:
    def __init__(self, root: str | Path, shards: int = 128):
        self.root = Path(root)
        self.shard_count = shards
        self.shards_dir = self.root / "shards"
        self.shards_dir.mkdir(parents=True, exist_ok=True)

    def shard_index(self, key: str) -> int:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return int(h[:16], 16) % self.shard_count

    def shard_rel(self, key: str) -> str:
        return f"shards/shard-{self.shard_index(key):03d}.jsonl"

    def shard_path(self, key: str) -> Path:
        return self.root / self.shard_rel(key)

    # ------------------------------------------------------------------ #
    def build(self, count: int) -> float:
        if self.root.exists():
            shutil.rmtree(self.root)
        self.shards_dir.mkdir(parents=True, exist_ok=True)
        buckets: list[list[dict[str, Any]]] = [[] for _ in range(self.shard_count)]
        for i in range(1, count + 1):
            obj = make_bench_object(i)
            buckets[self.shard_index(obj["key"])].append(obj)
        t0 = time.perf_counter()
        for s, objs in enumerate(buckets):
            self._write_shard_raw(self.shards_dir / f"shard-{s:03d}.jsonl", objs)
        return time.perf_counter() - t0

    def _write_shard_raw(self, path: Path, objs: list[dict[str, Any]]) -> None:
        buf = "".join(
            json.dumps(o, ensure_ascii=False, separators=(",", ":")) + "\n" for o in objs
        ).encode("utf-8")
        atomic_write_bytes(path, buf)

    def _read_shard(self, key: str, meter: Meter | None) -> tuple[list[dict[str, Any]], str, bytes]:
        rel = self.shard_rel(key)
        path = self.root / rel
        data = path.read_bytes()
        objs: list[dict[str, Any]] = []
        for line in data.splitlines():
            if line.strip():
                objs.append(json.loads(line))
        if meter is not None:
            meter.read_file(rel, data, len(objs))
        return objs, rel, data

    def update(self, key: str, mutator: Callable[[dict[str, Any]], None], meter: Meter) -> dict[str, Any]:
        objs, rel, _ = self._read_shard(key, meter)
        pos = next((i for i, o in enumerate(objs) if o.get("key") == key), -1)
        if pos < 0:
            raise KeyError(key)
        before = json.loads(json.dumps(objs[pos]))  # 深拷贝快照
        mutator(objs[pos])
        buf = "".join(
            json.dumps(o, ensure_ascii=False, separators=(",", ":")) + "\n" for o in objs
        ).encode("utf-8")
        atomic_write_bytes(self.root / rel, buf)
        meter.rewrite_file(rel, buf, len(objs))
        return {"key": key, "shard": rel, "objects_in_shard": len(objs),
                "position": pos, "before": before, "after": objs[pos]}

    # ------------------------------------------------------------------ #
    def count_objects(self) -> int:
        total = 0
        for p in sorted(self.shards_dir.glob("shard-*.jsonl")):
            with open(p, "rb") as fh:
                total += sum(1 for line in fh if line.strip())
        return total


def snapshot_file_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix == ".tmp":
            continue
        rel = p.relative_to(root).as_posix()
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        out[rel] = h.hexdigest()
    return out


def snapshot_object_digests(store: ShardStore) -> dict[str, str]:
    """独立全量复核：读取全部对象并计算 key->规范化摘要（审计遍，不属于更新范围）。"""
    out: dict[str, str] = {}
    for p in sorted(store.shards_dir.glob("shard-*.jsonl")):
        for line in p.read_bytes().splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            out[obj["key"]] = digest_obj(obj)
    return out


def review_single_update(
    *,
    store: ShardStore,
    key: str,
    meter: Meter,
    before_files: dict[str, str],
    before_objs: dict[str, str],
    expected_total: int = 60000,
) -> dict[str, Any]:
    """用独立的磁盘/全对象差分复核计量器自述的更新范围。"""
    expected_shard = store.shard_rel(key)
    after_files = snapshot_file_hashes(store.root)
    after_objs = snapshot_object_digests(store)

    changed_files = sorted(
        k for k in set(before_files) | set(after_files)
        if before_files.get(k) != after_files.get(k)
    )
    added_files = sorted(set(after_files) - set(before_files))
    removed_files = sorted(set(before_files) - set(after_files))
    changed_keys = sorted(
        k for k in set(before_objs) | set(after_objs)
        if before_objs.get(k) != after_objs.get(k)
    )

    scope = meter.scope()
    checks = {
        "total_objects_expected": len(after_objs) == expected_total,
        "meter_read_exactly_target_shard": scope["files_read"] == [expected_shard],
        "meter_rewrote_exactly_target_shard": scope["files_rewritten"] == [expected_shard],
        "disk_changed_exactly_target_shard": changed_files == [expected_shard],
        "no_file_added_or_removed": not added_files and not removed_files,
        "exactly_one_object_digest_changed": changed_keys == [key],
        "decoded_full_shard": scope["objects_decoded"] == scope["objects_encoded"],
        "non_target_objects_untouched": all(
            before_objs[k] == after_objs[k] for k in before_objs if k != key
        ),
    }
    return {
        "expected_shard": expected_shard,
        "meter_scope": scope,
        "disk_diff": {
            "changed_files": changed_files,
            "added_files": added_files,
            "removed_files": removed_files,
        },
        "changed_object_keys": changed_keys,
        "changed_object_count": len(changed_keys),
        "audit_objects_total": len(after_objs),
        "checks": checks,
        "all_checks_passed": all(checks.values()),
    }


def run_bench(artifacts_root: str | Path, count: int = 60000) -> dict[str, Any]:
    store_root = Path(artifacts_root) / "bench" / "store"
    store = ShardStore(store_root, shards=128)

    build_seconds = store.build(count)
    counted = store.count_objects()

    before_files = snapshot_file_hashes(store.root)
    before_objs = snapshot_object_digests(store)

    target_key = "obj-030000"
    meter = Meter()

    def mutate(o: dict[str, Any]) -> None:
        o["status"] = "verified"
        o["rev"] = int(o.get("rev", 1)) + 1
        o.setdefault("payload", {})["reviewed_by_single_update"] = "scope-audit"

    t0 = time.perf_counter()
    upd = store.update(target_key, mutate, meter)
    update_seconds = time.perf_counter() - t0

    review = review_single_update(
        store=store, key=target_key, meter=meter,
        before_files=before_files, before_objs=before_objs,
    )
    return {
        "requested_objects": count,
        "counted_objects_on_disk": counted,
        "shard_count": store.shard_count,
        "build_seconds": round(build_seconds, 4),
        "single_update_seconds": round(update_seconds, 6),
        "target_key": target_key,
        "target_shard_objects": upd["objects_in_shard"],
        "write_amplification_objects_per_changed_object": upd["objects_in_shard"],
        "review": review,
    }

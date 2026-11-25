"""基础工具：UTF-8 输出、规范化 JSON、SHA-256 摘要、原子写、JSONL 日志。

只使用 Python 3.12 标准库，兼容原生 Windows（路径/进程参数均为 Unicode）。
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def force_utf8_stdio() -> None:
    """在中文 Windows 控制台（cp936）下也能稳定打印报告。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- #
# 规范化 JSON 与摘要
# --------------------------------------------------------------------------- #
def canonical_bytes(obj: Any) -> bytes:
    """跨进程/跨平台稳定的规范化字节：排序键、无多余空白、不转义非 ASCII。"""
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: Any) -> str:
    """返回 'sha256:<64 hex>'，摘要是对 *实际内容* 的规范化字节计算的。"""
    return "sha256:" + sha256_hex(canonical_bytes(obj))


def digest_file(path: os.PathLike[str] | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def short_digest(digest: str, n: int = 12) -> str:
    tail = digest.split(":", 1)[-1]
    return tail[:n]


# --------------------------------------------------------------------------- #
# 文件 / JSONL
# --------------------------------------------------------------------------- #
def ensure_dir(path: os.PathLike[str] | str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def fsync_file(fh) -> None:  # pragma: no cover - 平台相关薄封装
    try:
        fh.flush()
        os.fsync(fh.fileno())
    except (OSError, AttributeError):
        # 某些临时/特殊文件系统不支持 fsync；原子 rename 仍然成立。
        pass


def atomic_write_bytes(path: os.PathLike[str] | str, data: bytes) -> None:
    """同目录临时文件 + fsync + os.replace，保证最终字段要么是旧版要么是新版。"""
    target = Path(path)
    ensure_dir(target.parent)
    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fsync_file(fh)
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_text(path: os.PathLike[str] | str, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: os.PathLike[str] | str, obj: Any, *, indent: int = 2) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=indent, allow_nan=False)
    atomic_write_text(path, text + "\n")


def append_jsonl(path: os.PathLike[str] | str, record: dict[str, Any]) -> None:
    """追加一条 JSONL 并 fsync，作为崩溃后可重放的持久事件。"""
    p = Path(path)
    ensure_dir(p.parent)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False)
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")
        fsync_file(fh)


def read_jsonl(path: os.PathLike[str] | str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with open(p, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"损坏的 JSONL {p} 第 {lineno} 行: {exc}") from exc
            if not isinstance(rec, dict):
                raise ValueError(f"JSONL 记录必须是对象: {p} 第 {lineno} 行")
            out.append(rec)
    return out


def load_json(path: os.PathLike[str] | str, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    with open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


def iter_files(root: os.PathLike[str] | str, suffixes: Iterable[str] | None = None) -> list[Path]:
    base = Path(root)
    if not base.exists():
        return []
    wanted = set(s.lower() for s in suffixes) if suffixes else None
    files = [p for p in base.rglob("*") if p.is_file()]
    if wanted is not None:
        files = [p for p in files if p.suffix.lower() in wanted]
    return sorted(files)

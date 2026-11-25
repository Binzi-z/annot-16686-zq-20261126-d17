#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""独立发布验证器（只依赖 Python 3.12 标准库，不导入 leakguard 包）。

用途
----
    python verify_release.py <release_dir> \
        [--report-json out.json] [--canaries canaries.json] [--require-manifest]

它只信任磁盘上的 *实际发布文件*，独立完成：
  1. 递归扫描每个 JSON 的字典键和值 —— 嵌套列表、跨页重复字典、空字段/空键
     都不会被跳过；同时对原始字节解码文本做正则兜底（即使 JSON 损坏也能查标记）。
  2. 检测人造金丝雀标记 ZMARK-* 与合成 PII/密钥模式、敏感字段名。
  3. 校验每份 leakguard.index/v1 信封是否绑定：
     接收租户 tenant、用途 purpose、策略代号 policy、实际内容摘要 content_digest，
     并独立重算 body 的规范化 SHA-256，识别摘要篡改。
  4. 识别 “同号异摘要”：同一个 index_id 在 indices/ 与 conflicts/ 等位置
     绑定了不同的 content_digest。
  5. 若存在 manifest.json，逐项复核文件哈希，并发现未登记文件。

退出码：0=通过；1=发现违规；2=验证器自身用法/IO 错误。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

ENVELOPE_KIND = "leakguard.index/v1"

# ---- 独立规则（与导出器内部规则刻意分开维护，避免共享同一个盲点） ----------- #
CANARY_RE = re.compile(r"ZMARK-[A-Z0-9]+-[0-9A-Fa-f]{8}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SSN_RE = re.compile(r"(?<![0-9A-Za-z])\d{3}-\d{2}-\d{4}(?![0-9A-Za-z])")
PHONE_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:\(\d{3}\)|\d{3})[-. ]?\d{3}[-. ]?\d{4}(?![0-9A-Za-z])"
)
CARD_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:4\d{3}[- ]\d{4}[- ]\d{4}[- ]\d{4}|4\d{15})(?![0-9A-Za-z])"
)
SECRET_RE = re.compile(r"(?<![0-9A-Za-z])sk-live-[0-9a-fA-F]{16,}(?![0-9A-Za-z])")

VALUE_RULES = (
    ("canary_marker", CANARY_RE),
    ("email_like", EMAIL_RE),
    ("ssn_like", SSN_RE),
    ("phone_like", PHONE_RE),
    ("card_like", CARD_RE),
    ("secret_literal", SECRET_RE),
)

SENSITIVE_EXACT = {
    "ssn", "social_security_number", "id_number", "id_card", "id_card_no",
    "passport_no", "passport", "bank_account", "account_number", "card_number",
    "credit_card", "cvv", "password", "passwd", "secret", "secret_note",
    "token", "api_key", "apikey", "private_key", "salary", "income",
    "home_address", "address", "phone", "mobile", "phone_number",
    "email", "email_address", "date_of_birth", "dob",
}
SENSITIVE_STEMS = (
    "ssn", "passport", "bank_account", "card_number", "credit_card",
    "password", "passwd", "private_key", "api_key", "secret", "token",
    "id_card", "id_number",
)
# 词元整词匹配，识别 contact_email / backup-phone 等复合键，但不误伤 microphone。
SENSITIVE_TOKENS = {
    "email", "e_mail", "mail", "phone", "tel", "telephone",
    "mobile", "cellphone", "fax", "whatsapp", "wechat",
}

REQUIRED_BINDINGS = ("tenant", "purpose", "policy", "content_digest")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def norm_key(key: str) -> str:
    return re.sub(r"[\s\-]+", "_", key.strip().lower())


def sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    nk = norm_key(key)
    if nk in SENSITIVE_EXACT:
        return True
    if any(stem in nk for stem in SENSITIVE_STEMS):
        return True
    return bool(set(nk.split("_")) & SENSITIVE_TOKENS)


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest_obj(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def jpath(parts: list[Any]) -> str:
    s = "$"
    for p in parts:
        s += f"[{p}]" if isinstance(p, int) else "." + str(p)
    return s


def scan_structure(node: Any) -> Iterator[tuple[str, str, str]]:
    """返回 (json_path, code, detail)。空容器也会被进入；字典键本身也被扫描。"""
    yield from _walk(node, [])


def _walk(node: Any, parts: list[Any]) -> Iterator[tuple[str, str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            if sensitive_key(k):
                yield jpath(parts + [str(k)]), "sensitive_key", f"敏感字段名 {k!r}"
            if isinstance(k, str):
                for code, rx in VALUE_RULES:
                    m = rx.search(k)
                    if m:
                        yield jpath(parts + [f"<key:{k!r}>"]), code + "_in_key", \
                            f"字典键 {k!r} 中命中 {code}: {m.group(0)[:48]}"
            # 关键：即使 v 是 "" / [] / {} / None 也照常递归，不做真值跳过。
            yield from _walk(v, parts + [str(k)])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, parts + [i])
    elif isinstance(node, str):
        for code, rx in VALUE_RULES:
            m = rx.search(node)
            if m:
                yield jpath(parts), code, f"字符串中命中 {code}: {m.group(0)[:48]}"
    # 标量叶子无需处理；遍历本身已经覆盖该路径。


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def verify(release_dir: Path, canaries: list[str] | None, require_manifest: bool) -> dict[str, Any]:
    violations: list[dict[str, str]] = []
    envelopes: list[dict[str, str]] = []
    scanned = 0
    total_bytes = 0

    if not release_dir.exists() or not release_dir.is_dir():
        return {
            "passed": False,
            "fatal": f"发布目录不存在或不是目录: {release_dir}",
            "violations": [],
        }

    files = sorted(p for p in release_dir.rglob("*") if p.is_file())
    json_files = [p for p in files if p.suffix.lower() == ".json"]

    for path in files:
        scanned += 1
        rel = path.relative_to(release_dir).as_posix()
        try:
            raw = path.read_bytes()
        except OSError as exc:
            violations.append({"code": "unreadable_file", "file": rel, "path": "-",
                               "detail": str(exc)})
            continue
        total_bytes += len(raw)
        text = raw.decode("utf-8", errors="replace")

        # (a) 原始文本兜底扫描：即便不是合法 JSON 也能发现标记。
        for code, rx in VALUE_RULES:
            for m in rx.finditer(text):
                violations.append({
                    "code": "raw_" + code,
                    "file": rel,
                    "path": f"<raw line {line_of(text, m.start())}>",
                    "detail": f"原始文本命中 {code}: {m.group(0)[:48]}",
                })

        # (b) 指定金丝雀逐个确认（精确名单，防止正则被绕过的争议）。
        if canaries:
            for canary in canaries:
                if canary and canary in text:
                    violations.append({
                        "code": "listed_canary_present",
                        "file": rel,
                        "path": f"<raw line {line_of(text, text.find(canary))}>",
                        "detail": f"发现必须缺席的标记 {canary}",
                    })

        if path.suffix.lower() != ".json":
            continue

        # (c) 结构化递归扫描。
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            violations.append({"code": "invalid_json", "file": rel, "path": "$",
                               "detail": f"JSON 解析失败: {exc}"})
            continue

        for pth, code, detail in scan_structure(obj):
            violations.append({"code": code, "file": rel, "path": pth, "detail": detail})

        # (d) 递归找出所有信封并校验绑定与摘要（分页 items 中嵌套的副本也不放过；
        #     conflicts/ 下的候选同样纳入，用于同号异摘要判定）。
        for at, env in _iter_envelopes(obj):
            env_info = _check_envelope(env, rel, violations, at)
            envelopes.append(env_info)

    # (e) 同号异摘要：按 index_id 聚合所有结构合法的信封。
    by_id: dict[str, set[str]] = {}
    for env in envelopes:
        if env.get("bindings_ok") == "true":
            by_id.setdefault(env["index_id"], set()).add(env["content_digest"])
    same_id_groups = {iid: sorted(ds) for iid, ds in sorted(by_id.items()) if len(ds) > 1}
    for iid, ds in same_id_groups.items():
        violations.append({
            "code": "same_id_different_digest",
            "file": "<multiple>",
            "path": f"$.index_id={iid}",
            "detail": f"同一索引号 {iid} 绑定了 {len(ds)} 个不同摘要: {', '.join(ds)}",
        })

    # (f) manifest 哈希与未登记文件。
    manifest_path = release_dir / "manifest.json"
    if manifest_path.exists():
        _check_manifest(release_dir, manifest_path, files, violations)
    elif require_manifest:
        violations.append({"code": "manifest_missing", "file": "manifest.json",
                           "path": "$", "detail": "要求 manifest 但不存在"})

    # 去重（原始扫描与结构扫描可能对同一泄漏各报一次，保留但避免完全相同条目刷屏）。
    dedup = _dedupe_violations(violations)

    return {
        "passed": not dedup,
        "release_dir": str(release_dir),
        "scanned_files": scanned,
        "json_files": len(json_files),
        "total_bytes": total_bytes,
        "envelope_count": len(envelopes),
        "envelopes": envelopes,
        "same_id_different_digest": same_id_groups,
        "violation_count": len(dedup),
        "violations": dedup,
    }


def _iter_envelopes(node: Any, parts: list[Any] | None = None) -> Iterator[tuple[str, dict[str, Any]]]:
    """递归产出树中所有 kind=leakguard.index/v1 的对象及其 JSONPath。"""
    if parts is None:
        parts = []
    if isinstance(node, dict):
        if node.get("kind") == ENVELOPE_KIND:
            yield jpath(parts) if parts else "$", node
        for k, v in node.items():
            yield from _iter_envelopes(v, parts + [str(k)])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_envelopes(v, parts + [i])


def _check_envelope(env: dict[str, Any], rel: str,
                    violations: list[dict[str, str]], at: str = "$") -> dict[str, str]:
    iid = str(env.get("index_id", "<missing>"))
    b = env.get("bindings")
    info: dict[str, str] = {"index_id": iid, "file": rel, "at": at,
                            "bindings_ok": "false", "content_digest": ""}
    bind_path = at + ".bindings" if at != "$" else "$.bindings"
    if not isinstance(b, dict):
        violations.append({"code": "bindings_missing", "file": rel, "path": bind_path,
                           "detail": "缺少 bindings 对象"})
        return info
    missing = [k for k in REQUIRED_BINDINGS if not b.get(k)]
    if missing:
        violations.append({"code": "binding_fields_missing", "file": rel,
                           "path": bind_path, "detail": f"缺少绑定字段: {missing}"})
    cd = b.get("content_digest", "")
    info["content_digest"] = cd if isinstance(cd, str) else ""
    if not isinstance(cd, str) or not DIGEST_RE.match(cd):
        violations.append({"code": "digest_format_bad", "file": rel,
                           "path": bind_path + ".content_digest",
                           "detail": f"摘要格式非法: {cd!r}"})
    else:
        actual = digest_obj(env.get("body"))
        if actual != cd:
            violations.append({
                "code": "content_digest_mismatch", "file": rel,
                "path": bind_path + ".content_digest",
                "detail": f"绑定摘要 {cd} 与重算正文摘要 {actual} 不一致（位置 {at}）",
            })
    if not missing and DIGEST_RE.match(cd or ""):
        info["bindings_ok"] = "true"
    return info


def _check_manifest(base: Path, manifest_path: Path, all_files: list[Path],
                    violations: list[dict[str, str]]) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        violations.append({"code": "manifest_invalid", "file": "manifest.json",
                           "path": "$", "detail": str(exc)})
        return
    listed: dict[str, str] = {}
    for item in manifest.get("files", []):
        p = item.get("path")
        if p:
            listed[p] = item.get("sha256", "")
    # *.tmp 是原子写的瞬时残留（正常不会在验证时存在），不应当作“未登记文件”假 FAIL。
    on_disk = {
        p.relative_to(base).as_posix()
        for p in all_files
        if not p.name.endswith(".tmp")
    }
    on_disk.discard("manifest.json")
    for rel in sorted(on_disk - set(listed)):
        violations.append({"code": "unlisted_file", "file": rel, "path": "$",
                           "detail": "实际发布文件未在 manifest 登记"})
    for rel, expected in listed.items():
        fp = base / rel
        if not fp.exists():
            violations.append({"code": "listed_file_absent", "file": rel, "path": "$",
                               "detail": "manifest 登记的文件不存在"})
            continue
        actual = sha256_file(fp)
        if expected and actual != expected:
            violations.append({"code": "file_hash_mismatch", "file": rel, "path": "$",
                               "detail": f"manifest 哈希 {expected} != 实际 {actual}"})


def _dedupe_violations(items: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, str]] = []
    for v in items:
        key = (v.get("code", ""), v.get("file", ""), v.get("path", ""), v.get("detail", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="独立离线发布验证器（标准库）")
    ap.add_argument("release_dir", help="实际发布目录（包含 indices/pages/receipts/manifest）")
    ap.add_argument("--report-json", help="把完整 JSON 报告写入该路径")
    ap.add_argument("--canaries", help="JSON 文件，内容为必须缺席的标记字符串数组")
    ap.add_argument("--require-manifest", action="store_true", help="要求 manifest.json 存在")
    args = ap.parse_args(argv)

    release = Path(args.release_dir)
    canaries: list[str] | None = None
    if args.canaries:
        try:
            canaries = json.loads(Path(args.canaries).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[verify] 无法读取 --canaries: {exc}", file=sys.stderr)
            return 2
        if not isinstance(canaries, list):
            print("[verify] --canaries 文件必须是 JSON 数组", file=sys.stderr)
            return 2

    try:
        report = verify(release, canaries, args.require_manifest)
    except Exception as exc:  # 验证器自身崩溃也要明确非零，不能误报通过
        print(f"[verify] 验证器错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.report_json:
        rp = Path(args.report_json)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if report.get("fatal"):
        print(f"[verify] FATAL: {report['fatal']}")
        return 2

    print(f"[verify] 目录 {report['release_dir']}")
    print(f"[verify] 扫描文件 {report['scanned_files']}（JSON {report['json_files']}），"
          f"信封 {report['envelope_count']}，字节 {report['total_bytes']}")
    if report["same_id_different_digest"]:
        print("[verify] 同号异摘要：")
        for iid, ds in report["same_id_different_digest"].items():
            print(f"  - {iid}: {len(ds)} 个摘要")
    if report["passed"]:
        print("[verify] PASS：未发现敏感泄漏/绑定违规。")
        return 0

    print(f"[verify] FAIL：{report['violation_count']} 条违规，前 30 条：")
    for v in report["violations"][:30]:
        print(f"  * [{v['code']}] {v['file']} :: {v['path']} :: {v['detail']}")
    if report["violation_count"] > 30:
        print(f"  ... 其余 {report['violation_count'] - 30} 条见 JSON 报告")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

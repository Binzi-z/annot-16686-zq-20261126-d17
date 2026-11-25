"""递归敏感数据扫描与深度脱敏（导出器自用的第二道防线）。

注意：真正“独立”的验证器是仓库根目录的 verify_release.py，它不导入本模块，
以免共享同一个可能有缺陷的实现。这里的规则用于导出时的纵深防御和包内自测。
"""
from __future__ import annotations

import re
from typing import Any, Iterator

# 三种结构陷阱使用的不同标记（另有常规密钥/PII 模式作为补充）。
CANARY_PATTERN = re.compile(r"ZMARK-[A-Z0-9]+-[0-9A-Fa-f]{8}")

# 前后不能紧邻十六进制/字母，避免把 sha256 摘要里的连续数字误判成证件/卡号。
SSN_PATTERN = re.compile(r"(?<![0-9A-Za-z])\d{3}-\d{2}-\d{4}(?![0-9A-Za-z])")
PHONE_PATTERN = re.compile(r"(?<![0-9A-Za-z])(?:\(\d{3}\)|\d{3})[-. ]?\d{3}[-. ]?\d{4}(?![0-9A-Za-z])")
CARD_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])(?:4\d{3}[- ]\d{4}[- ]\d{4}[- ]\d{4}|4\d{15})(?![0-9A-Za-z])"
)
SECRET_KEY_PATTERN = re.compile(r"(?<![0-9A-Za-z])sk-live-[0-9a-fA-F]{16,}(?![0-9A-Za-z])")
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("canary_marker", CANARY_PATTERN),
    ("email_like", EMAIL_PATTERN),
    ("ssn_like", SSN_PATTERN),
    ("phone_like", PHONE_PATTERN),
    ("card_like", CARD_PATTERN),
    ("secret_literal", SECRET_KEY_PATTERN),
)

# 规范化键名后，命中精确集合或包含任一敏感词干即视为敏感字段。
SENSITIVE_EXACT = {
    "ssn",
    "social_security_number",
    "id_number",
    "id_card",
    "id_card_no",
    "passport_no",
    "passport",
    "bank_account",
    "account_number",
    "card_number",
    "credit_card",
    "cvv",
    "password",
    "passwd",
    "secret",
    "secret_note",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "salary",
    "income",
    "home_address",
    "address",
    "phone",
    "mobile",
    "phone_number",
    "email",
    "email_address",
    "date_of_birth",
    "dob",
}

SENSITIVE_STEMS = (
    "ssn",
    "passport",
    "bank_account",
    "card_number",
    "credit_card",
    "password",
    "passwd",
    "private_key",
    "api_key",
    "secret",
    "token",
    "id_card",
    "id_number",
)

# 词元级敏感词：用于识别 contact_email / backup-phone / mobile_no 等复合键，
# 但按“下划线/连字符/空格分词后整词相等”判定，因此不会把 microphone 误判成 phone。
SENSITIVE_TOKENS = {
    "email",
    "e_mail",
    "mail",
    "phone",
    "tel",
    "telephone",
    "mobile",
    "cellphone",
    "fax",
    "whatsapp",
    "wechat",
}

REDACTION = "[REDACTED]"


def normalize_key(key: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())


def is_sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    nk = normalize_key(key)
    if not nk:
        # 空字符串键也可能夹带标记，不能因为“空字段”就跳过。
        return False
    if nk in SENSITIVE_EXACT:
        return True
    if any(stem in nk for stem in SENSITIVE_STEMS):
        return True
    tokens = set(nk.split("_"))
    return bool(tokens & SENSITIVE_TOKENS)


def format_path(parts: list[Any]) -> str:
    out = "$"
    for p in parts:
        if isinstance(p, int):
            out += f"[{p}]"
        else:
            out += "." + str(p)
    return out


def scan_object(obj: Any) -> Iterator[dict[str, str]]:
    """深度优先遍历任意 JSON 结构（含嵌套列表、字典键、空容器），产出发现。

    每条发现: {path, code, detail}
    """
    yield from _scan(obj, [])


def _scan(node: Any, path: list[Any]) -> Iterator[dict[str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            kpath = path + [f"<key:{k!r}>"]
            if is_sensitive_key(k):
                yield {
                    "path": format_path(path + [str(k)]),
                    "code": "sensitive_key",
                    "detail": f"敏感字段名 {k!r}",
                }
            if isinstance(k, str):
                for code, pat in VALUE_PATTERNS:
                    m = pat.search(k)
                    if m:
                        yield {
                            "path": format_path(kpath),
                            "code": code + "_in_key",
                            "detail": f"字典键中命中 {code}: {m.group(0)[:48]}",
                        }
            yield from _scan(v, path + [str(k)])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _scan(v, path + [i])
    elif isinstance(node, str):
        for code, pat in VALUE_PATTERNS:
            m = pat.search(node)
            if m:
                yield {
                    "path": format_path(path),
                    "code": code,
                    "detail": f"字符串值中命中 {code}: {m.group(0)[:48]}",
                }
    # None / bool / 数字：没有可扫描文本，但它们的存在保证父结构被完整遍历。


def has_findings(obj: Any) -> bool:
    return next(scan_object(obj), None) is not None


def deep_scrub(node: Any) -> Any:
    """导出前的纵深脱敏：删敏感键，并把任何字符串里的标记/密钥模式替换掉。

    无条件递归每一个节点（不按对象 id 做记忆化短路），因此同一个字典
    即使被引用/复制到多个分页，也会逐处清理。
    """
    if isinstance(node, dict):
        cleaned: dict[str, Any] = {}
        for k, v in node.items():
            if is_sensitive_key(k):
                # 敏感字段整体不落盘（策略要求保留空字段的由 policy 层重建）。
                continue
            cleaned[k] = deep_scrub(v)
        return cleaned
    if isinstance(node, list):
        return [deep_scrub(v) for v in node]
    if isinstance(node, str):
        out = node
        for _code, pat in VALUE_PATTERNS:
            out = pat.sub(REDACTION, out)
        return out
    return node

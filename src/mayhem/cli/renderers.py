from __future__ import annotations

import json
import os
import sys
from typing import Any

TRUNCATE_LIMIT = 1000
LARGE_NUMERIC_THRESHOLD = 9007199254740991


def is_tty() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def is_color_enabled(no_color: bool = False) -> bool:
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return is_tty()


def truncate_text(text: str, limit: int = TRUNCATE_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\u2026 (truncated, total {len(text)} chars)"


def format_value(value: Any, limit: int = TRUNCATE_LIMIT) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        if abs(value) > LARGE_NUMERIC_THRESHOLD:
            return str(value)
        return str(value)
    if isinstance(value, float):
        if abs(value) > 1e15 or (abs(value) < 1e-6 and value != 0):
            return repr(value)
        return str(value)
    if isinstance(value, list):
        if len(value) == 0:
            return "(empty)"
        if len(value) > 20:
            preview = ", ".join(format_value(v, limit=80) for v in value[:20])
            return truncate_text(preview + f", \u2026 +{len(value) - 20} more", limit=limit)
        return ", ".join(format_value(v, limit=80) for v in value)
    if isinstance(value, dict):
        if len(value) == 0:
            return "(empty)"
        return truncate_text(json.dumps(value, sort_keys=True, ensure_ascii=False), limit=limit)
    text = str(value)
    return truncate_text(text, limit=limit)


def render_table(headers: tuple[str, ...] | list[str], rows: list[list[Any]]) -> str:
    if not headers and not rows:
        return "(empty)"
    widths: list[int] = [len(str(h)) for h in headers]
    normalized_rows: list[list[str]] = []
    for row in rows:
        formatted = [format_value(cell) for cell in row]
        normalized_rows.append(formatted)
        for idx, cell in enumerate(formatted):
            if idx < len(widths):
                widths[idx] = max(widths[idx], len(cell))
            else:
                widths.append(len(cell))
    if len(headers) < len(widths):
        widths = widths[: len(headers)] if headers else widths
    lines: list[str] = []
    if headers:
        header_line = " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
        lines.append(header_line)
        separator = "-+-".join("-" * widths[i] for i in range(len(headers)))
        lines.append(separator)
    for row in normalized_rows:
        if headers:
            line = " | ".join(
                row[i].ljust(widths[i]) if i < len(widths) else row[i] for i in range(len(row))
            )
        else:
            line = " | ".join(row)
        lines.append(line)
    if not lines:
        return "(empty)"
    return "\n".join(lines)


def render_key_value(mapping: dict[str, Any]) -> str:
    if not mapping:
        return "(empty)"
    max_key = max(len(str(k)) for k in mapping)
    lines: list[str] = []
    for key in sorted(mapping.keys()):
        value = format_value(mapping[key])
        lines.append(f"{str(key).ljust(max_key)} : {value}")
    return "\n".join(lines)


def render_tree(node: Any, indent: int = 0, prefix: str = "") -> str:
    pad = "  " * indent
    if isinstance(node, dict):
        if not node:
            return pad + prefix + "(empty)"
        lines: list[str] = []
        for key in sorted(node.keys()):
            child = node[key]
            if isinstance(child, (dict, list)):
                lines.append(f"{pad}{prefix}{key}:")
                lines.append(render_tree(child, indent + 1))
            else:
                lines.append(f"{pad}{prefix}{key}: {format_value(child)}")
        return "\n".join(lines)
    if isinstance(node, list):
        if not node:
            return pad + prefix + "(empty)"
        lines = []
        for idx, item in enumerate(node):
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{prefix}[{idx}]:")
                lines.append(render_tree(item, indent + 1))
            else:
                lines.append(f"{pad}{prefix}[{idx}]: {format_value(item)}")
        return "\n".join(lines)
    return pad + prefix + format_value(node)


def render_human_summary(summary: dict[str, Any]) -> str:
    if not summary:
        return "(empty)"
    lines: list[str] = []
    for key in sorted(summary.keys()):
        value = summary[key]
        lines.append(f"{key}: {format_value(value)}")
    return "\n".join(lines)


def render_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)


def render_yaml(data: Any) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=True, allow_unicode=True)


def render(data: Any, fmt: str = "text", no_color: bool = False) -> str:
    normalized = fmt.strip().lower() if fmt else "text"
    if normalized == "json":
        if isinstance(data, dict) and "status" in data:
            return render_json(data)
        to_dict = getattr(data, "to_dict", None)
        if callable(to_dict):
            try:
                return render_json(to_dict())
            except Exception:
                return render_json(data)
        return render_json(data)
    if normalized == "yaml":
        to_dict = getattr(data, "to_dict", None)
        if callable(to_dict):
            try:
                return render_yaml(to_dict())
            except Exception:
                return render_yaml(data)
        return render_yaml(data)
    if isinstance(data, dict):
        return render_key_value(data)
    if isinstance(data, list):
        if not data:
            return "(empty)"
        if data and isinstance(data[0], list):
            return render_table((), data)
        if data and isinstance(data[0], dict):
            headers: list[str] = sorted({k for row in data for k in row})
            rows = [[format_value(row.get(h)) for h in headers] for row in data]
            return render_table(headers, rows)
        return render_tree(data)
    return format_value(data)


def json_never_polluted(stdout_text: str) -> bool:
    if not stdout_text.strip():
        return True
    try:
        json.loads(stdout_text)
        return True
    except Exception:
        return False

"""Funciones de análisis estadístico sobre registros parseados."""

from collections import Counter
from .config import ERROR_LEVELS


def analyze_nginx_access(records: list[dict], top_n: int = 10) -> dict:
    ips = Counter(r["ip"] for r in records)
    paths = Counter(r["path"] for r in records)
    statuses = Counter(r["status"] for r in records)
    methods = Counter(r["method"] for r in records if r.get("method"))
    agents = Counter(r["agent"] for r in records if r.get("agent"))
    total_bytes = sum(r["bytes"] for r in records)

    errors_5xx = sum(v for k, v in statuses.items() if k.startswith("5"))
    errors_4xx = sum(v for k, v in statuses.items() if k.startswith("4"))

    return {
        "total_requests": len(records),
        "total_bytes": total_bytes,
        "errors_5xx": errors_5xx,
        "errors_4xx": errors_4xx,
        "top_ips": ips.most_common(top_n),
        "top_paths": paths.most_common(top_n),
        "top_agents": agents.most_common(top_n),
        "status_codes": dict(sorted(statuses.items())),
        "methods": dict(methods),
    }


def analyze_docker(records: list[dict], top_n: int = 10) -> dict:
    levels = Counter(r["level"] for r in records)
    errors = [r["message"] for r in records if r["level"] in ERROR_LEVELS]
    top_errors = Counter(errors).most_common(top_n)

    return {
        "total_lines": len(records),
        "by_level": dict(sorted(levels.items())),
        "top_errors": top_errors,
        "error_count": len(errors),
    }


def analyze_nginx_error(records: list[dict], top_n: int = 10) -> dict:
    levels = Counter(r["level"] for r in records)
    msgs = Counter(r["message"][:80] for r in records)

    return {
        "total_errors": len(records),
        "by_level": dict(sorted(levels.items())),
        "top_messages": msgs.most_common(top_n),
    }

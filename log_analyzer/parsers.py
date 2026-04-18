"""Parsers para cada formato de log."""

import re
from datetime import datetime
from .config import NGINX_COMBINED, DOCKER_LOG, NGINX_ERROR


def _matches_status_filter(status: str, status_filter: str) -> bool:
    """
    Soporta filtros exactos (404), por clase (4xx, 5xx, 2xx) y por prefijo (4, 5).
    Normaliza 'xx' al dígito inicial para comparación de clase.
    """
    f = status_filter.lower().replace("x", "")
    return status.startswith(f)


def _parse_nginx_time(time_str: str) -> datetime | None:
    try:
        return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_docker_time(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    ts_str = ts_str.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_nginx_access(
    lines: list[str],
    status_filter: str | None,
    ip_filter: str | None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 0,
) -> list[dict]:
    records = []
    for line in lines:
        m = NGINX_COMBINED.match(line.strip())
        if not m:
            continue
        r = m.groupdict()
        r["bytes"] = int(r["bytes"]) if r["bytes"] != "-" else 0

        if status_filter and not _matches_status_filter(r["status"], status_filter):
            continue
        if ip_filter and r["ip"] != ip_filter:
            continue

        if since or until:
            ts = _parse_nginx_time(r.get("time", ""))
            if ts:
                if since and ts < since:
                    continue
                if until and ts > until:
                    continue

        records.append(r)
        if limit and len(records) >= limit:
            break
    return records


def parse_docker(
    lines: list[str],
    level_filter: str | None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 0,
) -> list[dict]:
    records = []
    for line in lines:
        m = DOCKER_LOG.match(line.strip())
        if not m:
            r = {"timestamp": "", "level": "INFO", "message": line.strip()}
        else:
            r = m.groupdict()
            if not r.get("level"):
                r["level"] = "INFO"

        if level_filter and r["level"] != level_filter.upper():
            continue

        if since or until:
            ts = _parse_docker_time(r.get("timestamp", ""))
            if ts:
                if since and ts < since:
                    continue
                if until and ts > until:
                    continue

        records.append(r)
        if limit and len(records) >= limit:
            break
    return records


def parse_nginx_error(
    lines: list[str],
    level_filter: str | None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 0,
) -> list[dict]:
    records = []
    for line in lines:
        m = NGINX_ERROR.match(line.strip())
        if not m:
            continue
        r = m.groupdict()
        if level_filter and r["level"].lower() != level_filter.lower():
            continue

        if since or until:
            try:
                ts_str = f"{r['date']} {r['time']}"
                ts = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
                if since and ts < since.replace(tzinfo=None):
                    continue
                if until and ts > until.replace(tzinfo=None):
                    continue
            except ValueError:
                pass

        records.append(r)
        if limit and len(records) >= limit:
            break
    return records


def search_lines(lines: list[str], pattern: str, case_sensitive: bool = False) -> list[tuple[int, str]]:
    """Busca patrón regex en líneas. Devuelve lista de (nro_linea, linea)."""
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"Patrón regex inválido: {e}") from e
    return [(i + 1, line) for i, line in enumerate(lines) if rx.search(line)]

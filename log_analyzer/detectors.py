"""Detección automática de formato de log."""

from .config import NGINX_COMBINED, DOCKER_LOG, NGINX_ERROR


def detect_format(line: str) -> str:
    """Detecta el formato del log a partir de una línea de muestra."""
    if NGINX_COMBINED.match(line):
        return "nginx_access"
    if NGINX_ERROR.match(line):
        return "nginx_error"
    if DOCKER_LOG.match(line):
        return "docker"
    return "unknown"


def detect_format_from_lines(lines: list[str]) -> str:
    """Detecta formato buscando la primera línea no vacía."""
    for line in lines:
        stripped = line.strip()
        if stripped:
            fmt = detect_format(stripped)
            if fmt != "unknown":
                return fmt
    return "unknown"

#!/usr/bin/env python3
"""
log-analyzer-cli — punto de entrada principal.

Importa y re-exporta todo desde el paquete log_analyzer para mantener
compatibilidad con código que importe directamente desde este módulo.
"""

from log_analyzer import (
    detect_format,
    parse_nginx_access,
    parse_nginx_error,
    parse_docker,
    analyze_nginx_access,
    analyze_nginx_error,
    analyze_docker,
)
from log_analyzer.cli import cli

__all__ = [
    "detect_format",
    "parse_nginx_access",
    "parse_nginx_error",
    "parse_docker",
    "analyze_nginx_access",
    "analyze_nginx_error",
    "analyze_docker",
    "cli",
]

if __name__ == "__main__":
    cli()

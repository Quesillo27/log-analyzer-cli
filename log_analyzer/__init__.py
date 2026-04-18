"""log-analyzer-cli — Analizador de logs nginx/docker."""

from .detectors import detect_format
from .parsers import parse_nginx_access, parse_nginx_error, parse_docker
from .analyzers import analyze_nginx_access, analyze_nginx_error, analyze_docker

__version__ = "2.0.0"
__all__ = [
    "detect_format",
    "parse_nginx_access",
    "parse_nginx_error",
    "parse_docker",
    "analyze_nginx_access",
    "analyze_nginx_error",
    "analyze_docker",
]

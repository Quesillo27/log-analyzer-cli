"""Constantes y configuración centralizada."""

import os
import re

DEFAULT_TOP_N = int(os.environ.get("LOG_ANALYZER_TOP", "10"))
DEFAULT_TAIL_LINES = int(os.environ.get("LOG_ANALYZER_TAIL_LINES", "20"))
MAX_STREAMING_LINES = int(os.environ.get("LOG_ANALYZER_MAX_LINES", "0"))  # 0 = sin límite

NGINX_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)?\s*(?P<path>[^"]*?)(?:\s+HTTP/[^"]*)?"?\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*?)"\s+'
    r'"(?P<agent>[^"]*?)"'
)

DOCKER_LOG = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
    r'(?P<level>INFO|WARN|WARNING|ERROR|DEBUG|FATAL|CRITICAL)?\s*'
    r'(?P<message>.+)'
)

NGINX_ERROR = re.compile(
    r'(?P<date>\d{4}/\d{2}/\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#\d+:\s+'
    r'(?P<message>.+)'
)

LEVEL_COLORS = {
    "DEBUG": "dim",
    "INFO": "green",
    "WARN": "yellow",
    "WARNING": "yellow",
    "ERROR": "red",
    "FATAL": "bold red",
    "CRITICAL": "bold red",
}

ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL"}

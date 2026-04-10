"""Tests para log-analyzer-cli."""

import pytest
import tempfile
import json
from pathlib import Path

# Agregar path del proyecto
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer import (
    detect_format,
    parse_nginx_access,
    parse_nginx_error,
    parse_docker,
    analyze_nginx_access,
    analyze_docker,
)
from click.testing import CliRunner
from analyzer import cli


# ─── Fixtures ────────────────────────────────────────────────────────────────

NGINX_ACCESS_SAMPLE = [
    '192.168.1.1 - - [10/Apr/2026:12:00:00 +0000] "GET /api/products HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.2 - - [10/Apr/2026:12:01:00 +0000] "POST /api/orders HTTP/1.1" 201 567 "-" "curl/7.68.0"',
    '192.168.1.1 - - [10/Apr/2026:12:02:00 +0000] "GET /api/products HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [10/Apr/2026:12:03:00 +0000] "GET /nonexistent HTTP/1.1" 404 89 "-" "curl/7.68.0"',
    '10.0.0.5 - - [10/Apr/2026:12:04:00 +0000] "GET /api/error HTTP/1.1" 500 200 "-" "Python/3.11"',
]

NGINX_ERROR_SAMPLE = [
    '2026/04/10 12:00:00 [error] 1234#0: *1 connect() failed (111: Connection refused)',
    '2026/04/10 12:01:00 [warn] 1234#0: *2 upstream slow response',
    '2026/04/10 12:02:00 [error] 1234#0: *3 file not found: /var/www/favicon.ico',
]

DOCKER_LOG_SAMPLE = [
    '2026-04-10T12:00:00Z INFO Server started on port 3000',
    '2026-04-10T12:01:00Z WARN Database connection slow (450ms)',
    '2026-04-10T12:02:00Z ERROR Failed to connect to Redis: ECONNREFUSED',
    '2026-04-10T12:03:00Z INFO Request processed in 23ms',
    '2026-04-10T12:04:00Z ERROR Failed to connect to Redis: ECONNREFUSED',
]


# ─── Tests de detección ───────────────────────────────────────────────────────

def test_detect_nginx_access():
    assert detect_format(NGINX_ACCESS_SAMPLE[0]) == "nginx_access"

def test_detect_nginx_error():
    assert detect_format(NGINX_ERROR_SAMPLE[0]) == "nginx_error"

def test_detect_docker():
    assert detect_format(DOCKER_LOG_SAMPLE[0]) == "docker"

def test_detect_unknown():
    assert detect_format("esto no es un log reconocido") == "unknown"


# ─── Tests de parseo ──────────────────────────────────────────────────────────

def test_parse_nginx_access_all():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    assert len(records) == 5

def test_parse_nginx_access_status_filter():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, "5", None)
    assert len(records) == 1
    assert records[0]["status"] == "500"

def test_parse_nginx_access_ip_filter():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, "192.168.1.1")
    assert len(records) == 2

def test_parse_nginx_access_fields():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    r = records[0]
    assert r["ip"] == "192.168.1.1"
    assert r["method"] == "GET"
    assert r["path"] == "/api/products"
    assert r["status"] == "200"
    assert r["bytes"] == 1234

def test_parse_docker_all():
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    assert len(records) == 5

def test_parse_docker_level_filter():
    records = parse_docker(DOCKER_LOG_SAMPLE, "ERROR")
    assert len(records) == 2
    assert all(r["level"] == "ERROR" for r in records)

def test_parse_nginx_error():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, None)
    assert len(records) == 3

def test_parse_nginx_error_level_filter():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, "error")
    assert len(records) == 2


# ─── Tests de análisis ────────────────────────────────────────────────────────

def test_analyze_nginx_access():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    stats = analyze_nginx_access(records, top_n=5)
    assert stats["total_requests"] == 5
    assert stats["total_bytes"] == 1234 + 567 + 1234 + 89 + 200
    assert "200" in stats["status_codes"]
    assert stats["status_codes"]["200"] == 2
    # IP más frecuente
    assert stats["top_ips"][0][0] in ("192.168.1.1", "10.0.0.5")

def test_analyze_docker():
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    stats = analyze_docker(records, top_n=5)
    assert stats["total_lines"] == 5
    assert stats["by_level"]["ERROR"] == 2
    assert stats["by_level"]["INFO"] == 2
    # Top error debe aparecer
    assert len(stats["top_errors"]) >= 1


# ─── Tests de CLI ─────────────────────────────────────────────────────────────

@pytest.fixture
def nginx_log_file(tmp_path):
    f = tmp_path / "access.log"
    f.write_text("\n".join(NGINX_ACCESS_SAMPLE) + "\n")
    return str(f)

@pytest.fixture
def docker_log_file(tmp_path):
    f = tmp_path / "app.log"
    f.write_text("\n".join(DOCKER_LOG_SAMPLE) + "\n")
    return str(f)


def test_cli_analyze_nginx(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx"])
    assert result.exit_code == 0
    assert "Resumen" in result.output or "requests" in result.output.lower() or "200" in result.output

def test_cli_analyze_docker(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", docker_log_file, "--format", "docker"])
    assert result.exit_code == 0

def test_cli_stats(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["stats", nginx_log_file])
    assert result.exit_code == 0
    assert "access.log" in result.output or "KB" in result.output

def test_cli_tail(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["tail", nginx_log_file, "--lines", "3"])
    assert result.exit_code == 0

def test_cli_export_json(nginx_log_file, tmp_path):
    out = str(tmp_path / "stats.json")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--export-json", out])
    assert result.exit_code == 0
    data = json.loads(Path(out).read_text())
    assert "total_requests" in data

def test_cli_export_csv(nginx_log_file, tmp_path):
    out = str(tmp_path / "records.csv")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--export-csv", out])
    assert result.exit_code == 0
    content = Path(out).read_text()
    assert "ip" in content  # header CSV

def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output

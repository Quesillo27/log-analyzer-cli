"""Tests para log-analyzer-cli — cobertura completa de parsers, analyzers y CLI."""

import gzip
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from log_analyzer import (
    detect_format,
    parse_nginx_access,
    parse_nginx_error,
    parse_docker,
    analyze_nginx_access,
    analyze_nginx_error,
    analyze_docker,
)
from log_analyzer.detectors import detect_format_from_lines
from log_analyzer.parsers import search_lines, _matches_status_filter
from log_analyzer.exporters import export_json, export_csv, export_markdown
from log_analyzer.cli import cli
from click.testing import CliRunner


# ─── Fixtures ─────────────────────────────────────────────────────────────────

NGINX_ACCESS_SAMPLE = [
    '192.168.1.1 - - [10/Apr/2026:12:00:00 +0000] "GET /api/products HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.2 - - [10/Apr/2026:12:01:00 +0000] "POST /api/orders HTTP/1.1" 201 567 "-" "curl/7.68.0"',
    '192.168.1.1 - - [10/Apr/2026:12:02:00 +0000] "GET /api/products HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [10/Apr/2026:12:03:00 +0000] "GET /nonexistent HTTP/1.1" 404 89 "-" "curl/7.68.0"',
    '10.0.0.5 - - [10/Apr/2026:12:04:00 +0000] "GET /api/error HTTP/1.1" 500 200 "-" "Python/3.11"',
    '10.0.0.6 - - [10/Apr/2026:12:05:00 +0000] "DELETE /api/users/1 HTTP/1.1" 403 50 "-" "curl/7.68.0"',
]

NGINX_ERROR_SAMPLE = [
    '2026/04/10 12:00:00 [error] 1234#0: *1 connect() failed (111: Connection refused)',
    '2026/04/10 12:01:00 [warn] 1234#0: *2 upstream slow response',
    '2026/04/10 12:02:00 [error] 1234#0: *3 file not found: /var/www/favicon.ico',
    '2026/04/10 12:03:00 [crit] 5678#0: *4 SSL handshake failed',
]

DOCKER_LOG_SAMPLE = [
    '2026-04-10T12:00:00Z INFO Server started on port 3000',
    '2026-04-10T12:01:00Z WARN Database connection slow (450ms)',
    '2026-04-10T12:02:00Z ERROR Failed to connect to Redis: ECONNREFUSED',
    '2026-04-10T12:03:00Z INFO Request processed in 23ms',
    '2026-04-10T12:04:00Z ERROR Failed to connect to Redis: ECONNREFUSED',
    '2026-04-10T12:05:00Z DEBUG Cache miss for key user:42',
    '2026-04-10T12:06:00Z FATAL Out of memory: kill process',
]


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


@pytest.fixture
def docker_gz_log_file(tmp_path):
    f = tmp_path / "app.log.gz"
    with gzip.open(f, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(DOCKER_LOG_SAMPLE) + "\n")
    return str(f)


@pytest.fixture
def nginx_error_log_file(tmp_path):
    f = tmp_path / "error.log"
    f.write_text("\n".join(NGINX_ERROR_SAMPLE) + "\n")
    return str(f)


@pytest.fixture
def empty_log_file(tmp_path):
    f = tmp_path / "empty.log"
    f.write_text("")
    return str(f)


# ─── Tests de detección de formato ────────────────────────────────────────────

def test_detect_nginx_access():
    assert detect_format(NGINX_ACCESS_SAMPLE[0]) == "nginx_access"


def test_detect_nginx_error():
    assert detect_format(NGINX_ERROR_SAMPLE[0]) == "nginx_error"


def test_detect_docker():
    assert detect_format(DOCKER_LOG_SAMPLE[0]) == "docker"


def test_detect_unknown():
    assert detect_format("esto no es un log reconocido") == "unknown"


def test_detect_format_from_lines_nginx():
    assert detect_format_from_lines(NGINX_ACCESS_SAMPLE) == "nginx_access"


def test_detect_format_from_lines_docker():
    assert detect_format_from_lines(DOCKER_LOG_SAMPLE) == "docker"


def test_detect_format_from_lines_skips_empty():
    lines = ["", "  ", NGINX_ERROR_SAMPLE[0]]
    assert detect_format_from_lines(lines) == "nginx_error"


def test_detect_format_from_lines_all_unknown():
    assert detect_format_from_lines(["garbage", "more garbage"]) == "unknown"


# ─── Tests de filtro de status ─────────────────────────────────────────────────

def test_status_filter_exact_match():
    assert _matches_status_filter("404", "404") is True


def test_status_filter_exact_no_match():
    assert _matches_status_filter("200", "404") is False


def test_status_filter_class_5xx():
    assert _matches_status_filter("500", "5xx") is True
    assert _matches_status_filter("503", "5xx") is True
    assert _matches_status_filter("200", "5xx") is False


def test_status_filter_class_4xx():
    assert _matches_status_filter("404", "4xx") is True
    assert _matches_status_filter("500", "4xx") is False


def test_status_filter_prefix():
    assert _matches_status_filter("500", "5") is True
    assert _matches_status_filter("404", "4") is True
    assert _matches_status_filter("200", "4") is False


# ─── Tests de parseo nginx access ─────────────────────────────────────────────

def test_parse_nginx_access_all():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    assert len(records) == 6


def test_parse_nginx_access_status_filter_5xx():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, "5xx", None)
    assert len(records) == 1
    assert records[0]["status"] == "500"


def test_parse_nginx_access_status_filter_4xx():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, "4xx", None)
    assert len(records) == 2
    statuses = {r["status"] for r in records}
    assert statuses == {"404", "403"}


def test_parse_nginx_access_status_filter_prefix():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, "5", None)
    assert len(records) == 1
    assert records[0]["status"] == "500"


def test_parse_nginx_access_ip_filter():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, "192.168.1.1")
    assert len(records) == 2
    assert all(r["ip"] == "192.168.1.1" for r in records)


def test_parse_nginx_access_fields():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    r = records[0]
    assert r["ip"] == "192.168.1.1"
    assert r["method"] == "GET"
    assert r["path"] == "/api/products"
    assert r["status"] == "200"
    assert r["bytes"] == 1234


def test_parse_nginx_access_limit():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None, limit=2)
    assert len(records) == 2


def test_parse_nginx_access_skips_malformed():
    lines = ["not a valid nginx line", NGINX_ACCESS_SAMPLE[0]]
    records = parse_nginx_access(lines, None, None)
    assert len(records) == 1


def test_parse_nginx_access_bytes_dash():
    line = '127.0.0.1 - - [10/Apr/2026:12:00:00 +0000] "HEAD / HTTP/1.1" 200 - "-" "-"'
    records = parse_nginx_access([line], None, None)
    assert records[0]["bytes"] == 0


# ─── Tests de parseo docker ────────────────────────────────────────────────────

def test_parse_docker_all():
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    assert len(records) == 7


def test_parse_docker_level_filter_error():
    records = parse_docker(DOCKER_LOG_SAMPLE, "ERROR")
    assert len(records) == 2
    assert all(r["level"] == "ERROR" for r in records)


def test_parse_docker_level_filter_fatal():
    records = parse_docker(DOCKER_LOG_SAMPLE, "FATAL")
    assert len(records) == 1
    assert "Out of memory" in records[0]["message"]


def test_parse_docker_limit():
    records = parse_docker(DOCKER_LOG_SAMPLE, None, limit=3)
    assert len(records) == 3


def test_parse_docker_no_level_defaults_to_info():
    lines = ["plain log line without level"]
    records = parse_docker(lines, None)
    assert records[0]["level"] == "INFO"


def test_parse_docker_fields():
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    r = records[0]
    assert r["level"] == "INFO"
    assert "Server started" in r["message"]
    assert r["timestamp"].startswith("2026-04-10")


# ─── Tests de parseo nginx error ──────────────────────────────────────────────

def test_parse_nginx_error_all():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, None)
    assert len(records) == 4


def test_parse_nginx_error_level_filter():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, "error")
    assert len(records) == 2


def test_parse_nginx_error_warn_filter():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, "warn")
    assert len(records) == 1
    assert "slow response" in records[0]["message"]


def test_parse_nginx_error_limit():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, None, limit=2)
    assert len(records) == 2


def test_parse_nginx_error_fields():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, None)
    r = records[0]
    assert r["level"] == "error"
    assert r["date"] == "2026/04/10"
    assert r["pid"] == "1234"


# ─── Tests de análisis ────────────────────────────────────────────────────────

def test_analyze_nginx_access_totals():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    stats = analyze_nginx_access(records, top_n=5)
    assert stats["total_requests"] == 6
    assert stats["total_bytes"] == 1234 + 567 + 1234 + 89 + 200 + 50
    assert stats["errors_5xx"] == 1
    assert stats["errors_4xx"] == 2


def test_analyze_nginx_access_top_ip():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    stats = analyze_nginx_access(records, top_n=5)
    top_count = stats["top_ips"][0][1]
    assert top_count == 2  # IP líder tiene 2 requests


def test_analyze_nginx_access_status_codes():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    stats = analyze_nginx_access(records, top_n=5)
    assert "200" in stats["status_codes"]
    assert stats["status_codes"]["200"] == 2


def test_analyze_nginx_access_includes_agents():
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    stats = analyze_nginx_access(records, top_n=5)
    assert len(stats["top_agents"]) > 0


def test_analyze_docker_totals():
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    stats = analyze_docker(records, top_n=5)
    assert stats["total_lines"] == 7
    assert stats["by_level"]["ERROR"] == 2
    assert stats["by_level"]["INFO"] == 2
    assert stats["error_count"] == 3  # 2 ERROR + 1 FATAL


def test_analyze_docker_top_errors():
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    stats = analyze_docker(records, top_n=5)
    assert len(stats["top_errors"]) >= 1
    # El error repetido debe ser el top
    assert "ECONNREFUSED" in stats["top_errors"][0][0]


def test_analyze_nginx_error():
    records = parse_nginx_error(NGINX_ERROR_SAMPLE, None)
    stats = analyze_nginx_error(records, top_n=5)
    assert stats["total_errors"] == 4
    assert "error" in stats["by_level"]


# ─── Tests de búsqueda ────────────────────────────────────────────────────────

def test_search_lines_basic():
    results = search_lines(DOCKER_LOG_SAMPLE, "ECONNREFUSED")
    assert len(results) == 2


def test_search_lines_returns_line_numbers():
    results = search_lines(DOCKER_LOG_SAMPLE, "FATAL")
    assert results[0][0] == 7  # línea 7


def test_search_lines_case_insensitive_default():
    results = search_lines(DOCKER_LOG_SAMPLE, "error")
    assert len(results) >= 2


def test_search_lines_case_sensitive():
    results = search_lines(DOCKER_LOG_SAMPLE, "error", case_sensitive=True)
    assert len(results) == 0  # el log usa "ERROR" en mayúsculas


def test_search_lines_regex_pattern():
    results = search_lines(DOCKER_LOG_SAMPLE, r"port \d+")
    assert len(results) == 1
    assert "3000" in results[0][1]


def test_search_lines_invalid_regex():
    with pytest.raises(ValueError, match="inválido"):
        search_lines(DOCKER_LOG_SAMPLE, "[invalid")


def test_search_lines_no_match():
    results = search_lines(DOCKER_LOG_SAMPLE, "NONEXISTENT_PATTERN_XYZ")
    assert results == []


# ─── Tests de exporters ───────────────────────────────────────────────────────

def test_export_json_creates_file(tmp_path):
    stats = {"total_requests": 5, "total_bytes": 1000}
    out = str(tmp_path / "stats.json")
    export_json(stats, out)
    data = json.loads(Path(out).read_text())
    assert data["total_requests"] == 5


def test_export_csv_creates_file(tmp_path):
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    out = str(tmp_path / "records.csv")
    export_csv(records, out)
    content = Path(out).read_text()
    assert "ip" in content
    assert "192.168.1.1" in content


def test_export_csv_empty_records(tmp_path, capsys):
    out = str(tmp_path / "empty.csv")
    export_csv([], out)
    assert not Path(out).exists()


def test_export_markdown_nginx(tmp_path):
    records = parse_nginx_access(NGINX_ACCESS_SAMPLE, None, None)
    stats = analyze_nginx_access(records, top_n=5)
    out = str(tmp_path / "report.md")
    export_markdown(stats, "nginx", out)
    content = Path(out).read_text()
    assert "# Log Analysis Report" in content
    assert "Status Codes" in content
    assert "Top IPs" in content


def test_export_markdown_docker(tmp_path):
    records = parse_docker(DOCKER_LOG_SAMPLE, None)
    stats = analyze_docker(records, top_n=5)
    out = str(tmp_path / "report.md")
    export_markdown(stats, "docker", out)
    content = Path(out).read_text()
    assert "Por Nivel" in content


# ─── Tests de CLI ─────────────────────────────────────────────────────────────

def test_cli_analyze_nginx(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx"])
    assert result.exit_code == 0
    assert "Resumen" in result.output or "200" in result.output


def test_cli_analyze_nginx_status_5xx(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--status", "5xx"])
    assert result.exit_code == 0


def test_cli_analyze_docker(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", docker_log_file, "--format", "docker"])
    assert result.exit_code == 0


def test_cli_analyze_docker_gz(docker_gz_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", docker_gz_log_file, "--format", "docker"])
    assert result.exit_code == 0
    assert "Procesadas 7 líneas" in result.output


def test_cli_analyze_docker_level_filter(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", docker_log_file, "--format", "docker", "--level", "ERROR"])
    assert result.exit_code == 0


def test_cli_analyze_nginx_error(nginx_error_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_error_log_file, "--format", "nginx-error"])
    assert result.exit_code == 0


def test_cli_analyze_empty_file(empty_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", empty_log_file])
    assert result.exit_code == 0
    assert "vacío" in result.output


def test_cli_analyze_auto_detect(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file])
    assert result.exit_code == 0
    assert "nginx" in result.output


def test_cli_analyze_export_json(nginx_log_file, tmp_path):
    out = str(tmp_path / "stats.json")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--export-json", out])
    assert result.exit_code == 0
    data = json.loads(Path(out).read_text())
    assert "total_requests" in data


def test_cli_analyze_export_csv(nginx_log_file, tmp_path):
    out = str(tmp_path / "records.csv")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--export-csv", out])
    assert result.exit_code == 0
    content = Path(out).read_text()
    assert "ip" in content


def test_cli_analyze_export_markdown(nginx_log_file, tmp_path):
    out = str(tmp_path / "report.md")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--export-md", out])
    assert result.exit_code == 0
    assert Path(out).exists()
    assert "# Log Analysis Report" in Path(out).read_text()


def test_cli_analyze_limit(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", nginx_log_file, "--format", "nginx", "--limit", "2"])
    assert result.exit_code == 0


def test_cli_stats_panel(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["stats", nginx_log_file])
    assert result.exit_code == 0
    assert "access.log" in result.output or "KB" in result.output


def test_cli_stats_json(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["stats", nginx_log_file, "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "file" in data
    assert "lines" in data
    assert data["lines"] == 6


def test_cli_stats_json_gz(docker_gz_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["stats", docker_gz_log_file, "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["file"] == "app.log.gz"
    assert data["lines"] == 7
    assert data["format"] == "docker"


def test_cli_tail_plain(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["tail", nginx_log_file, "--lines", "3"])
    assert result.exit_code == 0


def test_cli_tail_json_gz(docker_gz_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["tail", docker_gz_log_file, "--lines", "2", "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 2
    assert "Out of memory" in data[-1]


def test_cli_tail_json(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["tail", nginx_log_file, "--lines", "3", "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 3


def test_cli_tail_table(nginx_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["tail", nginx_log_file, "--lines", "2", "--output", "table"])
    assert result.exit_code == 0


def test_cli_tail_level_filter(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["tail", docker_log_file, "--level", "ERROR"])
    assert result.exit_code == 0


def test_cli_search_basic(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_log_file, "ECONNREFUSED"])
    assert result.exit_code == 0
    assert "2 coincidencias" in result.output


def test_cli_search_count_gz(docker_gz_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_gz_log_file, "ERROR", "--output", "count"])
    assert result.exit_code == 0
    assert result.output.strip() == "2"


def test_cli_search_count_output(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_log_file, "ERROR", "--output", "count"])
    assert result.exit_code == 0
    assert result.output.strip() == "2"


def test_cli_search_json_output(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_log_file, "INFO", "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert all("line" in item and "content" in item for item in data)


def test_cli_search_no_results(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_log_file, "NONEXISTENT_XYZ_999"])
    assert result.exit_code == 0
    assert "Sin resultados" in result.output


def test_cli_search_limit(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_log_file, ".", "--output", "json", "--limit", "2"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 2


def test_cli_search_invalid_regex(docker_log_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["search", docker_log_file, "[invalid"])
    assert result.exit_code != 0 or "Error" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "2.0.0" in result.output

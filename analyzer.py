#!/usr/bin/env python3
"""
log-analyzer-cli — Analizador de logs nginx/docker con estadísticas coloridas.
"""

import re
import sys
import json
import csv
import io
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# ─── Patrones de log ──────────────────────────────────────────────────────────

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

# ─── Parsers ──────────────────────────────────────────────────────────────────

def detect_format(line: str) -> str:
    """Detecta el formato del log automáticamente."""
    if NGINX_COMBINED.match(line):
        return "nginx_access"
    if NGINX_ERROR.match(line):
        return "nginx_error"
    if DOCKER_LOG.match(line):
        return "docker"
    return "unknown"


def parse_nginx_access(lines: list[str], status_filter: str | None, ip_filter: str | None) -> list[dict]:
    records = []
    for line in lines:
        m = NGINX_COMBINED.match(line.strip())
        if not m:
            continue
        r = m.groupdict()
        r["bytes"] = int(r["bytes"]) if r["bytes"] != "-" else 0

        if status_filter and not r["status"].startswith(status_filter.rstrip("x")):
            continue
        if ip_filter and r["ip"] != ip_filter:
            continue
        records.append(r)
    return records


def parse_docker(lines: list[str], level_filter: str | None) -> list[dict]:
    records = []
    for line in lines:
        m = DOCKER_LOG.match(line.strip())
        if not m:
            # Log sin nivel detectado
            r = {"timestamp": "", "level": "INFO", "message": line.strip()}
        else:
            r = m.groupdict()
            if not r.get("level"):
                r["level"] = "INFO"

        if level_filter and r["level"] != level_filter.upper():
            continue
        records.append(r)
    return records


def parse_nginx_error(lines: list[str], level_filter: str | None) -> list[dict]:
    records = []
    for line in lines:
        m = NGINX_ERROR.match(line.strip())
        if not m:
            continue
        r = m.groupdict()
        if level_filter and r["level"].lower() != level_filter.lower():
            continue
        records.append(r)
    return records


# ─── Análisis ─────────────────────────────────────────────────────────────────

def analyze_nginx_access(records: list[dict], top_n: int) -> dict:
    ips = Counter(r["ip"] for r in records)
    paths = Counter(r["path"] for r in records)
    statuses = Counter(r["status"] for r in records)
    methods = Counter(r["method"] for r in records if r.get("method"))
    total_bytes = sum(r["bytes"] for r in records)

    return {
        "total_requests": len(records),
        "total_bytes": total_bytes,
        "top_ips": ips.most_common(top_n),
        "top_paths": paths.most_common(top_n),
        "status_codes": dict(sorted(statuses.items())),
        "methods": dict(methods),
    }


def analyze_docker(records: list[dict], top_n: int) -> dict:
    levels = Counter(r["level"] for r in records)
    # Top errores únicos
    errors = [r["message"] for r in records if r["level"] in ("ERROR", "FATAL", "CRITICAL")]
    top_errors = Counter(errors).most_common(top_n)

    return {
        "total_lines": len(records),
        "by_level": dict(sorted(levels.items())),
        "top_errors": top_errors,
    }


def analyze_nginx_error(records: list[dict], top_n: int) -> dict:
    levels = Counter(r["level"] for r in records)
    msgs = Counter(r["message"][:80] for r in records)

    return {
        "total_errors": len(records),
        "by_level": dict(sorted(levels.items())),
        "top_messages": msgs.most_common(top_n),
    }


# ─── Renderizado ──────────────────────────────────────────────────────────────

def render_nginx_access(stats: dict, top_n: int) -> None:
    console.print()
    console.print(Panel(
        f"[bold]Total requests:[/bold] {stats['total_requests']:,}  |  "
        f"[bold]Total bytes:[/bold] {stats['total_bytes']:,}",
        title="[bold cyan]📊 Nginx Access Log — Resumen[/bold cyan]",
        border_style="cyan"
    ))

    # Status codes
    t = Table(title="Códigos de Status", box=box.SIMPLE_HEAVY, border_style="blue")
    t.add_column("Status", style="bold")
    t.add_column("Count", justify="right")
    t.add_column("Tipo")
    for code, count in sorted(stats["status_codes"].items()):
        c = int(code)
        if c < 300:
            tipo = "[green]OK[/green]"
        elif c < 400:
            tipo = "[yellow]Redirect[/yellow]"
        elif c < 500:
            tipo = "[orange3]Client Error[/orange3]"
        else:
            tipo = "[red]Server Error[/red]"
        t.add_row(code, f"{count:,}", tipo)
    console.print(t)

    # Top IPs
    t2 = Table(title=f"Top {top_n} IPs", box=box.SIMPLE_HEAVY, border_style="magenta")
    t2.add_column("IP", style="cyan")
    t2.add_column("Requests", justify="right")
    for ip, count in stats["top_ips"]:
        t2.add_row(ip, f"{count:,}")
    console.print(t2)

    # Top paths
    t3 = Table(title=f"Top {top_n} Paths", box=box.SIMPLE_HEAVY, border_style="green")
    t3.add_column("Path")
    t3.add_column("Requests", justify="right")
    for path, count in stats["top_paths"]:
        t3.add_row(path[:80], f"{count:,}")
    console.print(t3)

    # Methods
    t4 = Table(title="Métodos HTTP", box=box.SIMPLE_HEAVY, border_style="yellow")
    t4.add_column("Método")
    t4.add_column("Count", justify="right")
    for method, count in stats["methods"].items():
        t4.add_row(method, f"{count:,}")
    console.print(t4)


def render_docker(stats: dict, top_n: int) -> None:
    console.print()
    console.print(Panel(
        f"[bold]Total líneas:[/bold] {stats['total_lines']:,}",
        title="[bold cyan]🐳 Docker Log — Resumen[/bold cyan]",
        border_style="cyan"
    ))

    t = Table(title="Por Nivel", box=box.SIMPLE_HEAVY)
    t.add_column("Nivel")
    t.add_column("Count", justify="right")
    level_colors = {"DEBUG": "dim", "INFO": "green", "WARN": "yellow", "WARNING": "yellow",
                    "ERROR": "red", "FATAL": "bold red", "CRITICAL": "bold red"}
    for level, count in stats["by_level"].items():
        color = level_colors.get(level, "white")
        t.add_row(f"[{color}]{level}[/{color}]", f"{count:,}")
    console.print(t)

    if stats["top_errors"]:
        t2 = Table(title=f"Top {top_n} Errores", box=box.SIMPLE_HEAVY, border_style="red")
        t2.add_column("Mensaje (primeros 80 chars)")
        t2.add_column("Count", justify="right")
        for msg, count in stats["top_errors"]:
            t2.add_row(msg[:80], f"{count:,}")
        console.print(t2)


def render_nginx_error(stats: dict, top_n: int) -> None:
    console.print()
    console.print(Panel(
        f"[bold]Total errores:[/bold] {stats['total_errors']:,}",
        title="[bold red]🚨 Nginx Error Log — Resumen[/bold red]",
        border_style="red"
    ))

    t = Table(title="Por Nivel", box=box.SIMPLE_HEAVY)
    t.add_column("Nivel")
    t.add_column("Count", justify="right")
    for level, count in stats["by_level"].items():
        t.add_row(level, f"{count:,}")
    console.print(t)

    if stats["top_messages"]:
        t2 = Table(title=f"Top {top_n} Mensajes", box=box.SIMPLE_HEAVY, border_style="orange3")
        t2.add_column("Mensaje")
        t2.add_column("Count", justify="right")
        for msg, count in stats["top_messages"]:
            t2.add_row(msg, f"{count:,}")
        console.print(t2)


# ─── Export ──────────────────────────────────────────────────────────────────

def export_json(stats: dict, output_path: str) -> None:
    path = Path(output_path)
    path.write_text(json.dumps(stats, indent=2, default=str))
    console.print(f"[green]✅ Exportado a JSON:[/green] {path}")


def export_csv(records: list[dict], output_path: str) -> None:
    if not records:
        console.print("[yellow]No hay registros para exportar[/yellow]")
        return
    path = Path(output_path)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    console.print(f"[green]✅ Exportado a CSV:[/green] {path}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="log-analyzer")
def cli():
    """🔍 Log Analyzer CLI — Analiza logs nginx/docker con estadísticas."""
    pass


@cli.command("analyze")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["auto", "nginx", "nginx-error", "docker"]),
              default="auto", show_default=True, help="Formato del log")
@click.option("--top", default=10, show_default=True, help="Número de items en top N")
@click.option("--status", default=None, help="Filtrar por código de status (ej: 5, 404, 2xx)")
@click.option("--ip", default=None, help="Filtrar por IP específica")
@click.option("--level", default=None, help="Filtrar por nivel de log (ERROR, WARN, INFO...)")
@click.option("--export-json", "json_out", default=None, help="Exportar estadísticas a JSON")
@click.option("--export-csv", "csv_out", default=None, help="Exportar registros a CSV")
def analyze(logfile, fmt, top, status, ip, level, json_out, csv_out):
    """Analiza un archivo de log y muestra estadísticas."""

    path = Path(logfile)
    lines = path.read_text(errors="replace").splitlines()

    if not lines:
        console.print("[yellow]El archivo está vacío[/yellow]")
        return

    # Auto-detectar formato
    if fmt == "auto":
        sample = next((l for l in lines if l.strip()), "")
        fmt_detected = detect_format(sample)
        if fmt_detected == "nginx_access":
            fmt = "nginx"
        elif fmt_detected == "nginx_error":
            fmt = "nginx-error"
        elif fmt_detected == "docker":
            fmt = "docker"
        else:
            fmt = "docker"  # fallback genérico
        console.print(f"[dim]Formato detectado: {fmt}[/dim]")

    if fmt == "nginx":
        records = parse_nginx_access(lines, status, ip)
        stats = analyze_nginx_access(records, top)
        render_nginx_access(stats, top)
        if json_out:
            export_json(stats, json_out)
        if csv_out:
            export_csv(records, csv_out)

    elif fmt == "nginx-error":
        records = parse_nginx_error(lines, level)
        stats = analyze_nginx_error(records, top)
        render_nginx_error(stats, top)
        if json_out:
            export_json(stats, json_out)
        if csv_out:
            export_csv(records, csv_out)

    elif fmt == "docker":
        records = parse_docker(lines, level)
        stats = analyze_docker(records, top)
        render_docker(stats, top)
        if json_out:
            export_json(stats, json_out)
        if csv_out:
            export_csv(records, csv_out)

    console.print(f"\n[dim]Procesadas {len(lines):,} líneas de {path.name}[/dim]")


@cli.command("tail")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--lines", "-n", default=20, show_default=True, help="Últimas N líneas")
@click.option("--level", default=None, help="Filtrar por nivel (ERROR, WARN...)")
def tail(logfile, lines, level):
    """Muestra las últimas N líneas de un log con coloring."""
    path = Path(logfile)
    all_lines = path.read_text(errors="replace").splitlines()
    last = all_lines[-lines:]

    level_colors = {
        "ERROR": "red", "FATAL": "bold red", "CRITICAL": "bold red",
        "WARN": "yellow", "WARNING": "yellow",
        "INFO": "green", "DEBUG": "dim",
    }

    console.print(f"\n[bold cyan]📄 {path.name}[/bold cyan] — últimas {lines} líneas\n")
    for line in last:
        if level:
            if level.upper() not in line.upper():
                continue
        colored = line
        for lvl, color in level_colors.items():
            if lvl in line.upper():
                colored = f"[{color}]{line}[/{color}]"
                break
        console.print(colored)


@cli.command("stats")
@click.argument("logfile", type=click.Path(exists=True))
def stats_cmd(logfile):
    """Resumen rápido de un archivo de log (líneas, tamaño, fechas)."""
    path = Path(logfile)
    content = path.read_text(errors="replace")
    lines = content.splitlines()
    size_kb = path.stat().st_size / 1024

    # Intento detectar rango de fechas
    dates = re.findall(r'\d{4}[-/]\d{2}[-/]\d{2}', content)
    date_range = f"{min(dates)} → {max(dates)}" if dates else "desconocido"

    console.print(Panel(
        f"[bold]Archivo:[/bold] {path.name}\n"
        f"[bold]Tamaño:[/bold] {size_kb:.1f} KB\n"
        f"[bold]Líneas:[/bold] {len(lines):,}\n"
        f"[bold]Rango de fechas:[/bold] {date_range}\n"
        f"[bold]Formato detectado:[/bold] {detect_format(lines[0] if lines else '')}",
        title="[bold]📁 Stats del Archivo[/bold]",
        border_style="blue"
    ))


if __name__ == "__main__":
    cli()

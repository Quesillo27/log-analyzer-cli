"""CLI de log-analyzer usando Click."""

import gzip
import re
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.table import Table

from . import __version__
from .config import DEFAULT_TOP_N, DEFAULT_TAIL_LINES, LEVEL_COLORS
from .detectors import detect_format, detect_format_from_lines
from .parsers import parse_nginx_access, parse_nginx_error, parse_docker, search_lines
from .analyzers import analyze_nginx_access, analyze_nginx_error, analyze_docker
from .renderers import render_nginx_access, render_nginx_error, render_docker
from .exporters import export_json, export_csv, export_markdown

console = Console()


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise click.BadParameter(f"Fecha inválida: '{value}'. Usa formato YYYY-MM-DD o YYYY-MM-DDTHH:MM:SS")


def _read_lines(path: Path) -> list[str]:
    return _read_text(path).splitlines()


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8", errors="replace")


def _resolve_format(fmt: str, lines: list[str]) -> str:
    if fmt != "auto":
        return fmt
    detected = detect_format_from_lines(lines)
    mapping = {"nginx_access": "nginx", "nginx_error": "nginx-error", "docker": "docker"}
    resolved = mapping.get(detected, "docker")
    console.print(f"[dim]Formato detectado: {resolved}[/dim]")
    return resolved


@click.group()
@click.version_option(__version__, prog_name="log-analyzer")
def cli():
    """🔍 Log Analyzer CLI — Analiza logs nginx/docker con estadísticas."""
    pass


@cli.command("analyze")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["auto", "nginx", "nginx-error", "docker"]),
              default="auto", show_default=True, help="Formato del log")
@click.option("--top", default=DEFAULT_TOP_N, show_default=True, help="Número de items en top N")
@click.option("--status", default=None, help="Filtrar por código HTTP (ej: 5, 404, 2xx, 5xx)")
@click.option("--ip", default=None, help="Filtrar por IP específica")
@click.option("--level", default=None, help="Filtrar por nivel de log (ERROR, WARN, INFO...)")
@click.option("--since", default=None, help="Solo líneas desde esta fecha (YYYY-MM-DD o YYYY-MM-DDTHH:MM:SS)")
@click.option("--until", default=None, help="Solo líneas hasta esta fecha (YYYY-MM-DD o YYYY-MM-DDTHH:MM:SS)")
@click.option("--limit", default=0, help="Máximo de registros a procesar (0 = sin límite)")
@click.option("--export-json", "json_out", default=None, help="Exportar estadísticas a JSON")
@click.option("--export-csv", "csv_out", default=None, help="Exportar registros a CSV")
@click.option("--export-md", "md_out", default=None, help="Exportar informe a Markdown")
def analyze(logfile, fmt, top, status, ip, level, since, until, limit, json_out, csv_out, md_out):
    """Analiza un archivo de log y muestra estadísticas."""
    since_dt = _parse_datetime(since)
    until_dt = _parse_datetime(until)

    path = Path(logfile)
    lines = _read_lines(path)

    if not lines:
        console.print("[yellow]El archivo está vacío[/yellow]")
        return

    fmt = _resolve_format(fmt, lines)

    if fmt == "nginx":
        records = parse_nginx_access(lines, status, ip, since_dt, until_dt, limit)
        stats = analyze_nginx_access(records, top)
        render_nginx_access(stats, top)
        if json_out:
            export_json(stats, json_out)
        if csv_out:
            export_csv(records, csv_out)
        if md_out:
            export_markdown(stats, fmt, md_out)

    elif fmt == "nginx-error":
        records = parse_nginx_error(lines, level, since_dt, until_dt, limit)
        stats = analyze_nginx_error(records, top)
        render_nginx_error(stats, top)
        if json_out:
            export_json(stats, json_out)
        if csv_out:
            export_csv(records, csv_out)
        if md_out:
            export_markdown(stats, fmt, md_out)

    elif fmt == "docker":
        records = parse_docker(lines, level, since_dt, until_dt, limit)
        stats = analyze_docker(records, top)
        render_docker(stats, top)
        if json_out:
            export_json(stats, json_out)
        if csv_out:
            export_csv(records, csv_out)
        if md_out:
            export_markdown(stats, fmt, md_out)

    console.print(f"\n[dim]Procesadas {len(lines):,} líneas de {path.name}[/dim]")


@cli.command("tail")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--lines", "-n", default=DEFAULT_TAIL_LINES, show_default=True, help="Últimas N líneas")
@click.option("--level", default=None, help="Filtrar por nivel (ERROR, WARN...)")
@click.option("--output", type=click.Choice(["table", "json", "plain"]), default="plain",
              show_default=True, help="Formato de salida")
def tail(logfile, lines, level, output):
    """Muestra las últimas N líneas de un log con coloring."""
    path = Path(logfile)
    all_lines = _read_lines(path)
    last = all_lines[-lines:]

    if level:
        last = [l for l in last if level.upper() in l.upper()]

    if output == "json":
        click.echo(json.dumps(last, ensure_ascii=False, indent=2))
        return

    if output == "table":
        t = Table(title=f"{path.name} — últimas {lines} líneas", box=box.SIMPLE_HEAVY)
        t.add_column("#", style="dim", justify="right")
        t.add_column("Línea")
        for i, line in enumerate(last, 1):
            t.add_row(str(i), line[:120])
        console.print(t)
        return

    console.print(f"\n[bold cyan]📄 {path.name}[/bold cyan] — últimas {lines} líneas\n")
    for line in last:
        colored = line
        for lvl, color in LEVEL_COLORS.items():
            if lvl in line.upper():
                colored = f"[{color}]{line}[/{color}]"
                break
        console.print(colored)


@cli.command("stats")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--output", type=click.Choice(["panel", "json"]), default="panel",
              show_default=True, help="Formato de salida")
def stats_cmd(logfile, output):
    """Resumen rápido de un archivo de log (líneas, tamaño, fechas)."""
    import re as _re
    path = Path(logfile)
    content = _read_text(path)
    lines = content.splitlines()
    size_kb = path.stat().st_size / 1024

    dates = _re.findall(r'\d{4}[-/]\d{2}[-/]\d{2}', content)
    date_range = f"{min(dates)} → {max(dates)}" if dates else "desconocido"
    fmt = detect_format(lines[0] if lines else "")

    if output == "json":
        click.echo(json.dumps({
            "file": path.name,
            "size_kb": round(size_kb, 1),
            "lines": len(lines),
            "date_range": date_range,
            "format": fmt,
        }, indent=2))
        return

    console.print(Panel(
        f"[bold]Archivo:[/bold] {path.name}\n"
        f"[bold]Tamaño:[/bold] {size_kb:.1f} KB\n"
        f"[bold]Líneas:[/bold] {len(lines):,}\n"
        f"[bold]Rango de fechas:[/bold] {date_range}\n"
        f"[bold]Formato detectado:[/bold] {fmt}",
        title="[bold]📁 Stats del Archivo[/bold]",
        border_style="blue"
    ))


@cli.command("search")
@click.argument("logfile", type=click.Path(exists=True))
@click.argument("pattern")
@click.option("--case-sensitive", is_flag=True, default=False, help="Búsqueda sensible a mayúsculas")
@click.option("--context", "-C", default=0, help="Líneas de contexto antes y después del match")
@click.option("--output", type=click.Choice(["plain", "json", "count"]), default="plain",
              show_default=True, help="Formato de salida")
@click.option("--limit", default=0, help="Máximo de resultados (0 = sin límite)")
def search(logfile, pattern, case_sensitive, context, output, limit):
    """Busca un patrón regex en el archivo de log."""
    path = Path(logfile)
    all_lines = _read_lines(path)

    try:
        matches = search_lines(all_lines, pattern, case_sensitive)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if limit:
        matches = matches[:limit]

    if output == "count":
        click.echo(str(len(matches)))
        return

    if output == "json":
        click.echo(json.dumps(
            [{"line": ln, "content": content} for ln, content in matches],
            indent=2, ensure_ascii=False
        ))
        return

    if not matches:
        console.print(f"[yellow]Sin resultados para:[/yellow] {pattern}")
        return

    console.print(f"\n[bold cyan]🔍 {path.name}[/bold cyan] — {len(matches)} coincidencias para [bold]{pattern}[/bold]\n")
    flags = 0 if case_sensitive else re.IGNORECASE
    rx = re.compile(pattern, flags)

    for line_no, content in matches:
        if context:
            start = max(0, line_no - 1 - context)
            end = min(len(all_lines), line_no + context)
            for i in range(start, end):
                prefix = f"[cyan]{i+1:>6}[/cyan]" if (i + 1) != line_no else f"[bold green]{i+1:>6}[/bold green]"
                console.print(f"{prefix}  {all_lines[i]}")
            console.print("[dim]---[/dim]")
        else:
            highlighted = rx.sub(lambda m: f"[bold yellow]{m.group()}[/bold yellow]", content)
            console.print(f"[dim]{line_no:>6}[/dim]  {highlighted}")

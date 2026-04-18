"""Exportadores de datos a JSON, CSV y Markdown."""

import csv
import json
from pathlib import Path

from rich.console import Console

console = Console()


def export_json(stats: dict, output_path: str) -> None:
    path = Path(output_path)
    path.write_text(json.dumps(stats, indent=2, default=str))
    console.print(f"[green]✅ Exportado a JSON:[/green] {path}")


def export_csv(records: list[dict], output_path: str) -> None:
    if not records:
        console.print("[yellow]No hay registros para exportar[/yellow]")
        return
    path = Path(output_path)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    console.print(f"[green]✅ Exportado a CSV:[/green] {path}")


def export_markdown(stats: dict, fmt: str, output_path: str) -> None:
    """Genera un informe Markdown de las estadísticas."""
    path = Path(output_path)
    lines = [f"# Log Analysis Report\n"]

    if fmt == "nginx":
        lines += [
            f"**Total requests:** {stats['total_requests']:,}  ",
            f"**Total bytes:** {stats['total_bytes']:,}  ",
            f"**Errores 4xx:** {stats['errors_4xx']:,}  ",
            f"**Errores 5xx:** {stats['errors_5xx']:,}\n",
            "## Status Codes\n",
            "| Status | Count |",
            "|--------|-------|",
        ]
        for code, count in sorted(stats["status_codes"].items()):
            lines.append(f"| {code} | {count:,} |")
        lines += [
            "\n## Top IPs\n",
            "| IP | Requests |",
            "|----|----------|",
        ]
        for ip, count in stats["top_ips"]:
            lines.append(f"| {ip} | {count:,} |")
        lines += [
            "\n## Top Paths\n",
            "| Path | Requests |",
            "|------|----------|",
        ]
        for p, count in stats["top_paths"]:
            lines.append(f"| {p[:80]} | {count:,} |")

    elif fmt == "docker":
        lines += [
            f"**Total líneas:** {stats['total_lines']:,}  ",
            f"**Errores:** {stats['error_count']:,}\n",
            "## Por Nivel\n",
            "| Nivel | Count |",
            "|-------|-------|",
        ]
        for level, count in stats["by_level"].items():
            lines.append(f"| {level} | {count:,} |")
        if stats["top_errors"]:
            lines += ["\n## Top Errores\n", "| Mensaje | Count |", "|---------|-------|"]
            for msg, count in stats["top_errors"]:
                lines.append(f"| {msg[:80]} | {count:,} |")

    elif fmt == "nginx-error":
        lines += [
            f"**Total errores:** {stats['total_errors']:,}\n",
            "## Por Nivel\n",
            "| Nivel | Count |",
            "|-------|-------|",
        ]
        for level, count in stats["by_level"].items():
            lines.append(f"| {level} | {count:,} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[green]✅ Exportado a Markdown:[/green] {path}")

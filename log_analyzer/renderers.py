"""Renderizado de estadísticas en terminal usando Rich."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from .config import LEVEL_COLORS

console = Console()


def render_nginx_access(stats: dict, top_n: int) -> None:
    console.print()
    console.print(Panel(
        f"[bold]Total requests:[/bold] {stats['total_requests']:,}  |  "
        f"[bold]Total bytes:[/bold] {stats['total_bytes']:,}  |  "
        f"[bold]Errores 4xx:[/bold] [yellow]{stats['errors_4xx']:,}[/yellow]  |  "
        f"[bold]Errores 5xx:[/bold] [red]{stats['errors_5xx']:,}[/red]",
        title="[bold cyan]📊 Nginx Access Log — Resumen[/bold cyan]",
        border_style="cyan"
    ))

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

    t2 = Table(title=f"Top {top_n} IPs", box=box.SIMPLE_HEAVY, border_style="magenta")
    t2.add_column("IP", style="cyan")
    t2.add_column("Requests", justify="right")
    for ip, count in stats["top_ips"]:
        t2.add_row(ip, f"{count:,}")
    console.print(t2)

    t3 = Table(title=f"Top {top_n} Paths", box=box.SIMPLE_HEAVY, border_style="green")
    t3.add_column("Path")
    t3.add_column("Requests", justify="right")
    for path, count in stats["top_paths"]:
        t3.add_row(path[:80], f"{count:,}")
    console.print(t3)

    t4 = Table(title="Métodos HTTP", box=box.SIMPLE_HEAVY, border_style="yellow")
    t4.add_column("Método")
    t4.add_column("Count", justify="right")
    for method, count in stats["methods"].items():
        t4.add_row(method, f"{count:,}")
    console.print(t4)


def render_docker(stats: dict, top_n: int) -> None:
    console.print()
    console.print(Panel(
        f"[bold]Total líneas:[/bold] {stats['total_lines']:,}  |  "
        f"[bold]Errores:[/bold] [red]{stats['error_count']:,}[/red]",
        title="[bold cyan]🐳 Docker Log — Resumen[/bold cyan]",
        border_style="cyan"
    ))

    t = Table(title="Por Nivel", box=box.SIMPLE_HEAVY)
    t.add_column("Nivel")
    t.add_column("Count", justify="right")
    for level, count in stats["by_level"].items():
        color = LEVEL_COLORS.get(level, "white")
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

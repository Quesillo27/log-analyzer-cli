# log-analyzer-cli

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![CLI](https://img.shields.io/badge/cli-click-green) ![License](https://img.shields.io/badge/license-MIT-yellow)

Herramienta de línea de comandos para parsear y analizar logs de **nginx** (access y error) y **Docker** con estadísticas coloridas en terminal. Detecta el formato automáticamente.

## Instalación en 3 comandos

```bash
git clone https://github.com/Quesillo27/log-analyzer-cli
cd log-analyzer-cli
pip install -r requirements.txt
```

## Uso

```bash
# Analizar log nginx (auto-detect)
python analyzer.py analyze /var/log/nginx/access.log

# Analizar log Docker filtrando solo errores
python analyzer.py analyze app.log --format docker --level ERROR

# Ver últimas 50 líneas con coloring
python analyzer.py tail /var/log/nginx/error.log --lines 50

# Stats rápidas de un archivo
python analyzer.py stats /var/log/nginx/access.log
```

## Ejemplo

```bash
python analyzer.py analyze access.log --format nginx --top 5
# → Muestra tabla con status codes, top IPs, top paths, métodos HTTP

python analyzer.py analyze app.log --format docker --export-json stats.json
# → Exporta estadísticas a stats.json

python analyzer.py analyze access.log --format nginx --status 5 --top 10
# → Solo errores 5xx, top 10 paths
```

## API / Comandos disponibles

| Comando | Descripción |
|---------|-------------|
| `analyze <file>` | Analiza el log y muestra estadísticas completas |
| `tail <file>` | Últimas N líneas con coloring por nivel |
| `stats <file>` | Resumen rápido: tamaño, líneas, rango de fechas |

### Opciones de `analyze`

| Opción | Default | Descripción |
|--------|---------|-------------|
| `--format` | auto | Formato: `nginx`, `nginx-error`, `docker`, `auto` |
| `--top` | 10 | Número de items en top N |
| `--status` | — | Filtrar por código HTTP (ej: `5`, `404`, `2`) |
| `--ip` | — | Filtrar por IP específica |
| `--level` | — | Filtrar por nivel de log (`ERROR`, `WARN`, `INFO`) |
| `--export-json` | — | Exportar estadísticas a archivo JSON |
| `--export-csv` | — | Exportar registros parseados a CSV |

## Formatos de log soportados

| Formato | Detección | Campos analizados |
|---------|-----------|-------------------|
| nginx access (combined) | Auto | IP, path, status, bytes, método |
| nginx error | Auto | Nivel, mensaje, fecha |
| Docker | Auto | Nivel, mensaje, timestamp |

## Variables de entorno

No requiere variables de entorno. Es una herramienta CLI puramente local.

## Tests

```bash
make test
# o directamente:
python -m pytest tests/ -v
```

## Contribuir

PRs bienvenidos. Corre `make test` antes de enviar.

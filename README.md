# log-analyzer-cli

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![CLI](https://img.shields.io/badge/cli-click-green) ![Tests](https://img.shields.io/badge/tests-76%20passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-yellow)

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
python3 analyzer.py analyze /var/log/nginx/access.log

# Analizar solo errores 5xx
python3 analyzer.py analyze access.log --format nginx --status 5xx

# Analizar log Docker filtrando solo errores
python3 analyzer.py analyze app.log --format docker --level ERROR

# Ver últimas 50 líneas con coloring
python3 analyzer.py tail /var/log/nginx/error.log --lines 50

# Stats rápidas de un archivo (JSON)
python3 analyzer.py stats /var/log/nginx/access.log --output json

# Buscar patrón regex en el log
python3 analyzer.py search access.log "ECONNREFUSED" --context 2

# Buscar con salida JSON o solo el conteo
python3 analyzer.py search app.log "ERROR" --output json
python3 analyzer.py search app.log "ERROR" --output count
```

## Comandos disponibles

| Comando | Descripción |
|---------|-------------|
| `analyze <file>` | Analiza el log y muestra estadísticas completas |
| `tail <file>` | Últimas N líneas con coloring por nivel |
| `stats <file>` | Resumen rápido: tamaño, líneas, rango de fechas |
| `search <file> <pattern>` | Busca patrón regex con resaltado y contexto |

### Opciones de `analyze`

| Opción | Default | Descripción |
|--------|---------|-------------|
| `--format` | auto | Formato: `nginx`, `nginx-error`, `docker`, `auto` |
| `--top` | 10 | Número de items en top N |
| `--status` | — | Filtrar por código HTTP: `404`, `5xx`, `4xx`, `5` |
| `--ip` | — | Filtrar por IP específica |
| `--level` | — | Filtrar por nivel de log (`ERROR`, `WARN`, `INFO`) |
| `--since` | — | Solo líneas desde fecha (`YYYY-MM-DD` o `YYYY-MM-DDTHH:MM:SS`) |
| `--until` | — | Solo líneas hasta fecha |
| `--limit` | 0 | Máximo de registros (0 = sin límite) |
| `--export-json` | — | Exportar estadísticas a JSON |
| `--export-csv` | — | Exportar registros parseados a CSV |
| `--export-md` | — | Exportar informe completo a Markdown |

### Opciones de `tail`

| Opción | Default | Descripción |
|--------|---------|-------------|
| `--lines` / `-n` | 20 | Últimas N líneas |
| `--level` | — | Filtrar por nivel |
| `--output` | plain | Salida: `plain`, `table`, `json` |

### Opciones de `search`

| Opción | Default | Descripción |
|--------|---------|-------------|
| `--case-sensitive` | false | Búsqueda sensible a mayúsculas |
| `--context` / `-C` | 0 | Líneas de contexto antes/después del match |
| `--output` | plain | Salida: `plain`, `json`, `count` |
| `--limit` | 0 | Máximo de resultados |

### Opciones de `stats`

| Opción | Default | Descripción |
|--------|---------|-------------|
| `--output` | panel | Salida: `panel`, `json` |

## Ejemplos avanzados

```bash
# Exportar análisis completo a Markdown
python3 analyzer.py analyze access.log --format nginx --export-md report.md

# Solo errores de las últimas 24h con export JSON
python3 analyzer.py analyze app.log --format docker --level ERROR \
  --since 2026-04-10 --export-json errors.json

# Buscar patrón con contexto y límite
python3 analyzer.py search access.log "500" --context 2 --limit 10

# Stats en JSON para scripting
python3 analyzer.py stats access.log --output json | jq .lines
```

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `LOG_ANALYZER_TOP` | 10 | Valor por defecto de `--top` |
| `LOG_ANALYZER_TAIL_LINES` | 20 | Valor por defecto de `--lines` en tail |
| `LOG_ANALYZER_MAX_LINES` | 0 | Límite global de líneas (0 = sin límite) |

## Formatos de log soportados

| Formato | Detección automática | Campos analizados |
|---------|---------------------|-------------------|
| nginx access (combined) | ✅ | IP, path, status, bytes, método, agente |
| nginx error | ✅ | Nivel, mensaje, fecha, PID |
| Docker / app | ✅ | Nivel, mensaje, timestamp |

## Estructura del proyecto

```
log-analyzer-cli/
├── analyzer.py              # Punto de entrada (shim de compatibilidad)
├── log_analyzer/
│   ├── __init__.py
│   ├── config.py            # Constantes, regex, env vars
│   ├── detectors.py         # Detección de formato
│   ├── parsers.py           # Parsers por formato + búsqueda
│   ├── analyzers.py         # Análisis estadístico
│   ├── renderers.py         # Renderizado Rich en terminal
│   ├── exporters.py         # JSON, CSV, Markdown
│   └── cli.py               # Comandos Click
├── tests/
│   └── test_analyzer.py     # 76 tests
├── requirements.txt
└── Makefile
```

## Tests

```bash
make test
# o directamente:
python3 -m pytest tests/ -v
```

## Roadmap

- **Watch mode**: seguir un archivo en tiempo real y filtrar líneas nuevas (`tail -f` con soporte de filtros)
- **Geo-IP**: resolución de IPs a países en reportes de nginx access
- **Formato syslog**: soporte para `/var/log/syslog` y journald
- **Integración ELK**: exportar análisis en formato compatible con Elasticsearch
- **Dashboard HTML**: generar HTML interactivo con Chart.js desde el análisis

## Contribuir

PRs bienvenidos. Corre `make test` antes de enviar.

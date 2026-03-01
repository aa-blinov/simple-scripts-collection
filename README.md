# Simple Scripts Collection

52 single-file Python utilities for everyday tasks. **No external dependencies** — Python 3.10+ standard library only.

```sh
python <script>.py --help
```

## Table of Contents

- [Files & Filesystem](#files--filesystem)
- [Text & Data](#text--data)
- [Network & Web](#network--web)
- [Encoding & Security](#encoding--security)
- [System & Process](#system--process)
- [Development](#development)
- [Utilities & Conversion](#utilities--conversion)

---

## Files & Filesystem

| Script | Description | Example |
|--------|-------------|---------|
| [simple-file-search.py](simple-file-search.py) | Recursive file search by name/glob pattern | `python simple-file-search.py "*.log" /var/` |
| [simple-file-server.py](simple-file-server.py) | Serve the current directory over HTTP | `python simple-file-server.py -p 8080` |
| [simple-duplicate-finder.py](simple-duplicate-finder.py) | Find duplicate files by SHA-256 hash | `python simple-duplicate-finder.py ~/Downloads --delete` |
| [simple-rename-batch.py](simple-rename-batch.py) | Regex batch rename files (dry-run by default) | `python simple-rename-batch.py "IMG_(\d+)" "photo_\1" --apply` |
| [simple-dir-size.py](simple-dir-size.py) | Directory tree with cumulative sizes | `python simple-dir-size.py . -d 2 -s` |
| [simple-file-watcher.py](simple-file-watcher.py) | Poll a directory for create/modify/delete events | `python simple-file-watcher.py src/` |
| [simple-zip.py](simple-zip.py) | Create, extract, and list ZIP archives | `python simple-zip.py create out.zip src/` |
| [simple-find-replace.py](simple-find-replace.py) | Regex find/replace across files by glob (dry-run default) | `python simple-find-replace.py "foo" "bar" "**/*.py" --apply` |
| [simple-watch-run.py](simple-watch-run.py) | Re-run a command whenever watched files change | `python simple-watch-run.py -w "**/*.py" -- python app.py` |
| [simple-backup.py](simple-backup.py) | Incremental directory backup to timestamped ZIP/TAR archives | `python simple-backup.py src/ backups/ --format tar.gz` |

---

## Text & Data

| Script | Description | Example |
|--------|-------------|---------|
| [simple-word-frequency-counter.py](simple-word-frequency-counter.py) | Word frequency analysis in a text file | `python simple-word-frequency-counter.py article.txt -n 20` |
| [simple-json-formatter.py](simple-json-formatter.py) | Format, validate, and compact JSON | `python simple-json-formatter.py data.json --in-place --sort-keys` |
| [simple-csv-viewer.py](simple-csv-viewer.py) | Render CSV as an ASCII table | `python simple-csv-viewer.py data.csv -n 50 -c name,age` |
| [simple-csv-stats.py](simple-csv-stats.py) | Descriptive statistics for a numeric CSV column | `python simple-csv-stats.py data.csv price` |
| [simple-text-diff.py](simple-text-diff.py) | Colored unified diff between two text files | `python simple-text-diff.py old.txt new.txt` |
| [simple-xml.py](simple-xml.py) | Format, validate, and XPath-query XML documents | `python simple-xml.py format data.xml --in-place` |
| [simple-template.py](simple-template.py) | `string.Template` variable substitution from CLI or env file | `python simple-template.py nginx.tmpl -v PORT=8080 HOST=example.com` |
| [simple-log-tail.py](simple-log-tail.py) | `tail -f` with optional grep filter and color highlighting (ERROR/WARN/INFO) | `python simple-log-tail.py app.log -g ERROR` |
| [simple-json-csv.py](simple-json-csv.py) | Convert JSON arrays ↔ CSV in both directions | `python simple-json-csv.py to-csv data.json -o out.csv` |

---

## Network & Web

| Script | Description | Example |
|--------|-------------|---------|
| [simple-ping.py](simple-ping.py) | Ping one or more hosts | `python simple-ping.py google.com 8.8.8.8` |
| [simple-port-scanner.py](simple-port-scanner.py) | Scan open TCP ports on a host | `python simple-port-scanner.py 192.168.1.1 -r 1-1024` |
| [simple-http-status-checker.py](simple-http-status-checker.py) | Concurrent HTTP status checker | `python simple-http-status-checker.py -f urls.txt` |
| [simple-ssl-check.py](simple-ssl-check.py) | SSL certificate expiry checker with warning threshold | `python simple-ssl-check.py github.com google.com -w 30` |
| [simple-dns-lookup.py](simple-dns-lookup.py) | DNS A / AAAA / MX / PTR lookup | `python simple-dns-lookup.py github.com --type MX` |
| [simple-network-info.py](simple-network-info.py) | Local network interfaces, IPs, and MAC addresses | `python simple-network-info.py --all` |
| [simple-mock-api.py](simple-mock-api.py) | HTTP mock API server driven by a JSON config file | `python simple-mock-api.py routes.json -p 8000` |
| [simple-http-request.py](simple-http-request.py) | curl-like HTTP client: GET/POST/PUT/DELETE, JSON body, headers, timing, and auto-redirect following | `python simple-http-request.py https://api/endpoint -X POST -j @body.json -v` |

**mock-api config format:**
```json
{
  "routes": [
    {"method": "GET",  "path": "/health", "status": 200, "body": {"ok": true}},
    {"method": "POST", "path": "/users",  "status": 201, "body": {"id": 1}, "delay": 0.3}
  ]
}
```

---

## Encoding & Security

| Script | Description | Example |
|--------|-------------|---------|
| [simple-password-generator.py](simple-password-generator.py) | Random password generator | `python simple-password-generator.py -l 20 -n 5` |
| [simple-base64.py](simple-base64.py) | Base64 encode / decode (standard and URL-safe) | `python simple-base64.py encode "hello world"` |
| [simple-hash.py](simple-hash.py) | Hash a file or string (md5 / sha1 / sha256 / …) | `python simple-hash.py file.zip --all` |
| [simple-encode.py](simple-encode.py) | Hex, HTML entity, ROT13, and binary encoding | `python simple-encode.py hex "Hello"` |
| [simple-jwt-decode.py](simple-jwt-decode.py) | Decode and inspect a JWT token (no verification) | `python simple-jwt-decode.py <token>` |

---

## System & Process

| Script | Description | Example |
|--------|-------------|---------|
| [simple-sysinfo.py](simple-sysinfo.py) | CPU, RAM, all disks, GPU info, and CPU temperature | `python simple-sysinfo.py` |
| [simple-process-list.py](simple-process-list.py) | List processes or kill by name/PID (shows CPU% and MEM% on Unix) | `python simple-process-list.py list --top 10` |
| [simple-timer.py](simple-timer.py) | Countdown timer with optional Pomodoro mode and musical alert beep | `python simple-timer.py 25m --pomodoro` |
| [simple-epoch.py](simple-epoch.py) | Convert Unix timestamps to/from human datetime | `python simple-epoch.py -z +03:00` |
| [simple-benchmark.py](simple-benchmark.py) | `timeit` expression timing and `cProfile` script profiling | `python simple-benchmark.py time "sorted(range(1000))" -n 50000` |

---

## Development

| Script | Description | Example |
|--------|-------------|---------|
| [simple-todo.py](simple-todo.py) | Persistent CLI todo list with priorities (high/normal/low) and visual emojis | `python simple-todo.py add "Fix that bug" -p high` |
| [simple-calculator.py](simple-calculator.py) | Safe arithmetic expression evaluator | `python simple-calculator.py "2 ** 10 + 1"` |
| [simple-regex-tester.py](simple-regex-tester.py) | Test and highlight regex matches; supports substitution | `python simple-regex-tester.py "(\d{4})-(\d{2})" "today: 2026-03"` |
| [simple-sqlite.py](simple-sqlite.py) | SQLite browser: query, import/export CSV, show schema | `python simple-sqlite.py data.db query "SELECT * FROM users"` |
| [simple-dotenv-run.py](simple-dotenv-run.py) | Run any command with variables injected from a `.env` file | `python simple-dotenv-run.py .env -- python app.py` |
| [simple-clipboard.py](simple-clipboard.py) | Read from or write to the system clipboard | `echo hello \| python simple-clipboard.py` |

**sqlite subcommands:** `query (q)` · `tables (t)` · `schema (s)` · `import-csv` · `export-csv`

| [simple-git-log.py](simple-git-log.py) | Pretty git log with stats and author/date filtering | `python simple-git-log.py -n 20 --stat --all` |
| [simple-parallel-run.py](simple-parallel-run.py) | Run N commands in parallel with graceful Ctrl+C termination and labeled output | `python simple-parallel-run.py "npm build" "pytest" --names build test` |
| [simple-cron.py](simple-cron.py) | Run a command on a cron schedule (`* * * * *` format) | `python simple-cron.py "*/5 * * * *" -- python sync.py` |
| [simple-notify.py](simple-notify.py) | Desktop notification from CLI (Windows/macOS/Linux) | `python long_task.py ; python simple-notify.py "Done" -t "Build"` |

---

## Utilities & Conversion

| Script | Description | Example |
|--------|-------------|---------|
| [simple-uuid.py](simple-uuid.py) | Generate UUIDs (v1 / v4 / v5) | `python simple-uuid.py -n 5` |
| [simple-url-parse.py](simple-url-parse.py) | Parse, encode, decode, and build URLs | `python simple-url-parse.py parse "https://example.com/path?q=1"` |
| [simple-ip-calc.py](simple-ip-calc.py) | IP address and subnet calculator | `python simple-ip-calc.py info 192.168.1.0/24` |
| [simple-color.py](simple-color.py) | HEX ↔ RGB ↔ HSL color converter with terminal preview | `python simple-color.py "#ff6600"` |
| [simple-env-diff.py](simple-env-diff.py) | Diff two `.env` files: missing, extra, and changed keys | `python simple-env-diff.py .env.example .env` |

---

## Requirements

- Python 3.10+
- No external packages — standard library only

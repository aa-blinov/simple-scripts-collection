# Simple scripts collection

Fifty-two single-file Python utilities for everyday command-line work: finding
files, reading logs, converting formats, checking certificates, watching
directories, inspecting processes. Every script runs on its own, with nothing
installed but Python 3.10 or newer.

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

---

## Quick start

```bash
git clone https://github.com/aa-blinov/simple-scripts-collection.git
cd simple-scripts-collection
python3 simple-uuid.py -n 3
```

Python 3.10 or newer is the only requirement. There is no install step, no
requirements file and nothing to build: each script is a complete program in
one file.

Every script takes `--help` and prints the options it accepts.

```bash
python3 simple-calculator.py --help
```

A script that reads text takes a path, and falls back to standard input when
the path is omitted, so it drops into a pipeline:

```bash
echo hello | python3 simple-base64.py encode
```

## What it does

- **One file per task.** Each script does one thing, and nothing in the
  repository imports anything else in the repository. A script can be copied
  out on its own.
- **The standard library is the whole dependency list.** No third-party
  packages, so there is no install step and no virtual environment. A few
  scripts call `git`, `nslookup`, `ping` or `xclip` when they need them.
- **Every script documents itself.** The command line is built by argparse, so
  `--help` prints the options the script accepts.
- **Data comes from a file or from standard input.** A script that reads text
  takes a path, and falls back to standard input when the path is omitted. A
  script that writes takes an output path when it has one, and writes to
  standard output otherwise.
- **Nothing is changed until it is asked for.** The three scripts that write to
  files print what they would do and stop. `--apply` turns on the batch
  rename and the find-and-replace, `--delete` turns on the duplicate removal.

### Files and filesystem

| Script | Description | Example |
| --- | --- | --- |
| [simple-file-search.py](simple-file-search.py) | Simple file search utility with tree-like output, filtering by extension. | `python3 simple-file-search.py /var/log -n app -e log` |
| [simple-file-server.py](simple-file-server.py) | A simple HTTP file server that serves files from a specified directory. | `python3 simple-file-server.py -p 8080` |
| [simple-duplicate-finder.py](simple-duplicate-finder.py) | Find duplicate files in a directory by content hash. | `python3 simple-duplicate-finder.py ~/Downloads` |
| [simple-rename-batch.py](simple-rename-batch.py) | Batch rename files in a directory using regex patterns. | `python3 simple-rename-batch.py . "IMG_(\d+)" "photo_\1"` |
| [simple-dir-size.py](simple-dir-size.py) | Display a directory tree with file and folder sizes. | `python3 simple-dir-size.py . -d 2 -s` |
| [simple-file-watcher.py](simple-file-watcher.py) | Watch a directory for file system changes using polling. | `python3 simple-file-watcher.py src/` |
| [simple-zip.py](simple-zip.py) | Create, extract, and inspect ZIP archives. | `python3 simple-zip.py create out.zip src/` |
| [simple-find-replace.py](simple-find-replace.py) | Find and replace text across multiple files using regex or plain strings. | `python3 simple-find-replace.py "foo" "bar" "**/*.py"` |
| [simple-watch-run.py](simple-watch-run.py) | Re-run a command whenever watched files change. | `python3 simple-watch-run.py -w "src/**/*.py" -- python app.py` |
| [simple-backup.py](simple-backup.py) | Incremental directory backup to timestamped ZIP or TAR archives. | `python3 simple-backup.py src/ backups/ --format tar.gz` |

### Text and data

| Script | Description | Example |
| --- | --- | --- |
| [simple-word-frequency-counter.py](simple-word-frequency-counter.py) | Counts the frequency of words in text files and directories. | `python3 simple-word-frequency-counter.py -f article.txt -n 20` |
| [simple-json-formatter.py](simple-json-formatter.py) | Format, validate, and pretty-print JSON from a file or stdin. | `python3 simple-json-formatter.py data.json --in-place --sort-keys` |
| [simple-csv-viewer.py](simple-csv-viewer.py) | Display CSV files as a formatted table in the terminal. | `python3 simple-csv-viewer.py data.csv -n 50 -c name age` |
| [simple-csv-stats.py](simple-csv-stats.py) | Compute descriptive statistics for numeric columns in a CSV file. | `python3 simple-csv-stats.py data.csv -c price` |
| [simple-text-diff.py](simple-text-diff.py) | Show a colored diff between two text files. | `python3 simple-text-diff.py old.txt new.txt` |
| [simple-xml.py](simple-xml.py) | Format, validate, and XPath-query XML documents. | `python3 simple-xml.py format data.xml --in-place` |
| [simple-template.py](simple-template.py) | Fill a template file with values from arguments, environment, or a .env file. | `python3 simple-template.py nginx.tmpl -v PORT=8080 HOST=example.com` |
| [simple-log-tail.py](simple-log-tail.py) | Follow the tail of a log file in real time (like tail -f). | `python3 simple-log-tail.py app.log -g ERROR` |
| [simple-json-csv.py](simple-json-csv.py) | Convert JSON arrays to CSV and CSV to JSON arrays. | `python3 simple-json-csv.py to-csv data.json -o out.csv` |

### Network and web

| Script | Description | Example |
| --- | --- | --- |
| [simple-ping.py](simple-ping.py) | Simple TCP Ping Utility. | `python3 simple-ping.py google.com -p 443 -c 4` |
| [simple-port-scanner.py](simple-port-scanner.py) | Advanced port scanner for network discovery and service identification. | `python3 simple-port-scanner.py 192.168.1.1 -p 1-1024` |
| [simple-http-status-checker.py](simple-http-status-checker.py) | Check HTTP status codes for a list of URLs concurrently. | `python3 simple-http-status-checker.py -f urls.txt` |
| [simple-ssl-check.py](simple-ssl-check.py) | Check SSL certificate expiry for one or more domains. | `python3 simple-ssl-check.py github.com google.com -w 30` |
| [simple-dns-lookup.py](simple-dns-lookup.py) | Perform DNS lookups for A, AAAA, MX, PTR, NS, TXT, and CNAME records. | `python3 simple-dns-lookup.py github.com -t MX` |
| [simple-network-info.py](simple-network-info.py) | Show local network interfaces, IP addresses, and MAC addresses. | `python3 simple-network-info.py --all` |
| [simple-mock-api.py](simple-mock-api.py) | Lightweight HTTP mock API server driven by a JSON config file. | `python3 simple-mock-api.py routes.json -p 8000` |
| [simple-http-request.py](simple-http-request.py) | curl-like HTTP client: GET/POST/PUT/DELETE with headers, JSON body, and timing. | `python3 simple-http-request.py https://example.com -X POST -j @body.json -v` |

The mock API is driven by a JSON file:

```json
{
  "routes": [
    {"method": "GET",  "path": "/health", "status": 200, "body": {"ok": true}},
    {"method": "POST", "path": "/users",  "status": 201, "body": {"id": 1}, "delay": 0.3}
  ]
}
```

### Encoding and security

| Script | Description | Example |
| --- | --- | --- |
| [simple-password-generator.py](simple-password-generator.py) | Secure Random Password Generator. | `python3 simple-password-generator.py -l 20` |
| [simple-base64.py](simple-base64.py) | Encode and decode Base64 from strings, files, or stdin. | `python3 simple-base64.py encode "hello world"` |
| [simple-hash.py](simple-hash.py) | Compute cryptographic hashes for strings, files, or stdin. | `python3 simple-hash.py file.zip --all` |
| [simple-encode.py](simple-encode.py) | Encode and decode strings: hex, HTML entities, URL, ROT13, and binary. | `python3 simple-encode.py hex "Hello"` |
| [simple-jwt-decode.py](simple-jwt-decode.py) | Decode and inspect a JWT token without verifying the signature. | `python3 simple-jwt-decode.py "$TOKEN"` |

### System and process

| Script | Description | Example |
| --- | --- | --- |
| [simple-sysinfo.py](simple-sysinfo.py) | Display system information: OS, CPU, memory, disk, and GPU usage. | `python3 simple-sysinfo.py` |
| [simple-process-list.py](simple-process-list.py) | List, search, and kill processes by name or PID. | `python3 simple-process-list.py list -n 10` |
| [simple-timer.py](simple-timer.py) | CLI countdown timer with optional Pomodoro mode. | `python3 simple-timer.py 25m --pomodoro` |
| [simple-epoch.py](simple-epoch.py) | Convert between Unix timestamps and human-readable dates. | `python3 simple-epoch.py -z +03:00` |
| [simple-benchmark.py](simple-benchmark.py) | Benchmark Python expressions and scripts with timeit and cProfile. | `python3 simple-benchmark.py time "sorted(range(1000))" -n 50000` |

### Development

| Script | Description | Example |
| --- | --- | --- |
| [simple-todo.py](simple-todo.py) | Simple CLI to-do list stored as a JSON file in the home directory. | `python3 simple-todo.py add "Fix that bug" -p high` |
| [simple-calculator.py](simple-calculator.py) | Restricted eval Calculator. | `python3 simple-calculator.py "2 ** 10 + 1"` |
| [simple-regex-tester.py](simple-regex-tester.py) | Test regular expressions interactively against text input. | `python3 simple-regex-tester.py "(\d{4})-(\d{2})" "today: 2026-03"` |
| [simple-sqlite.py](simple-sqlite.py) | SQLite database browser and query runner. | `python3 simple-sqlite.py data.db query "SELECT * FROM users"` |
| [simple-dotenv-run.py](simple-dotenv-run.py) | Run a command with environment variables loaded from a .env file. | `python3 simple-dotenv-run.py .env -- python app.py` |
| [simple-clipboard.py](simple-clipboard.py) | Read from or write to the system clipboard. | `echo hello \| python3 simple-clipboard.py` |
| [simple-git-log.py](simple-git-log.py) | Pretty-print git log with branch graph, stats, and author/date filtering. | `python3 simple-git-log.py -n 20 --stat --all` |
| [simple-parallel-run.py](simple-parallel-run.py) | Run multiple commands in parallel and stream their output. | `python3 simple-parallel-run.py "npm run build" "pytest" --names build test` |
| [simple-cron.py](simple-cron.py) | Run a command on a cron-like schedule (minute granularity). | `python3 simple-cron.py "*/5 * * * *" -- python sync.py` |
| [simple-notify.py](simple-notify.py) | Send a desktop notification from the command line. | `python3 simple-notify.py "Done" -t "Build"` |

The SQLite browser takes the database path first and then one of `query`,
`tables`, `schema`, `import-csv` or `export-csv`.

### Utilities and conversion

| Script | Description | Example |
| --- | --- | --- |
| [simple-uuid.py](simple-uuid.py) | Generate UUIDs from the command line. | `python3 simple-uuid.py -n 5` |
| [simple-url-parse.py](simple-url-parse.py) | Parse, encode, and decode URLs and query strings. | `python3 simple-url-parse.py parse "https://example.com/path?q=1"` |
| [simple-ip-calc.py](simple-ip-calc.py) | IPv4/IPv6 subnet calculator using the standard ipaddress module. | `python3 simple-ip-calc.py info 192.168.1.0/24` |
| [simple-color.py](simple-color.py) | Convert colors between HEX, RGB, and HSL with terminal preview. | `python3 simple-color.py "#ff6600"` |
| [simple-env-diff.py](simple-env-diff.py) | Compare two .env files and report missing, extra, and changed keys. | `python3 simple-env-diff.py .env.example .env` |

## How it works

Every script is built the same way: an argparse parser describing the command
line, the work, and a return code. All but one open with a module docstring
naming the task. There is no package, no shared module and no entry point, so
the repository root is the whole program.

```
python3 simple-<task>.py [options] [arguments]
```

- The result goes to standard output. Diagnostics go to standard error, and
  the exit code is 0 unless the script failed.
- A script that reads text takes a file path, or standard input when the path
  is omitted. A script that writes takes an output path when it has one, and
  writes to standard output otherwise.
- Six scripts dispatch on their sub-command with a `match` statement:
  `simple-encode.py`, `simple-ip-calc.py`, `simple-process-list.py`,
  `simple-todo.py`, `simple-url-parse.py` and `simple-zip.py`. They need
  Python 3.10, and they fail to parse on 3.9.
- Nine scripts print ANSI colour. `simple-color.py` uses it to show the
  colour it converted; the other eight take `--no-color`, and three of those,
  `simple-git-log.py`, `simple-log-tail.py` and `simple-parallel-run.py`,
  switch it off on their own when standard output is not a terminal.
- A script is meant to be read. Three run past 150 lines:
  `simple-port-scanner.py` at 783, `simple-word-frequency-counter.py` at 410
  and `simple-sysinfo.py` at 310. The other 49 are under 180, and the median
  is 85.

Eight of the scripts reach outside Python for the job in hand: `git` for
`simple-git-log.py`, `nslookup` for the mail exchanger records of
`simple-dns-lookup.py`, `ping` for the host check in
`simple-port-scanner.py`, `notify-send` or `zenity` for `simple-notify.py`,
`xclip`, `xsel` or `wl-clipboard` for `simple-clipboard.py` on Linux, `ip`
or `ipconfig` for `simple-network-info.py`, `ps` or `tasklist` for
`simple-process-list.py`, and `nvidia-smi` for the GPU line in
`simple-sysinfo.py`.

## Configuration

There is no configuration file and no environment variable to set. Every
option is a command-line flag, and the defaults worth knowing are below.

| Script | Option | Default |
| --- | --- | --- |
| `simple-backup.py` | `--format` | `zip` |
| `simple-backup.py` | `--exclude` | `*.pyc`, `__pycache__`, `.git`, `node_modules`, `.DS_Store` |
| `simple-benchmark.py` | `--number`, `--repeat` | 100000 loops per repeat, 5 repeats |
| `simple-csv-stats.py`, `simple-csv-viewer.py` | `--delimiter`, `--encoding` | `,`, `utf-8` |
| `simple-dotenv-run.py` | `--override` | off: a variable already in the environment wins |
| `simple-epoch.py` | `--timezone` | `+00:00` |
| `simple-file-server.py` | `--bind`, `--port`, `--directory` | `0.0.0.0`, `8001`, `files` |
| `simple-file-watcher.py`, `simple-watch-run.py` | `--interval` | 1.0 s |
| `simple-find-replace.py` | glob argument | `**/*` |
| `simple-git-log.py` | `-n` | 20 commits |
| `simple-hash.py` | `--algorithm` | `sha256` |
| `simple-http-request.py` | `--method` | `GET`, and up to 10 redirects are followed |
| `simple-http-status-checker.py` | `--timeout`, `--workers` | 10 s, 10 workers |
| `simple-json-formatter.py` | `--indent` | 2 spaces |
| `simple-log-tail.py` | `--lines`, `--interval` | 10 lines, 0.2 s |
| `simple-mock-api.py` | config, `--port`, `--host` | `mock-api.json`, `8000`, `127.0.0.1` |
| `simple-notify.py` | `--title`, `--duration` | `Notification`, 5 s |
| `simple-parallel-run.py` | `--names` | `cmd-0`, `cmd-1` |
| `simple-password-generator.py` | `--length` | 16 characters, 8 is the minimum |
| `simple-ping.py` | `--port`, `--count`, `--timeout` | 80, 4 attempts, 1 s |
| `simple-port-scanner.py` | `--protocol`, `--timeout` | `tcp`, 1.0 s |
| `simple-ssl-check.py` | `--port`, `--timeout`, `--warn` | 443, 10 s, 30 days |
| `simple-text-diff.py` | `--mode`, `--context` | `unified`, 3 lines |
| `simple-timer.py` | `--pomodoro` | off; the cycle is 25 min of work and 5 min of break, four times, then 15 min |
| `simple-todo.py` | `--priority` | `normal`; the list lives in `~/.simple-todo.json` |
| `simple-uuid.py` | `--version`, `--count` | 4, 1 |
| `simple-word-frequency-counter.py` | `--top_n` | 10 |
| `simple-xml.py` | `--indent` | 2 spaces |

Two things live outside the working directory: the to-do list in
`~/.simple-todo.json`, and the archives `simple-backup.py` writes into the
destination directory you name.

## Development

```bash
python3 simple-uuid.py --help     # what a script accepts
python3 simple-uuid.py -n 3       # run one
python3 -m compileall -q .        # byte-compile every script
```

`python3 -m compileall -q .` is the only check the collection has. There is no
test suite, no CI and no build step: the scripts are the deliverable, so a
change is checked by running the script and reading what it prints. The
command leaves `__pycache__` directories behind.

| Path | What it is |
| --- | --- |
| `simple-<task>.py` | One script per task. 52 files, 5861 lines. |
| `README.md` | The index of the scripts, one table per category. |

Adding a script means adding one file and one table row. The description in
the table is the script's own module docstring, so the two change together.
The rest of the collection agrees on the shape of a script: a one-line module
docstring, an argparse parser, output on standard output, errors on standard
error, and standard input as the fallback when a text input is given by no
path.

## License

MIT, © Alexander Blinov. See [LICENSE](LICENSE).

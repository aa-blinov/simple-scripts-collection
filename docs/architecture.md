# Architecture

How `simple-scripts-collection` is put together.

## The shape

One flat directory and 52 complete programs. There is no package, no shared
module, no entry point and no build, so the repository root is the whole
program and every script is a world of its own.

```
python3 simple-<task>.py [options] [arguments]
  |
  |  argparse builds the parser and prints --help
  v
the work
  |
  +--> the result      -> standard output
  +--> the complaint   -> standard error
  |
  v
exit code 0, unless the script failed
```

A script that reads text takes a file path, and falls back to standard input
when the path is omitted. A script that writes takes an output path when it
has one, and writes to standard output otherwise. That is what lets the
collection drop into a pipe.

| Module | What it holds |
| --- | --- |
| `simple-file-search.py` | The file search, with a tree and a type filter. |
| `simple-file-server.py` | The HTTP file server. |
| `simple-duplicate-finder.py` | The duplicate finder, by content hash. |
| `simple-rename-batch.py` | The batch rename, by regular expression. |
| `simple-dir-size.py` | The directory tree with sizes. |
| `simple-file-watcher.py` | The polling watcher. |
| `simple-zip.py` | The archive tool: create, extract, inspect. |
| `simple-find-replace.py` | The find and replace across files. |
| `simple-watch-run.py` | The command runner that watches files. |
| `simple-backup.py` | The incremental backup, to ZIP or TAR. |
| `simple-word-frequency-counter.py` | The word frequency count. |
| `simple-json-formatter.py` | The JSON formatter and validator. |
| `simple-csv-viewer.py` | The CSV table. |
| `simple-csv-stats.py` | The descriptive statistics for numeric columns. |
| `simple-text-diff.py` | The coloured diff. |
| `simple-xml.py` | The XML formatter, validator and XPath query. |
| `simple-template.py` | The template filler. |
| `simple-log-tail.py` | The log follower. |
| `simple-json-csv.py` | The JSON and CSV converter. |
| `simple-ping.py` | The TCP ping. |
| `simple-port-scanner.py` | The port scanner. The longest script at 783 lines. |
| `simple-http-status-checker.py` | The concurrent status checker. |
| `simple-ssl-check.py` | The certificate expiry check. |
| `simple-dns-lookup.py` | The DNS lookups. |
| `simple-network-info.py` | The interfaces, addresses and MAC addresses. |
| `simple-mock-api.py` | The mock HTTP server. |
| `simple-http-request.py` | The HTTP client. |
| `simple-password-generator.py` | The password generator. |
| `simple-base64.py` | The Base64 encoder and decoder. |
| `simple-hash.py` | The hash calculator. |
| `simple-encode.py` | The encoder: hex, HTML, URL, ROT13, binary. |
| `simple-jwt-decode.py` | The JWT decoder. |
| `simple-sysinfo.py` | The system information. |
| `simple-process-list.py` | The process list, search and kill. |
| `simple-timer.py` | The countdown timer, with a Pomodoro mode. |
| `simple-epoch.py` | The timestamp converter. |
| `simple-benchmark.py` | The expression and script benchmark. |
| `simple-todo.py` | The to-do list. |
| `simple-calculator.py` | The expression calculator. |
| `simple-regex-tester.py` | The regular expression tester. |
| `simple-sqlite.py` | The database browser and query runner. |
| `simple-dotenv-run.py` | The runner with a `.env` file loaded. |
| `simple-clipboard.py` | The clipboard reader and writer. |
| `simple-git-log.py` | The git log, with a branch graph. |
| `simple-parallel-run.py` | The parallel command runner. |
| `simple-cron.py` | The cron-like scheduler. |
| `simple-notify.py` | The desktop notification. |
| `simple-uuid.py` | The UUID generator. |
| `simple-url-parse.py` | The URL parser and encoder. |
| `simple-ip-calc.py` | The subnet calculator. |
| `simple-color.py` | The colour converter. |
| `simple-env-diff.py` | The `.env` file comparison. |
| `README.md` | The index. One table per category, one row per script. |

The scripts total 5861 lines. The median script is 85 lines, three run past
150 (`simple-port-scanner.py` at 783, `simple-word-frequency-counter.py` at
410 and `simple-sysinfo.py` at 310), and the other 49 are under 180.

`src/`, `scripts/` and `tests/` exist as empty directories with a
`.gitkeep` in each.

## The data flow

Every script has the same flow, and the variations are all at the ends of
it.

```
argv
  |
  |  argparse: parse, validate, --help
  v
the work
  |  the input: a path, or standard input when no path was given
  |  the output: standard output, or a file when one was named
  v
the verdict
  |  exit code 0, or non-zero when the script failed
  v
the complaint, on standard error
```

Eleven scripts read standard input, and for those the path is an optional
argument: `simple-base64.py`, `simple-clipboard.py`, `simple-csv-stats.py`,
`simple-csv-viewer.py`, `simple-encode.py`, `simple-hash.py`,
`simple-json-csv.py`, `simple-json-formatter.py`, `simple-jwt-decode.py`,
`simple-regex-tester.py` and `simple-template.py`. The rest that read text
follow the same rule.

Six scripts dispatch on their sub-command with a `match` statement:
`simple-encode.py`, `simple-ip-calc.py`, `simple-process-list.py`,
`simple-todo.py`, `simple-url-parse.py` and `simple-zip.py`. They need
Python 3.10, and they raise `SyntaxError` on 3.9 before argparse ever runs.

## Decisions worth knowing about

### The directory is flat on purpose

There is no shared module, and a helper a script needs sits in the same file
as the script. A `common.py` would tie every script to the directory layout
and would stop a script from being copied out of the repository on its own,
which is the thing the collection is for.

### The module docstring is the README row

The description in the README table is the first line of the script's own
docstring, so the two change together.
`simple-word-frequency-counter.py` is the exception: it has no module
docstring, and its row carries the argparse description instead.

### A destructive action is opt-in

Three scripts write to files: `simple-rename-batch.py`,
`simple-find-replace.py` and `simple-duplicate-finder.py`. Each prints what
it would do and stops. `--apply` turns on the first two, and `--delete` turns
on the third. Making the destructive path the default is a change in
behaviour, and not a fix.

### Colour is decided two ways

`simple-git-log.py`, `simple-log-tail.py` and `simple-parallel-run.py` switch
the colour off when standard output is not a terminal. The other scripts
that print ANSI codes need `--no-color`. `simple-color.py` prints colour on
purpose, because the colour is the answer.

### Eight scripts shell out for the job in hand

`git` for `simple-git-log.py`, `nslookup` for the mail exchanger records of
`simple-dns-lookup.py`, `ping` for the host check in
`simple-port-scanner.py`, `notify-send` or `zenity` for `simple-notify.py`,
`xclip`, `xsel` or `wl-clipboard` for `simple-clipboard.py` on Linux, `ip`
or `ipconfig` for `simple-network-info.py`, `ps` or `tasklist` for
`simple-process-list.py`, and `nvidia-smi` for the GPU line in
`simple-sysinfo.py`.

Four more scripts call `subprocess` as well, but to run the command the
user asked for: `simple-dotenv-run.py`, `simple-cron.py`,
`simple-parallel-run.py` and `simple-watch-run.py`.

### Two scripts print an emoji

`simple-file-search.py` marks the entries of its tree, and `simple-todo.py`
marks the priority of a task. The house style bans emoji in every file, and
the house checker reports both as hard failures.

### Two docstrings promise more than the code does

`simple-dns-lookup.py` says it looks up NS, TXT and CNAME records; its
`--type` accepts only A, AAAA, MX, PTR and ALL, and only the MX lookup needs
the external `nslookup`. `simple-password-generator.py` says it guarantees a
mix of character types; it picks from the union of all of them, and can
return a password with no digit in it.

### The backup decides what is new by modification time

`simple-backup.py` parses the previous archive's timestamp out of its file
name and includes a file when its mtime is newer than that stamp. A file
whose content changed without its mtime moving is skipped.

### The cron uses AND where cron uses OR

`simple-cron.py` compares day-of-month and day-of-week with AND. A real cron
runs a job when either field matches, so `0 1 * * 1` here means the first of
the month on a Monday.

## Boundaries

- **No script may import another script.** There is no shared module and no
  package, so every helper lives in the file that needs it. A script has to
  work when it is the only file in a directory.
- **No script may import a third-party package.** The collection has no
  requirements file, and adding one would put an install step in front of
  every use.
- **A new script is one file and one README row.** The row's description is
  the script's module docstring, and the two change together.
- **A new script takes `--help`.** argparse builds the parser, and the
  description carries the usage.
- **A script that reads text takes a path and falls back to standard input.**
- **A script that writes prints its plan and stops, unless a flag says
  otherwise.**
- **The result goes to standard output and the complaint to standard error.**
- **The output stays inside ASCII.** Two scripts break this today; anything
  added from here on does not.

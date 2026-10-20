# AGENTS.md — agent context for `simple-scripts-collection`

A directory of 52 single-file Python scripts for everyday command-line work.
There is no package, no build and no test suite: a script is a whole program
that runs from the standard library, and the repository is one flat directory
of them.

This file is what you need to work on the collection without reading all 52
scripts.

## Run / build / test

```bash
python3 simple-uuid.py --help   # what a script accepts
python3 simple-uuid.py -n 3     # run one
python3 -m compileall -q .      # byte-compile every script: the only check there is
```

Python 3.10 or newer. There is no install step, no requirements file and no
test runner. `python3 -m compileall -q .` is the closest thing to a build, and
it leaves `__pycache__` directories behind.

## Where things live

| Path | What it is |
| --- | --- |
| `simple-<task>.py` | One script per task. 52 files, 5861 lines. |
| `README.md` | The index. One table per category, one row per script. |

There is no `src/`, no `tests/` and no shared module. Every helper a script
needs sits in the same file as the script.

## Traps

- **Six scripts need Python 3.10.** `simple-encode.py`, `simple-ip-calc.py`,
  `simple-process-list.py`, `simple-todo.py`, `simple-url-parse.py` and
  `simple-zip.py` dispatch on their sub-command with a `match` statement. On
  3.9 they raise `SyntaxError` before argparse runs, which reads as a broken
  script rather than an old interpreter.
- **The README row and the module docstring are the same text.** The
  description in the table is the first line of the script's docstring, so the
  two change together. `simple-word-frequency-counter.py` is the exception: it
  has no module docstring, and its row carries the argparse description
  instead.
- **Two docstrings promise more than the code does.**
  `simple-dns-lookup.py` says it looks up NS, TXT and CNAME records; its
  `--type` accepts only A, AAAA, MX, PTR and ALL, and only the MX lookup needs
  the external `nslookup` binary. `simple-password-generator.py` says it
  guarantees a mix of character types; it picks from the union of all of them
  and can return a password with no digit in it.
- **The three scripts that write to files are dry runs until a flag is
  passed.** `--apply` for `simple-rename-batch.py` and
  `simple-find-replace.py`, `--delete` for `simple-duplicate-finder.py`.
  Making the destructive path the default is a change in behaviour, not a
  fix.
- **`simple-duplicate-finder.py --delete` keeps the first path in `rglob`
  order.** That order comes from the filesystem, not from the file name or
  the modification time, so the survivor is not predictable from the listing.
- **`simple-backup.py` decides what is new by modification time.** The
  previous archive's timestamp is parsed out of its file name, and a file is
  included when its mtime is newer than that stamp. A file whose content
  changed without its mtime moving is skipped.
- **`simple-backup.py` deletes the archive it just wrote when nothing
  changed.** If no file is newer than the last backup, the new archive is
  removed and the run reports "Nothing changed". Do not point it at a
  destination where the archive itself is the receipt.
- **`simple-cron.py` compares day-of-month and day-of-week with AND.** Real
  cron runs a job when either field matches, so `0 1 * * 1` here means the
  first of the month on a Monday, which is rare.
- **`simple-cron.py --shell` drops everything after the first word.** With
  `--shell` the command becomes `cmd[0]` alone, so `-- python sync.py` runs
  `python` and loses `sync.py`. Without `--shell`, a single quoted string is
  split with `shlex`.
- **`simple-ssl-check.py` has two thresholds.** `--warn` (30 days by default)
  picks the OK or WARN label, while the colour turns yellow at 14 days, which
  is written into the code. A certificate with 20 days left is labelled WARN
  and printed in green.
- **`simple-http-request.py` changes the method when you give it a body.**
  `-j`, `-d` and `-F` all turn a GET into a POST. On a redirect the method is
  reset to GET and the body is dropped, up to ten hops.
- **`simple-mock-api.py` serves one request at a time.** It uses
  `HTTPServer`, not `ThreadingHTTPServer`, so a route with a `delay` blocks
  every other request for the length of the delay.
- **`simple-file-server.py` changes the working directory.** It calls
  `os.chdir(directory)` before serving, so the process is left standing in
  the published directory, and it binds `0.0.0.0` by default.
- **`simple-file-search.py` prints the whole tree whatever `-n` says.** The
  name filter reaches the count at the end and nothing else. The tree shows
  every entry, cut down only by `--extensions` when that is given.
- **`simple-log-tail.py` only ever prints new lines.** It opens the file once
  and seeks to the end, so a file that is rotated or truncated under it is
  not picked up.
- **`simple-file-watcher.py` and `simple-watch-run.py` poll.** The watcher
  compares modification times alone, so a change that leaves the mtime alone
  is invisible; the runner compares the mtime and the size.
- **`simple-todo.py` writes outside the repository.** The list lives in
  `~/.simple-todo.json`, read and written as one JSON document with no lock.
- **Colour is decided two ways.** `simple-git-log.py`,
  `simple-log-tail.py` and `simple-parallel-run.py` switch the colour off
  when standard output is not a terminal. The other scripts that print ANSI
  codes need `--no-color`.
- **`simple-port-scanner.py` scans 58 ports by default, not 1000.** The
  built-in list holds 58 entries, and `--top-ports N` takes the first N
  entries of that list and sorts them, so the flag does not give the N most
  common ports in the world.
- **`simple-port-scanner.py` scans one host at a time.** A single target is
  scanned in the foreground, and only the CIDR path uses the thread pool. A
  host that fails the `ping` check is never scanned at all.
- **`simple-calculator.py` calls `eval` with the builtins removed.** The
  expression is not parsed or validated before it is evaluated.
- **`simple-git-log.py --stat` runs one extra command per commit.** Each
  commit costs a `git diff-tree` call on top of the `git log` call.
- **Two scripts print emoji.** `simple-file-search.py` marks files, folders
  and other entries in its tree, and `simple-todo.py` marks the priority of a
  task. The house style bans emoji in every file, and the house checker
  reports both as hard failures.

## Style / safety rails

- **One file per task, and no shared module.** A helper goes in the same file
  as the script that needs it. A `common.py` would tie every script to the
  directory layout and stop it from being copied out on its own.
- **Standard library only.** No third-party packages, and no install step for
  the person who runs a script. The repository has no requirements file
  because the collection has no dependencies.
- **The module docstring is the description.** The first line names the task,
  for a reader who has not opened the file. It is the text the README table
  shows.
- **Every script takes `--help`.** argparse builds the parser, and the
  description carries the usage. Ten scripts also set an epilog with a worked
  example.
- **A destructive action is opt-in.** The scripts that rename, rewrite or
  delete print what they would do and stop.
- **Standard input is the fallback input.** A script that reads text takes a
  path or falls back to standard input, so it works in a pipeline.
- **Standard output carries the result and standard error carries the
  complaint.** The exit code is 0 unless the script failed.
- **No emoji in any file.** The house style bans them and the house checker
  fails the build when it finds one. Two scripts break the rule today, as
  noted above; anything added from here on stays inside ASCII.

## Where the product truth lives

`PRODUCT.md` holds it. Read it before adding a script, and write the change
there when the collection changes.

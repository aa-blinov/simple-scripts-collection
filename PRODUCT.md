# Product

<!-- impeccable:product-schema 1 -->

## Platform

command line

The collection is 52 Python 3.10 scripts that run on Linux, macOS and Windows.
There is no interface but the terminal, no install step and no runtime
dependency outside the standard library.

Eight scripts call a program outside Python when they need one: `git` for the
log viewer, `nslookup` for the mail exchanger records, `ping` for the host
check in the port scanner, `nvidia-smi` for the GPU line, `ip` or `ipconfig`
for the interface list, `ps` or `tasklist` for the process list, `osascript`
on macOS and `notify-send` or `zenity` on Linux for the desktop notification,
and `xclip`, `xsel` or `wl-clipboard` on Linux for the clipboard.

## Users

The owner of the repository, and anyone who arrives from a search for a
script that does one small thing. The situation: a chore turns up at the
command line, and the choice is between installing a tool for it, writing a
throwaway script, and copying one of these.

There is no second audience the repository can point at. It carries no
description on GitHub, no tags, no releases and no test suite, and one person
subscribes to it.

## Product Purpose

The collection turns one-off command-line chores into a file that can be
copied. A duplicate finder, a certificate expiry check, a log tail, a port
scan, a JSON formatter: each is small enough to read in one sitting and
complete enough to hand a real path.

Success for the user: the script is run straight from the repository or copied
out of it, and it does the job without a setup step. Success for the product:
a task that came up twice ends up as a file in this directory rather than as a
line in somebody's shell history.

## Positioning

The neighbouring tool is the shell pipeline, or the one-line Python written
under pressure. Here there is nothing to import, nothing to install and
nothing to configure. You run the file.

The second difference is the output itself. The scripts print what they
found and stop. There is no interactive mode, no menu, and no state beyond the
two that write files.

The third is what happens at the edges. A script that would change your files
prints the change and does nothing until you ask. A script that cannot do the
job exits with a code that says so, and a script that needs a program that is
missing either names it or degrades to an empty result.

## Operating Context

The scripts are run from a shell, one at a time, usually with a path typed by
hand. The output goes to a terminal, and the tables are sized from their
content rather than from the width of the window, so a wide input produces a
wide table.

Some of them run until they are interrupted: `simple-log-tail.py` follows a
file, `simple-cron.py` runs a command on a schedule, `simple-file-server.py`
and `simple-mock-api.py` stay up. All of them stop on Ctrl+C, and the two
that start a child process, `simple-watch-run.py` and `simple-parallel-run.py`,
terminate it on the way out.

Two things live outside the working directory. The to-do list is in
`~/.simple-todo.json`, and `simple-backup.py` writes archives into the
destination directory you name. Everything else reads and writes where you
point it.

## Capabilities and Constraints

Confirmed by the code:

- 52 scripts, 5861 lines, and no third-party import anywhere in the
  repository.
- Python 3.10 or newer. Six scripts dispatch on their sub-command with
  `match` and fail to parse on 3.9.
- Every script builds its command line with argparse and answers `--help`.
- Every script that reads text takes a file path or falls back to standard
  input.
- The scripts that modify files are dry runs until a flag is passed:
  `--apply` for `simple-rename-batch.py` and `simple-find-replace.py`,
  `--delete` for `simple-duplicate-finder.py`.
- `simple-file-server.py` binds `0.0.0.0` on port 8001 and publishes a
  directory named `files` by default. `simple-mock-api.py` binds `127.0.0.1`
  on port 8000 and serves one request at a time.
- `simple-port-scanner.py` scans TCP over a built-in list of 58 ports by
  default, and uses `ping` to decide whether a host is up.
- `simple-calculator.py` evaluates the expression with `eval` and the
  builtins removed.
- `simple-jwt-decode.py` decodes a token and never verifies the signature.
  It says so in the output.
- `simple-notify.py` prints the message when neither `notify-send` nor
  `zenity` is installed.
- Nine scripts print ANSI colour. Eight of them take `--no-color`, and three
  of those switch the colour off on their own when standard output is not a
  terminal.
- Two scripts print emoji, which the house style bans.

Deliberately not true, and worth knowing before a change:

- There is no test suite, no CI and no build.
- There is no package, no console entry point and no shared module. Nothing
  in the collection is importable as a package.
- There is no stated support policy for any platform. Six scripts branch on
  the platform: five call `platform.system()`, and `simple-port-scanner.py`
  checks `sys.platform`. The rest do not.
- `simple-dns-lookup.py` does not look up NS, TXT or CNAME records, although
  its docstring says it does.
- `simple-password-generator.py` does not guarantee a mix of character types,
  although its docstring says it does.

## Brand Commitments

**Name:** Simple Scripts Collection. **Voice:** plain and technical. The
scripts say what they found in one line per item, and the README is a table of
names, descriptions and commands.

The interface reports a failure rather than hiding it. `simple-clipboard.py`
names the clipboard tools it looked for. `simple-http-request.py` exits with
the HTTP status code it received. `simple-calculator.py` prints the exception
from the expression it could not evaluate.

**Assets:** there is no logo and no typography to keep. The only colour is
ANSI, chosen per script, and it marks a status rather than decorating.

## Evidence on Hand

- `README.md` holds the index of all 52 scripts, with a description and an
  example command for each.
- The first line of each script's module docstring is where the description
  in that table comes from. `simple-word-frequency-counter.py` has no
  docstring, and its row carries the argparse description instead.
- The argparse parser in each script holds every option and every default
  quoted in the documents.
- `simple-mock-api.py` carries the JSON route format in its docstring.
- `simple-port-scanner.py` is the only script with a result model, and it
  uses dataclasses.

Absent, and not to be invented: no download counts, no usage numbers, no
testimonials, no comparison with other collections, and no stated support
policy for any platform. The repository has seven commits, no tags and no
releases, and its one open issue asks for the house standard to be adopted.

## Product Principles

1. **One file per task.** A script is a whole program in a single file, and
   nothing in it imports anything else in the repository.
2. **The standard library is the whole dependency list.** No third-party
   packages, and no install step for the person who runs the script.
3. **Nothing changes until it is asked for.** The scripts that write to files
   print the change and stop, and the flag that applies it has to be typed.
4. **The output is the plainest thing that works.** One line per result, ANSI
   colour where it carries information, and a flag to turn the colour off
   where it would get in the way.
5. **The README is the index.** Every script has a row with its own
   description and an example, and a script is not in the collection until it
   has one.

## Accessibility & Inclusion

- **The terminal is the only interface.** There is no screen-reader story to
  write, and no accessibility standard has been set for the collection.
- **Colour is never the only signal.** The scripts that colour their output
  also print the status word next to it, and `--no-color` removes the escape
  codes altogether.
- **Nothing depends on the width of the window.** The tables are sized from
  their content, so they grow with the data rather than being cut to fit.
- **The command line is the whole interface, and the script documents it.**
  `--help` prints the options the script accepts, so nothing about the
  interface has to be learned from outside the repository.
- **No standard has been chosen, and nothing has been tested against one.**
  Screen readers, high-contrast themes and colour vision deficiency have not
  been considered, and the collection carries no accessibility policy.

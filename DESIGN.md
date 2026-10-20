---
name: simple-scripts-collection
description: The terminal language of 52 single-file utilities: one ANSI palette, one output convention, one dry-run rule.
colors:
  green: '\033[32m'
  yellow: '\033[33m'
  red: '\033[31m'
  blue: '\033[34m'
  magenta: '\033[35m'
  cyan: '\033[36m'
  dim: '\033[90m'
  bold: '\033[1m'
  reset: '\033[0m'
typography:
  body:
    fontFamily: "terminal default"
    fontSize: "terminal default"
    fontWeight: 400
    lineHeight: "terminal default"
rounded:
  md: none
spacing: {}
---

# Design system: simple-scripts-collection

## Overview

**Creative North Star: "The drawer of hand tools"**

The collection has no interface of its own. Fifty-two programs run in a
terminal and print text, and the terminal supplies the typeface, the
starting colours, the width and the background. What the collection decides
comes down to three things: which escape code carries which meaning, which
stream carries the result, and what a script prints before it touches
anything on disk.

Three decisions carry the whole thing. A script that writes to files prints
what it would do and stops, and the flag that changes that is opt-in. The
result goes to standard output and the complaint goes to standard error, so
a script drops into a pipe without anything else having to be filtered out.
The exit code is the verdict, and it is 0 unless the script failed.

The rejections matter as much. There is no banner, no logo, no spinner, no
progress bar, no table library and no `rich` or `click`. There is no
package, no shared module and no entry point, so a script can be copied out
of the repository and still run.

**Key characteristics:**

- the terminal's typeface, its width and its background
- one ANSI palette, shared by the nine scripts that print colour
- the result on standard output, the complaint on standard error
- a destructive action is opt-in, and the dry run is the default
- the exit code says whether it worked

## Colors

The collection uses the eight standard ANSI SGR codes and the two attributes
that go with them. They are literal escape sequences in the source files, so
the palette is in the code and there is no theme file to change it.

- **Green** (`\033[32m`): the good news. An added key, a passing certificate,
  a line added by a diff, a 2xx status.
- **Red** (`\033[31m`): the bad news. A deleted key, a line removed by a
  diff, a 4xx or 5xx status, an expired certificate.
- **Yellow** (`\033[33m`): the warning. A changed key, a line the diff could
  not place, a 3xx status, a certificate inside the 30-day window.
- **Cyan** (`\033[36m`): the structure. A column header, a diff hunk header,
  the name of a command.
- **Blue** (`\033[34m`): one of the five colours the git graph cycles
  through.
- **Magenta** (`\033[35m`): the other half of the git graph cycle, and the
  context line in a diff.
- **Dim** (`\033[90m`): the secondary text. The trailing summary of a status
  check, the muted part of a certificate line.
- **Bold** (`\033[1m`): the emphasis. The subject of a commit line.
- **Reset** (`\033[0m`): the end of every run of colour.

What each script means by each code differs, and the difference is worth
recording:

| Script | What the colours mean there |
| --- | --- |
| `simple-ssl-check.py` | `ok`, `warn`, `err`, `dim`, keyed to the certificate expiry |
| `simple-env-diff.py` | `add`, `del`, `chg`, `hdr` |
| `simple-http-status-checker.py` | one colour per status class, 2xx to 5xx, plus `dim` |
| `simple-text-diff.py` | `+` green, `-` red, `?` yellow, `@` cyan, `!` magenta |
| `simple-git-log.py` | the five graph colours, plus `bold` and `dim` for the subject |
| `simple-parallel-run.py` | one colour per command name, so two streams can be told apart |
| `simple-log-tail.py` | the bright variants 91, 92 and 93 for the log level |
| `simple-regex-tester.py` | a green background and black text on the matched span |
| `simple-color.py` | the colour it converted, printed as a foreground and a background |

### Named rules

**The Terminal's Palette Is The Palette.** The scripts never set a
background, never pick a hue outside the eight, and never rely on a 256-colour
or true-colour code. A script that runs on a terminal with eight colours
looks the same as one that runs on a terminal with a million.

**The Colour Is Never The Only Channel.** Every status that gets a colour
also gets a word or a sign: `OK`, `WARN`, `ERR`, a `+` or a `-` in a diff, a
`2xx` in a status check. A reader on a terminal with no colour, or a reader
who cannot tell green from red, loses nothing.

## Typography

The scripts name no typeface and no size. The terminal's own font is used,
and the scripts' text is plain ASCII apart from the two that print an emoji.

The one typographic decision is to use the terminal's attributes where a
typesetter would use a type. Bold marks the subject of a commit line in
`simple-git-log.py`. Dim marks the secondary text in
`simple-http-status-checker.py` and `simple-ssl-check.py`. The bright
variants of red, green and yellow, 91, 92 and 93, mark the log level in
`simple-log-tail.py`, where the level has to be readable in a wall of
output.

### Named rules

**The Terminal's Type Is The Type.** No script sets a font, and no script
embeds a typeface. The reader's terminal decides, and the scripts stay
readable in a monospace pane, a log file and a piped capture.

## Layout

The width is the terminal's, and the scripts do not wrap or truncate to fit
it. Where a script needs columns, it computes them from the data and prints
them.

Two layouts recur. The first is the boxed table, drawn with ASCII: a rule of
`+` and `-`, a row of `|`-separated cells, one space of padding on each side
of a cell. `simple-csv-viewer.py` draws it, and the column widths are the
widest cell in the column or the width of the header, whichever is larger.

The second is the tree. `simple-dir-size.py` and `simple-file-search.py` draw
it with `├── ` and `└── ` for the entries and `│   ` and four spaces for the
indent, one level at a time. The name is followed by `/` for a folder, and
then by the size in the units `B`, `KB`, `MB`, `GB`, `TB` or `PB`.

### Named rules

**The Table Is Drawn In ASCII.** A rule of `+` and `-`, a cell of `|`, one
space of padding. A box drawn with box-drawing characters looks better in a
modern terminal and turns into noise in a log file, an email or a paste into
a ticket.

**The Tree Is Drawn In ASCII.** Same reason. The connectors are the ones a
person can type by hand.

## Elevation & Depth

There is none, and there is nowhere for it to go. A terminal has no layers,
and no script draws a shadow, a panel or a border that is not part of the
table or the tree.

The only thing that reads as depth comes from the indentation of a tree,
and that is the data's own structure rather than a decoration.

## Shapes

There are no rounded corners and no border radius, because there are no
rectangles with a fill. The shapes in the output are the table, the tree and
the line of text.

## Components

### The parser

- **Shape:** one argparse parser per script, describing the options.
- **Help:** every script takes `--help`, and argparse prints the usage. Ten
  scripts add an epilog with a worked example.
- **Description:** the parser's description is the task in one line, and the
  module docstring says the same thing.

### The result

- **Shape:** the answer, on standard output, in the shortest form that carries
  it.
- **Examples:** a UUID per line, a table, a tree, one line per match.
- **Counts:** where a script prints a set, it prints the count with it. The
  CSV table ends with `N row(s)`.

### The complaint

- **Shape:** the error, on standard error, with the reason in the message.
- **Exit code:** 0 unless the script failed.

### The dry run

- **Shape:** the plan, one line per action, then the stop.
- **Examples:** `simple-rename-batch.py` prints the old name and the new one
  for every file it would rename. `simple-find-replace.py` prints the file
  and the number of replacements it would make. `simple-duplicate-finder.py`
  prints the groups it found.
- **The flag:** `--apply` for the two that rewrite, `--delete` for the one
  that removes.

### The colour switch

- **Shape:** `--no-color` on eight of the nine scripts that print colour.
- **Automatic:** `simple-git-log.py`, `simple-log-tail.py` and
  `simple-parallel-run.py` switch the colour off by themselves when standard
  output is not a terminal.
- **Exception:** `simple-color.py` prints colour on purpose, because the
  colour is the answer.

## Do's and Don'ts

- **Do** keep the eight ANSI codes and the two attributes as the whole
  palette, and use the bright variants only where the plain one is too quiet.
- **Do** put a word or a sign next to every coloured status.
- **Do** draw tables and trees in ASCII.
- **Do** send the result to standard output and the complaint to standard
  error, and keep the exit code at 0 unless the script failed.
- **Do** make a destructive action opt-in, and print the dry run by default.
- **Don't** add a dependency. The whole point of the collection is that a
  script runs with nothing but the interpreter.
- **Don't** add a shared module. A script has to be copyable out of the
  repository on its own.
- **Don't** add a banner, a spinner or a progress bar. A script that prints
  one line per result is pipeable, and a spinner is not.
- **Don't** use a colour that is not in the eight, and don't rely on a
  colour alone.
- **Don't** put an emoji in the output. Two scripts print one today, and the
  house checker fails the build when it finds one.

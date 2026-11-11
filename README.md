# goose-sast

[![ci](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml)

A security linter for Goose: source rules, dependency policy checks and advisory checks.

The package is a library and a command. The library scans a text or a tree and gives the findings as values. The `sast` command prints them and sets the exit code. Each finding holds a rule ID, a severity, a confidence and a CWE number. It also holds the file, the line, the column and a message.

## Install

```goose
import sast from "rekanalar/goose-sast@v0.2.0";
```

Build the command from the package root:

```
goose build -o sast cmd/sast.goose
sast [flags] <path>
```

## Example

```goose
import std;
import sast from "rekanalar/goose-sast@v0.2.0";

fn main() {
    var o = sast::default_options();
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/main.goose", "let r = rand_int(10);\n", o, fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    print(out[..]);
}
```

## API

| Signature | Result |
|---|---|
| `default_options() -> Options` | the options of a plain run; it empties the ID lists |
| `scan_text(path, src, o, out) -> i64` | scans one text; appends the findings; gives the count kept |
| `scan_dir(dir, o, out) -> i64, i64` | scans every `.goose` file under a directory; gives the files scanned and skipped |
| `sort_findings(out)` | orders the findings by file, line, column and rule |
| `findings_reset()` | empties the path and message buffers before a run |
| `opt_exclude(id)`, `opt_include(id)` | filters by rule ID; an alias ID works too |
| `opt_skip_path(part)` | skips a path part in the walk |
| `reg_find(id) -> i64` | gives the registry index of an ID, or -1 |
| `list_rules(out)` | writes one line per rule |
| `format_text(findings, out)` | writes one line per finding |
| `format_json(findings, scanned, skipped, out)` | writes one JSON object: the findings, the totals per severity and the file counts |
| `format_summary(findings, scanned, skipped, out)` | writes the count line |

## Command

| Flag | Effect |
|---|---|
| `-severity low\|medium\|high\|critical` | the lowest severity to report |
| `-confidence low\|medium\|high` | the lowest confidence to report |
| `-exclude ID,ID` | leaves rules out |
| `-include ID,ID` | keeps only these rules |
| `-exclude-path NAME,NAME` | skips path parts in the walk |
| `-f text\|json` | the output format; text is the default |
| `-quiet` | prints nothing; the exit code stays |
| `-no-fail` | always exits 0 |
| `-list-rules` | prints the rule list |

The exit code is 0 with no finding, 1 with findings and 2 when the scan fails.

## Suppression

A comment on the line of a finding silences it. `// nosec`, `// noqa` and `// nosemgrep` all work. A list of rule IDs after the word limits the comment to those rules. An alias ID counts as its rule.

## Rules

The rule IDs follow the IDs of `gosec` and `bandit`, with the aliases below. Run `sast -list-rules` for the full list.

| Rule | Defect |
|---|---|
| G101 (B105, B106, B107) | a credential literal beside a secret-named name |
| G102 (B104) | a bind-all address literal |
| G103 | an `extern` declaration |
| G109 (G115) | an `as!` cast to a smaller integer |
| G116 (B613) | a bidirectional control character in the source |
| G117 | a secret-named value in a JSON writer call |
| G201, G202 (B608) | a SQL string built from a variable |
| G203 | HTML built from a variable |
| G204 | a process command from a variable |
| G301, G302 (B103), G306 | a wide permission literal |
| G303 (B108), G304, G111 | a temp path, a variable path, the root path |
| G401 (B324) | a weak hash |
| G404 (B311) | a weak random source |
| G501 to G507, B401 to B415 | blocklisted imports |
| B101 | an `assert` outside a test file |
| B110 (B112) | an empty catch body |
| B113 | a `wait` with a zero limit |
| B607, B609 | a partial command path, a wildcard argument |

## Limits

- The rules read the source as text. A name that a program builds at run time stays invisible.
- The tokenizer holds strings, comments, identifiers and numbers. It does not parse the language, so a rule that needs types does not exist.
- Most rules of the references have no Goose surface. The standard library holds no TLS, HTTP, SQL, archive or template code. The package leaves those rules out.
- The dependency policy and advisory checks are not in this release.
- The `sast` command reads one path per run.

## Security

- The scan bounds one file at 16 MiB, the walk at 4096 files and 64 directory levels.
- The walk follows symbolic links, because the standard library has no call that tells a link from a directory. A link loop ends at the depth bound. A link that points outside the tree makes the scan read files outside it. Scan only trees that you trust, or skip a link with `-exclude-path`.
- The output writes each byte outside printable ASCII as `\xNN`. A hostile path cannot inject a control sequence into a terminal.
- A file that the scan cannot read counts as skipped. The summary line shows the count, so a skipped file never hides.
- The scan runs no code from the files it reads.

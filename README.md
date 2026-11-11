# goose-sast

[![ci](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml)

A security linter for Goose: source rules, dependency policy checks and advisory checks.

The package is a library and a command. The library scans a text or a tree and gives the findings as values. The `sast` command prints them and sets the exit code. Each finding holds a rule ID, a severity, a confidence and a CWE number. It also holds the file, the line, the column and a message.

## Install

```goose
import sast from "rekanalar/goose-sast@v0.5.0";
import semver from "rekanalar/goose-semver@v1.0.1";
```

The advisory check reads its version ranges through the semver module.
A program that uses this package declares both. The package also holds
a small C part, so a program that uses it needs a C compiler.

Build the command from the package root:

```
goose build -o sast cmd/sast.goose
sast [flags] <path>
```

## Example

```goose
import std;
import sast from "rekanalar/goose-sast@v0.5.0";
import semver from "rekanalar/goose-semver@v1.0.1";

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
| `read_manifest(src) -> i64` | reads the import lines into dependencies; gives the count |
| `read_policy(text, err) -> bool` | reads the policy JSON; false on a fault |
| `read_advisories(text, err) -> bool` | reads the advisory JSON in the RustSec shape |
| `check_deps(src, out) -> i64` | runs the ban, licence, source and advisory checks; gives the count |
| `read_custom(text, err) -> bool` | reads a custom rule file; false on a fault |
| `custom_reset()` | drops the custom rules of the run |
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
| `-max-depth N` | the directory levels the walk reads |
| `-max-files N` | the files the walk reads |
| `-rules FILE` | loads custom rules from this file |
| `-policy FILE` | runs the dependency checks with this policy |
| `-advisories FILE` | runs the advisory check with this file |
| `-quiet` | prints nothing; the exit code stays |
| `-no-fail` | always exits 0 |
| `-list-rules` | prints the rule list |

The exit code is 0 with no finding, 1 with findings and 2 when the scan fails.

## Suppression

A comment on the line of a finding silences it. `// nosec`, `// noqa` and `// nosemgrep` all work. A list of rule IDs after the word limits the comment to those rules. An alias ID counts as its rule.

A block suppression covers many lines. A comment with `// nosec:start` opens one, and a comment with `// nosec:end` closes it. Every finding between the two markers stays out. A marker with no end reaches the last line of the file.

## Custom rules

A file of custom rules adds rules without a change to the package. The file is JSON:

```json
{
  "rules": [
    { "id": "HOUSE01", "severity": "high", "kind": "ident", "text": "legacy_login",
      "message": "the legacy login is forbidden" },
    { "id": "HOUSE02", "severity": "low", "kind": "ident", "text": "debug_mode", "exact": true,
      "message": "a debug flag sits in the source" }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | the rule ID; an ID that the built-in rules hold is a fault |
| `severity` | `low`, `medium`, `high` or `critical` |
| `kind` | `ident` reads identifiers, `string` reads string literals, `comment` reads comments |
| `text` | what the rule looks for |
| `exact` | true matches the whole token; false matches a part |
| `message` | the message of the finding |

A custom rule joins the registry. The filters, the suppressions and the exit code treat it like a built-in rule. A second `-rules` file replaces the first.

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
| G702, G703 | a value from the command line, the environment or a file reaches a process call or a file path |
| G404 (B311) | a weak random source |
| G501 to G507, B401 to B415 | blocklisted imports |
| B101 | an `assert` outside a test file |
| B110 (B112) | an empty catch body |
| B113 | a `wait` with a zero limit |
| B607, B609 | a partial command path, a wildcard argument |

The dependency checks report under their own IDs.

| Rule | Defect |
|---|---|
| BAN | a banned package, or a package in a banned version range |
| LICENSE | a licence that is not on the allow list, or a missing licence |
| SOURCE | a source that is not on the allow list |
| ADVISORY | a pinned version that an advisory range covers |

## Limits

- The rules read the source as text. A name that a program builds at run time stays invisible.
- The tokenizer holds strings, comments, identifiers and numbers. It does not parse the language, so a rule that needs types does not exist.
- A rule that matches on a name alone, such as G401, matches a local function of that name too. The linter cannot tell the two apart. Read such a finding before you act on it.
- The scope rules use the brace depth. A name of a deeper scope hides the name of an outer scope. A name of a sibling scope still matches.
- Most rules of the references have no Goose surface. The standard library holds no TLS, HTTP, SQL, archive or template code. The package leaves those rules out.
- The advisory file holds the advisories of Rust packages. No Goose advisory database exists. The package reads the RustSec file format and reports the hits of the package names that match.
- The tool runs offline. It reads no network and holds no database of its own.
- The `sast` command reads one path per run.

## Security

- The scan bounds one file at 16 MiB, the walk at 4096 files and 64 directory levels. The `-max-files` and `-max-depth` flags lower both bounds.
- The link check is one C call with one argument. A path longer than 4096 bytes counts as a link and stays out of the walk.
- The walk skips a symbolic link and any other reparse point. A loop of links cannot make the walk read one file twice. A link cannot point the walk outside the tree. A path that the check cannot read counts as a link.
- The output writes each byte outside printable ASCII as `\xNN`. A hostile path cannot inject a control sequence into a terminal.
- A file that the scan cannot read counts as skipped. The summary line shows the count, so a skipped file never hides.
- The scan runs no code from the files it reads.

# goose-sast

[![ci](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml)

A security linter for Goose: source rules, dependency policy checks and advisory checks.

The package is a library and a command. The library scans a text or a tree and gives the findings as values. The `sast` command prints them and sets the exit code. Each finding holds a rule ID, a severity, a confidence and a CWE number. It also holds the file, the line, the column and a message.

## Install

```goose
import sast from "rekanalar/goose-sast@v0.7.2";
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
import sast from "rekanalar/goose-sast@v0.7.2";
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
| `read_custom_more(text, err) -> bool` | adds the rules of a rule file to the rules of the run |
| `read_config(text, mask, options, policy, advisories, rules, err) -> bool` | reads a config file; false on a fault |
| `split_list(list, out)` | splits a list on commas and leaves out the empty parts |
| `scan_dir_budget(dir, options, out, budget) -> i64, i64` | scans a tree against a file budget that several trees share; the caller sorts the findings |
| `scan_reset()` | clears the state of one run: the list of the walked directories, the finding store and the bound flag. A run calls it once before it scans |
| `read_bounded(path, max, out) -> bool` | reads a regular file of at most max bytes; false for a pipe, a device, a directory and a file that is too large |
| `custom_reset()` | drops the custom rules of the run |
| `reg_find(id) -> i64` | gives the registry index of an ID, or -1 |
| `list_rules(out)` | writes one line per rule |
| `format_text(findings, out)` | writes one line per finding |
| `format_json(findings, scanned, skipped, out)` | writes one JSON object: the findings, the totals per severity and the file counts |
| `format_summary(findings, scanned, skipped, out)` | writes the count line |
| `format_sarif(findings, out)` | writes one SARIF 2.1.0 object with the rule rows and the results |

## Command

| Flag | Effect |
|---|---|
| `-severity low\|medium\|high\|critical` | the lowest severity to report |
| `-confidence low\|medium\|high` | the lowest confidence to report |
| `-exclude ID,ID` | leaves rules out |
| `-include ID,ID` | keeps only these rules |
| `-exclude-path NAME,NAME` | skips path parts in the walk |
| `-f text\|json\|sarif` | the output format; text is the default |
| `-max-depth N` | the directory levels the walk reads |
| `-max-files N` | the files the walk reads |
| `-rules FILE` | loads custom rules from this file; the flag takes several files |
| `-config FILE` | reads the settings of the run from this file |
| `-no-config` | reads no config file of the current directory |
| `-policy FILE` | runs the dependency checks with this policy |
| `-advisories FILE` | runs the advisory check with this file |
| `-quiet` | prints nothing; the exit code stays |
| `-no-fail` | always exits 0 |
| `-list-rules` | prints the rule list |

The command takes several targets. It scans each target in turn. A directory target runs the walk and a file target runs the text scan. The summary line counts the files of all targets. A directory that two targets name by the same bytes is walked once. The dependency checks read the first target that is a file.

The exit code is 0 with no finding, 1 with findings and 2 when the scan fails.

The dependency checks set the exit code to the bitset of cargo-deny.

| Bit | Break |
|---|---|
| 1 | an advisory |
| 2 | a banned package |
| 4 | a denied licence |
| 8 | a denied source |

A run with a banned package and no other finding exits 2, the code of a failed scan. A run with an advisory and no other finding exits 1, the code of a finding.

## Config file

A config file holds the settings of a run. The command reads the file `.goose-sast.json` of the current directory. The `-config` flag names another file. The file is JSON:

```json
{
  "min_severity": "medium",
  "min_confidence": "low",
  "exclude": "G401,G404",
  "include": "",
  "exclude_path": "vendor,third_party",
  "policy": "policy.json",
  "rules": "company.json,repo.json",
  "advisories": "advisories.json",
  "max_files": 4096,
  "max_depth": 64
}
```

| Key | Value |
|---|---|
| `min_severity` | `low`, `medium`, `high` or `critical` |
| `min_confidence` | `low`, `medium` or `high` |
| `exclude` | rule IDs that commas separate |
| `include` | rule IDs that commas separate |
| `exclude_path` | path parts that commas separate |
| `policy` | the path of a policy file |
| `rules` | the paths of rule files that commas separate |
| `advisories` | the path of an advisory file |
| `max_files` | a whole number |
| `max_depth` | a whole number |

A flag of the command line wins over the value of the file. The command checks every value of the file, also the values that a flag replaces.

A file that does not parse is a fault. A negative bound is a fault. A bound of more than nine digits is a fault. A key that the command does not know is a fault. A key that the file holds twice is a fault. The fault names the key and the run ends with exit code 2.

The rule files of the config file join the rule files of the `-rules` flag. The merge of the rule files is the rule of the package.

The command reads the file `.goose-sast.json` of the current directory. A checkout that holds that file sets the settings of the run. A CI job that scans an untrusted checkout should pass `-no-config` or name its own file with the `-config` flag.

## Suppression

A comment on the line of a finding silences it. `// nosec`, `// noqa` and `// nosemgrep` all work. A list of rule IDs after the word limits the comment to those rules. An alias ID counts as its rule.

A block suppression covers many lines. A comment with `// nosec:start` opens one, and a comment with `// nosec:end` closes it. `// goose-sast:disable` and `// goose-sast:enable` are the same thing under other names. A marker with no end reaches the last line of the file.

A directive with a rule list covers those rules only. `// goose-sast:disable G101, G102` silences the two rules until the matching enable. Two disables of one rule with one enable close the first open range. A list of IDs that no rule carries opens no range and the run says nothing about it.

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

A custom rule joins the registry. The filters, the suppressions and the exit code treat it like a built-in rule. Several `-rules` files merge. The rules of each file join the rules of the earlier files. A rule ID that two files hold is a fault that names the ID. A file that faults leaves the rules of the run as they were.

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
- G401 and G404 read one token before and one token after a name. They report a call form only. A call through a function value or an alias stays invisible.
- The scope rules use the brace depth. A name of a deeper scope hides the name of an outer scope. A name of a sibling scope still matches.
- Most rules of the references have no Goose surface. The standard library holds no TLS, HTTP, SQL, archive or template code. The package leaves those rules out.
- The advisory file holds the advisories of Rust packages. No Goose advisory database exists. The package reads the RustSec file format and reports the hits of the package names that match.
- The tool runs offline. It reads no network and holds no database of its own.
- The `sast` command takes several targets. The file count bound covers the whole run. The depth bound applies to each tree.
- The config file sits in the current directory. The command does not walk up the tree to find it.
- The rule IDs of a config file and of a flag name the built-in rules. The custom rules load after the lists, so a custom rule ID does not work there.
- The walk compares the bytes of a path. The targets `a` and `./a` name one directory, and the walk reads it twice. The standard library has no canonical path call.
- The dependency checks read the first target that is a file. A run with only directories leaves them out.
- A `-exclude` or `-include` flag with an empty value still replaces the list of the config file.
- The exit code of the dependency checks shares its values with the exit codes of the scan. A caller that needs to tell the two apart reads the output.
- The command reads the file `.goose-sast.json` of the current directory. A checkout that holds that file sets the settings of the run.

## Security

- The scan bounds one file at 16 MiB, the walk at 4096 files and 64 directory levels. The `-max-files` and `-max-depth` flags lower both bounds.
- The link check is one C call with one argument. A path longer than 4096 bytes counts as a link and stays out of the walk.
- The walk skips a symbolic link and any other reparse point. A link cannot point the walk outside the tree. A path that the check cannot read counts as a link.
- The walk holds the byte path of every directory it enters and skips a directory it has seen. A bind-mount loop costs one visit. A directory reached by two different paths counts twice.
- The output writes each byte outside printable ASCII as `\xNN`. A hostile path cannot inject a control sequence into a terminal.
- A file that the scan cannot read counts as skipped. The summary line shows the count, so a skipped file never hides.
- The scan runs no code from the files it reads.
- The config file is read once per run. Its size is bounded like the size of a source file. A file that does not parse is a fault, never a silent default.
- The command reads no pipe, no device and no directory. A file that is no regular file ends the run with exit code 2. The size of a file is read before its bytes, so a file above the bound never reaches the memory.
- The count of the findings of a run is bounded at 65536. A run that reaches the bound says so on the error output. The count in the summary is then a lower bound.
- The messages of a fault write each byte outside printable ASCII as `\xNN`, except the newline. A hostile name in a config file or a rule file cannot inject a control sequence. A C1 control is safe too.

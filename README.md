# goose-sast

[![ci](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-sast/actions/workflows/ci.yml)

A security linter for Goose: source rules, dependency policy checks and advisory checks.

The package is a library and a command. The library scans a text or a tree and gives the findings as values. The `sast` command prints them and sets the exit code. Each finding holds a rule ID, a severity, a confidence and a CWE number. It also holds the file, the line, the column and a message.

## Install

```goose
import sast from "rekanalar/goose-sast@v0.9.0";
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
import sast from "rekanalar/goose-sast@v0.9.0";
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
| `default_options() -> Options` | the options of a plain run; it empties the ID lists and gives the default profile |
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
| `scan_reset()` | clears the state of one run: the list of the walked directories, the finding store, the bound flag and the count of the left-out directories. A run calls it once before it scans |
| `read_bounded(path, max, out) -> bool` | reads a regular file of at most max bytes; false for a pipe, a device, a directory and a file that is too large |
| `Options.report_unused` | a field: when true, `scan_text` collects the suppressions that silenced nothing |
| `Options.profile` | a field: the profile of the run; `PROFILE_DEFAULT`, `PROFILE_STRICT` or `PROFILE_ALL` |
| `profile_of_name(name) -> i64` | gives the profile of a name, or -1 when no profile carries it |
| `reg_tier_set(id, tier)` | sets the tier of a rule; `TIER_DEFAULT` or `TIER_STRICT` |
| `dirs_left_out` | the count of the directories that the profile left out of the walk; `scan_reset()` clears it |
| `secret_class(name) -> i64` | gives the class of a name: 0 none, 1 weak, 2 strong |
| `unused_text` | the rows of the unused report, one `path:line: unused suppression [ID]` per row; `scan_reset()` clears it |
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
| `-profile default\|strict\|all` | the rule set and the walk policy; the default is `default` |
| `-report-unused` | names each suppression that silenced nothing, on the error output; the exit code does not change |
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

## Profiles

A profile names a rule set and a walk policy. Three profiles exist.

| Profile | Rules | Walk |
|---|---|---|
| `default` | every rule except G304, G104 and B101 | leaves out the `test` and `examples` directories that it finds |
| `strict` | every rule | leaves out the `test` and `examples` directories that it finds |
| `all` | every rule | leaves out nothing |

The default profile is the quiet one. A first run over a real project gives the findings that a reader must act on. The three rules that the default profile leaves out are common in real code and rarely a defect.

The `-profile` flag chooses the profile. The config key `profile` chooses it too, and the flag wins over the key. An unknown name is a fault, and the fault names the flag or the key.

The walk leaves out a directory whose name is exactly `test` or exactly `examples`. The match is exact and in lower case. A directory named `Test`, `tests` or `example` is read. A target that the user names is always scanned, even when the target is named `test`.

The summary line names the directories that the profile left out. The JSON output holds the same count under the key `left_out`. The SARIF output holds no count. The command `-list-rules` names the profile that first holds each rule.

An `-include` flag turns a rule on in any profile. An `-exclude` flag turns it off in any profile. The two flags never change the walk policy of the profile.

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
  "max_depth": 64,
  "profile": "default"
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
| `profile` | `default`, `strict` or `all` |

A flag of the command line wins over the value of the file. The command checks every value of the file, also the values that a flag replaces.

A file that does not parse is a fault. A negative bound is a fault. A bound of more than nine digits is a fault. A key that the command does not know is a fault. A key that the file holds twice is a fault. The fault names the key and the run ends with exit code 2.

The rule files of the config file join the rule files of the `-rules` flag. The merge of the rule files is the rule of the package.

The command reads the file `.goose-sast.json` of the current directory. A checkout that holds that file sets the settings of the run. A CI job that scans an untrusted checkout should pass `-no-config` or name its own file with the `-config` flag.

## Suppression

A comment on the line of a finding silences it. `// nosec`, `// noqa` and `// nosemgrep` all work. A list of rule IDs after the word limits the comment to those rules. An alias ID counts as its rule.

A comment that stands alone on its line may silence the line below it. `// nosec:next` and `// goose-sast:disable-next-line` both work, like `eslint-disable-next-line` of ESLint. A list of rule IDs after the word limits the comment to those rules. A directive with no list covers every rule. The directive covers the one line that follows it. A directive at the end of a file covers nothing, and so does a comment that trails code.

A block suppression covers many lines. A comment with `// nosec:start` opens one, and a comment with `// nosec:end` closes it. `// goose-sast:disable` and `// goose-sast:enable` are the same thing under other names. A marker with no end reaches the last line of the file.

A directive with a rule list covers those rules only. `// goose-sast:disable G101, G102` silences the two rules until the matching enable. Two disables of one rule with one enable close the first open range. A list of IDs that no rule carries opens no range, so a typo never hides a finding.

The flag `-report-unused` lists each suppression that silenced nothing. Ruff (RUF100) and golangci-lint (`nolintlint`) have the same report. A comment with a list gives one row for each ID that matched nothing. A block that matched nothing gives the line that opened it. An ID that no rule carries gives no row. The report is off by default, and it does not change the exit code.

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
| `kind` | `ident` reads identifiers, `string` reads string literals, `comment` reads comments, `regex` searches the text of the file |
| `text` | what the rule looks for; for the kind `regex`, the expression |
| `exact` | true matches the whole token; false matches a part |
| `message` | the message of the finding |

A rule of the kind `regex` searches the whole text of each file, like the `pattern-regex` of semgrep. It reports the line and the column of each match, using the regex engine of the standard library. The engine refuses the anchors `^` and `$` and the flag `(?m)`. A rule that holds one is a fault that names the rule. semgrep accepts them. Match one line with the text around the shape instead.

A custom rule joins the registry. The filters, the suppressions and the exit code treat it like a built-in rule. Several `-rules` files merge. The rules of each file join the rules of the earlier files. A rule ID that two files hold is a fault that names the ID. A file that faults leaves the rules of the run as they were.

## Rules

The rule IDs follow the IDs of `gosec` and `bandit`, with the aliases below. Run `sast -list-rules` for the full list.

| Rule | Defect |
|---|---|
| G101 (B105, B106, B107) | a credential literal beside a secret-named name; a weak name needs a literal that looks like a credential |
| G102 (B104) | a bind-all address literal in the call of `listen`, `bind`, `serve` or `accept` |
| G103 | an `extern` declaration |
| G109 (G115) | an `as!` cast to a smaller integer |
| G116 (B613) | a bidirectional control character in the source |
| G117 | a secret-named value in a JSON writer call |
| G201, G202 (B608) | a SQL string built from a variable |
| G203 | HTML built from a variable |
| G204 | a process command from a variable |
| G301, G302 (B103), G306 | a wide permission literal |
| G303 (B108), G304, G111 | a temp path, a variable path (strict), the root path |
| G401 (B324) | a weak hash |
| G702, G703 | a value from the command line, the environment or a file reaches a process call or a file path |
| G404 (B311) | a weak random source |
| G501 to G507, B401 to B415 | blocklisted imports |
| B101 | an `assert` outside a test file (strict) |
| G104 | the result of a call is dropped (strict) |
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
- G401 and G404 report a bare call and a qualified call, such as `md5::sum(x)` and `rand::int(n)`. The language stores no function value, so no name can hold the weak function. gosec and bandit resolve the import alias in the same way. Only semgrep follows a function value, and Goose has none to follow.
- The taint rules read the braces of the file, not a parser. Each open brace makes a scope. A name is visible in its scope and in the scopes inside it. A name of a sibling scope stays out, like the scope model of ESLint. A brace in a string or a comment does not count. A rebinding of a name does not clear an earlier taint of the same scope.
- The credential rule G101 reads one line. A name and its literal sit on the same line. A secret name of one function misses a literal of another.
- G101 splits the secret names in two sets. A strong name holds `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`, `api_key`, `privatekey` or `private_key`. It reports a literal of two bytes or more with one byte above a space. A short real password such as `admin` still reports, and a space inside is allowed.
- A weak name holds `pass` or `pwd`. It reports a literal of eight bytes or more with no space and more than one distinct byte. The name `key` is no secret name.
- bandit B105 reads the name only. gosec G101 reads the name and adds an entropy test. The two disagree, so the package keeps its own floor. The name test is a substring test, so `bypass` is a weak name.
- G102 reads the callee of the call that holds the literal. It walks back at most 32 tokens to the open bracket. A literal in a nested call belongs to the inner call, so `listen(host_or("0.0.0.0"), p)` reports nothing.
- The form `":port"` is not read. gosec resolves the call to `net.Listen` with type data. The package has none, so it reads the name of the callee. bandit B104 flags a bare literal, and the package does not copy that.
- The summary clause counts the directories that the profile left out, not the files. A count of files needs a walk of the directory that the profile meant to skip.
- The profile reaches the source rules. The dependency rules BAN, LICENSE, SOURCE and ADVISORY read no profile and no `-include` or `-exclude` list.
- The default profile leaves out G304, G104 and B101. The walk leaves out the `test` and `examples` directories that it finds. A run of an earlier release reported those findings.
- The library default changed too: `default_options()` gives the default profile. A caller that needs the old result sets `profile` to `PROFILE_ALL`.
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

- The default profile leaves out three rules and two directory names. It never hides them in silence. The summary line names the count of left-out directories, and the JSON output holds the same count.
- The command `-list-rules` marks each rule that the default leaves out. The `-profile strict` flag brings the three rules back. The `-profile all` flag brings the directories back too. The `-include` flag brings one rule back.
- A directory or a file that the user names as a target is always scanned, whatever its name is. Only a directory that the walk finds below a target can stay out. The match of the name is exact and in lower case, so a name such as `Test` is read.
- The summary clause holds a count and a flag name. No path reaches the terminal through it.
- A profile name is compared whole. A name of more than 16 bytes is an unknown name, and an unknown name is a fault.
- The scan bounds one file at 16 MiB, the walk at 4096 files and 64 directory levels. The `-max-files` and `-max-depth` flags lower both bounds.
- The link check is one C call with one argument. A path longer than 4096 bytes counts as a link and stays out of the walk.
- The walk skips a symbolic link and any other reparse point. A link cannot point the walk outside the tree. A path that the check cannot read counts as a link.
- The walk holds the byte path of every directory it enters and skips a directory it has seen. A bind-mount loop costs one visit. A directory reached by two different paths counts twice.
- The output writes each byte outside printable ASCII as `\xNN`. A hostile path cannot inject a control sequence into a terminal.
- A file that the scan cannot read counts as skipped. The summary line shows the count, so a skipped file never hides.
- The scan runs no code from the files it reads.
- A regex rule uses the regex engine of the standard library. That engine bounds its states, its instructions and its repeat counts. A pattern with a counted repeat above the bound is a fault at load. A rule file that faults leaves no expression behind.
- A regex rule compiles once, when the rule file loads, and not once per file. The matches of one file stop at the bound of the findings of a run. The line count is one pass over the bytes, so many matches cost linear time.
- A run holds at most 1024 custom rules. A file that goes past the bound is a fault. An empty regex match reports once, at the start of the file.
- A rule file is trusted input, like a config file. A project that scans untrusted checkouts should load rule files from a path it controls.
- A suppression covers only what it names. The next-line directive covers one line and never a range. A comment that trails code covers nothing next to it.
- The unused report writes each byte outside printable ASCII as `\xNN`, so a hostile path cannot inject a control sequence.
- The config file is read once per run. Its size is bounded like the size of a source file. A file that does not parse is a fault, never a silent default.
- The command reads no pipe, no device and no directory. A file that is no regular file ends the run with exit code 2. The size of a file is read before its bytes, so a file above the bound never reaches the memory.
- The count of the findings of a run is bounded at 65536. A run that reaches the bound says so on the error output. The count in the summary is then a lower bound.
- The messages of a fault write each byte outside printable ASCII as `\xNN`, except the newline. A hostile name in a config file or a rule file cannot inject a control sequence. A C1 control is safe too.

# Examples

Run the commands from the package directory. Each program reads the files
below and checks what they report.

## Rule files

Pass a rule file with `-rules`. The sample file is `samples/secrets.goose`.
Every secret in it is fake.

| File | Kinds | What it shows |
|---|---|---|
| `rules/secrets.json` | `string`, `ident` | private keys, key prefixes, secret names |
| `rules/house-style.json` | `ident` | exact and partial names that a team forbids |
| `rules/comments.json` | `comment` | open tasks, hacks, a password in a comment |
| `rules/regex.json` | `regex` | token shapes, IPv4, email, plain http |
| `custom-rules.json` | `ident` | the two rules of the `custom.goose` program |

A `regex` rule takes no `^` or `$` and no `(?m)`. The regex engine of the
standard library refuses them.

## Policy files

Pass a policy file with `-policy`. A root file holds the import lines.

| Policy | Root file | Result |
|---|---|---|
| `policy/strict.json` | `policy/root-clean.goose` | no finding, exit 0 |
| `policy/strict.json` | `policy/root-bad.goose` | bans, licences and a source; exit 15 with the advisories |
| `policy/permissive.json` | `policy/root-bad.goose` | one source finding, exit 8 |
| `policy/with-ignores.json` | `policy/root-advised.goose` | two advisories ignored, with a reason each |

The exit code of the dependency checks is a bitset. Advisories add 1, bans
add 2, licences add 4 and sources add 8.

## Advisory files

Pass an advisory file with `-advisories`.

| File | Form | What it shows |
|---|---|---|
| `advisories/single.json` | list under `advisories` | one range with a patched version |
| `advisories/several.json` | list under `advisories` | four packages, three severities |
| `advisories/bare-list.json` | the list alone | a file with no wrapper object |

A pin that a patched version replaces gives no finding. The `markdown` pin in
`policy/root-advised.goose` shows it.

## Programs and the config file

| File | What it does |
|---|---|
| `catalog.goose` | runs every file above and ends with an error when a count is wrong |
| `scan.goose`, `suppress.goose` | the scan and the suppression comments |
| `custom.goose`, `deps.goose` | the custom rules and the dependency checks |
| `sast-config.json` | one config file that joins rules, policy and advisories |

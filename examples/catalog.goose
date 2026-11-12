// Runs every example rule file, policy file and advisory file of this
// directory and checks what each one reports. A wrong count ends the
// program with an error, so the examples cannot drift from the package.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

var fails: i64 = 0;

fn check(ok: bool, what: const u8[:]) {
    if !ok {
        print("FAIL: ", what, "\n");
        fails = fails + 1;
    }
}

fn load(path: const u8[:], out: u8[>..]&) {
    read_file(path, out);
}

fn count_id(fs: const sast::Finding[>..]&, id: const u8[:]) -> i64 {
    let want = sast::reg_find(id);
    var n: i64 = 0;
    for f in fs { if f.rule == want { n = n + 1; } }
    return n;
}

// rule_file loads a rule file and checks that each ID reports once on
// the sample file.
fn rule_file(path: const u8[:], ids: const u8[:][]) {
    var text: u8[>..] = [];
    load(path, text);
    var err: u8[>..] = [];
    check(sast::read_custom(text[..], err), path);
    var src: u8[>..] = [];
    load("examples/samples/secrets.goose", src);
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("samples/secrets.goose", src[..], sast::default_options(), fs);
    for id in ids { check(count_id(fs, id) == 1, id); }
    sast::custom_reset();
}

// deps_count runs the dependency checks and gives the finding count.
// An empty policy path or advisory path leaves that part out.
fn deps_count(root: const u8[:], policy: const u8[:], adv: const u8[:]) -> i64 {
    sast::pol_reset();
    sast::adv_reset();
    var err: u8[>..] = [];
    if policy.len > 0 {
        var p: u8[>..] = [];
        load(policy, p);
        check(sast::read_policy(p[..], err), policy);
    }
    if adv.len > 0 {
        var a: u8[>..] = [];
        load(adv, a);
        check(sast::read_advisories(a[..], err), adv);
    }
    var src: u8[>..] = [];
    load(root, src);
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    return sast::check_deps(src[..], fs);
}

fn main() {
    rule_file("examples/rules/secrets.json", ["SEC01", "SEC02", "SEC03", "SEC04"]);
    rule_file("examples/rules/house-style.json", ["HOUSE01", "HOUSE02", "HOUSE03", "HOUSE04"]);
    rule_file("examples/rules/comments.json", ["NOTE01", "NOTE02", "NOTE03", "NOTE04"]);
    rule_file("examples/rules/regex.json", ["RX01", "RX02", "RX03", "RX04", "RX05", "RX06"]);

    let strict = "examples/policy/strict.json";
    let several = "examples/advisories/several.json";
    check(deps_count("examples/policy/root-clean.goose", strict, several) == 0, "a clean program");
    check(deps_count("examples/policy/root-bad.goose", strict, several) == 9, "a program that breaks the strict policy");
    check(deps_count("examples/policy/root-bad.goose", "examples/policy/permissive.json", "") == 1, "the permissive policy");
    check(deps_count("examples/policy/root-advised.goose", "", several) == 3, "the several advisories");
    check(deps_count("examples/policy/root-advised.goose", "examples/policy/with-ignores.json", several) == 1, "the ignore list");
    check(deps_count("examples/policy/root-glob.goose", "", "examples/advisories/bare-list.json") == 2, "the bare advisory list");
    check(deps_count("examples/policy/root-advised.goose", "", "examples/advisories/single.json") == 1, "the single advisory");

    if fails > 0 { abort("some examples drifted"); }
    print("all examples hold\n");
}

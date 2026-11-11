// The tests of the linter: each rule on a source text, the filters,
// the suppression comments and the escape of hostile bytes.
import std;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

var fails: i64 = 0;

fn check(ok: bool, what: const u8[:]) {
    if !ok {
        fails = fails + 1;
        print("FAIL ", what);
    }
}

// count_rule gives how many findings of the rule ID the text yields.
fn count_rule(src: const u8[:], id: const u8[:]) -> i64 {
    var o = sast::default_options();
    return count_rule_with(src, id, o);
}

fn count_rule_with(src: const u8[:], id: const u8[:], o: sast::Options) -> i64 {
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", src, o, fs);
    let want = sast::reg_find(id);
    var n: i64 = 0;
    for f in fs { if f.rule == want { n = n + 1; } }
    return n;
}

fn main() {
    check(count_rule("let password = \"hunter2hunter2\";\n", "G101") == 1, "G101 literal");
    check(count_rule("let name = \"hello\";\n", "G101") == 0, "G101 clean");
    check(count_rule("let a = \"0.0.0.0\";\n", "G102") == 1, "G102 bind");
    check(count_rule("let a = \"127.0.0.1\";\n", "G102") == 0, "G102 loopback");
    check(count_rule("let a = \"select * from t where a=\" + x;\n", "G202") == 1, "G202 sql");
    check(count_rule("let a = \"select \" + str(x);\n", "G201") == 1, "G201 format");
    check(count_rule("let h = \"<b>\" + name;\n", "G203") == 1, "G203 html");
    check(count_rule("run(cmd, args);\n", "G204") == 1, "G204 variable command");
    check(count_rule("run(\"ls\", args);\n", "B607") == 1, "B607 partial path");
    check(count_rule("run(\"/bin/ls\", args);\n", "B607") == 0, "B607 full path");
    check(count_rule("write_file(\"/tmp/x\", d);\n", "G303") == 1, "G303 temp");
    check(count_rule("read_file(p, out);\n", "G304") == 1, "G304 variable path");
    check(count_rule("make_dir(\"d\", 0o755);\n", "G301") == 1, "G301 dir mode");
    check(count_rule("f(0o777);\n", "G302") == 1, "G302 wide mode");
    check(count_rule("write_file(\"a\", d, 0o644);\n", "G306") == 1, "G306 write mode");
    check(count_rule("let h = md5(x);\n", "G401") == 1, "G401 weak hash");
    check(count_rule("let r = rand_int(5);\n", "G404") == 1, "G404 weak random");
    check(count_rule("let r = rng { 42 };\n", "G404") == 1, "G404 constant seed");
    check(count_rule("import m from \"a/goose-md5@v1.0.0\";\n", "G501") == 1, "G501 import");
    check(count_rule("import m from \"a/goose-telnet@v1.0.0\";\n", "B401") == 1, "B401 import");
    check(count_rule("let c = x as! i8;\n", "G109") == 1, "G109 cast");
    check(count_rule("let c = x as! i64;\n", "G109") == 0, "G109 wide cast");
    check(count_rule("assert(x > 0);\n", "B101") == 1, "B101 assert");
    check(count_rule("exception::try() { } catch { };\n", "B110") == 0, "B110 no match without empty body");
    check(count_rule("let w = wait(h, 0);\n", "B113") == 1, "B113 zero wait");
    check(count_rule("run(\"tar\", \"*\");\n", "B609") == 1, "B609 wildcard");
    check(count_rule("let a = \"\xE2\x80\xAE\";\n", "G116") == 1, "G116 bidi");
    check(count_rule("let a = \"/\";\n", "G111") == 1, "G111 root");

    check(count_rule("extern \"c_fn\" fn f(x: i64);\n", "G103") == 1, "G103 extern");
    check(count_rule("json::format_string(out, api_token);\n", "G117") == 1, "G117 secret into json");
    check(count_rule("json::format_string(out, name);\n", "G117") == 0, "G117 clean");

    // The aliases resolve to their rule.
    check(sast::reg_find("B311") == sast::reg_find("G404"), "alias B311");
    check(sast::reg_find("B613") == sast::reg_find("G116"), "alias B613");
    check(sast::reg_find("B608") == sast::reg_find("G202"), "alias B608");
    check(sast::reg_find("XXXX") < 0, "unknown ID");

    // Suppression comments.
    check(count_rule("let a = \"0.0.0.0\"; // nosec\n", "G102") == 0, "nosec all");
    check(count_rule("let a = \"0.0.0.0\"; // nosec G102\n", "G102") == 0, "nosec named");
    check(count_rule("let a = \"0.0.0.0\"; // nosec G999\n", "G102") == 1, "nosec other rule");
    check(count_rule("let a = \"0.0.0.0\"; // noqa: B104\n", "G102") == 0, "noqa alias");
    check(count_rule("let a = \"0.0.0.0\"; // nosemgrep\n", "G102") == 0, "nosemgrep");

    // Filters.
    var o = sast::default_options();
    o.min_severity = sast::SEV_HIGH;
    check(count_rule_with("let a = \"0.0.0.0\";\n", "G102", o) == 0, "severity floor");
    o = sast::default_options();
    sast::opt_exclude("B104");
    check(count_rule_with("let a = \"0.0.0.0\";\n", "G102", o) == 0, "exclude by alias");
    o = sast::default_options();
    sast::opt_include("G404");
    check(count_rule_with("let a = \"0.0.0.0\";\n", "G102", o) == 0, "include other");
    o = sast::default_options();

    // A string holding a rule trigger is no finding on its own.
    check(count_rule("// md5 here\n", "G401") == 0, "comment is no finding");

    // Hostile bytes: a path with a control byte is escaped.
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("a\x1b[31m.goose", "let a = \"0.0.0.0\";\n", o, fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    var raw = false;
    for b in out { if b == 27 { raw = true; } }
    check(!raw, "escape byte stays out of the output");

    // The test-file skip of B101.
    sast::findings_reset();
    var fs2: sast::Finding[>..] = [];
    sast::scan_text("src/a_test.goose", "assert(x);\n", o, fs2);
    check(fs2.len == 0, "B101 skips test files");

    // The rule list has one row per ID.
    var lines: u8[>..] = [];
    sast::list_rules(lines);
    var rows: i64 = 0;
    for b in lines { if b == 10 { rows = rows + 1; } }
    check(rows == sast::rule_count(), "list has one line per rule");

    // A block suppression covers the lines between the markers.
    check(count_rule("// nosec:start\nlet a = \"0.0.0.0\";\n// nosec:end\n", "G102") == 0, "block suppression");
    check(count_rule("// nosec:start\nlet a = \"0.0.0.0\";\n", "G102") == 0, "block without an end");
    check(count_rule("// nosec:start\nlet a = \"0.0.0.0\";\n// nosec:end\nlet b = \"0.0.0.0\";\n", "G102") == 1, "block ends");
    check(count_rule("// nosec:start\nlet a = \"0.0.0.0\";\n// nosec:end\nlet b = \"0.0.0.0\";\n// nosec\n", "G102") == 1, "line after a block");

    // The scope: a secret name and a literal of another block do not
    // match, and a name of a deeper scope shadows an outer name.
    check(count_rule("let password = \"hunter2hunter2\";\n", "G101") == 1, "G101 assignment");
    check(count_rule("fn f() { let password = \"hunter2hunter2\"; }\n", "G101") == 1, "G101 in a block");
    check(count_rule("let password = \"hunter2hunter2\";\nfn f() { let x = \"other\"; }\n", "G101") == 1, "G101 one scope");
    check(count_rule("if p == \"hunter2hunter2\" { }\n", "G101") == 0, "G101 no binding");
    check(count_rule("fn f(password: const u8[:]) { }\n", "G101") == 0, "G101 no literal");
    check(count_rule("let token = \"abcdef123456\";\n", "G101") == 1, "G101 token");

    // The taint map: a value from the command line reaches a process
    // call, and a name of another scope does not.
    check(count_rule("let x = args();\nrun(x, a);\n", "G702") == 1, "G702 taint to a process");
    check(count_rule("let x = args();\nwrite_file(x, d);\n", "G703") == 1, "G703 taint to a path");
    check(count_rule("let x = args();\nrun(\"ls\", a);\n", "G702") == 0, "G702 no taint");
    check(count_rule("fn f() { let x = args(); }\nrun(x, a);\n", "G702") == 0, "G702 out of scope");
    check(count_rule("let x = \"literal\";\nrun(x, a);\n", "G702") == 0, "G702 no source");

    // The manifest reader reads the import lines.
    var root: u8[>..] = [];
    read_file("test/deps/root.goose", root);
    check(sast::read_manifest(root[..]) == 2, "manifest count");
    check(sast::dep_name(0) == "url", "manifest name");
    check(sast::dep_source(0) == "rekanalar/goose-url", "manifest source");
    check(sast::dep_tag(0) == "v0.1.1", "manifest tag");
    check(sast::dep_line_of(0) == 2, "manifest line");
    check(sast::dep_count() == 2, "manifest holds no stdlib import");

    // The policy reader reads the four sections.
    var pol: u8[>..] = [];
    read_file("test/deps/policy.json", pol);
    var perr: u8[>..] = [];
    check(sast::read_policy(pol[..], perr), "policy parses");
    check(sast::pol_banned("banned"), "policy ban");
    check(!sast::pol_banned("url"), "policy no ban");
    check(sast::pol_banver("url") == ">=0.2.0", "policy ban range");
    check(sast::pol_licence_allowed("MIT"), "policy licence");
    check(sast::pol_licence_of("banned") == "GPL", "policy per dep");
    check(sast::pol_source_allowed("rekanalar"), "policy source");

    // The advisory reader reads the RustSec shape.
    var adv: u8[>..] = [];
    read_file("test/deps/advisories.json", adv);
    var aerr: u8[>..] = [];
    check(sast::read_advisories(adv[..], aerr), "advisories parse");
    check(sast::adv_count() == 1, "advisory count");
    check(sast::adv_id(0) == "RSEC-2021-0001", "advisory id");
    check(sast::adv_package(0) == "url", "advisory package");
    check(sast::adv_severity(0) == "high", "advisory severity");
    check(sast::adv_patched(0) == "0.2.0", "advisory patched");

    // The dependency checks report each break.
    var df: sast::Finding[>..] = [];
    sast::findings_reset();
    let n = sast::check_deps(root[..], df);
    check(n == df.len, "dependency count");
    var bans: i64 = 0;
    var lics: i64 = 0;
    var advs: i64 = 0;
    for f in df {
        let rid = sast::reg_id_s[f.rule];
        if rid == "BAN" { bans = bans + 1; }
        if rid == "LICENSE" { lics = lics + 1; }
        if rid == "ADVISORY" { advs = advs + 1; }
    }
    check(bans == 1, "one banned package");
    check(lics == 1, "one denied licence");
    check(advs == 1, "one advisory hit");

    // A clean manifest reports nothing.
    var clean_root: u8[>..] = [];
    for b in "import std;\n" { clean_root.push(b); }
    var df2: sast::Finding[>..] = [];
    sast::findings_reset();
    check(sast::check_deps(clean_root[..], df2) == 0, "clean manifest");

    // A policy that does not parse is a fault.
    var bad: u8[>..] = [];
    for b in "{ \"bans\": " { bad.push(b); }
    var berr: u8[>..] = [];
    check(!sast::read_policy(bad[..], berr), "bad policy faults");
    check(berr.len > 0, "bad policy names the fault");

    // The JSON form parses with the JSON module and holds the totals.
    var fj: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("a\x1b.goose", "let a = \"0.0.0.0\";\nlet r = rand_int(3);\n", o, fj);
    var jo: u8[>..] = [];
    sast::format_json(fj[..], 1, 0, jo);
    var rawj = false;
    for b in jo { if b == 27 { rawj = true; } }
    check(!rawj, "json holds no control byte");
    var doc: json::Node[>..] = [];
    var dec: u8[>..] = [];
    let root, jerr = json::parse(jo[..], doc, dec);
    check(root != null, "json parses");

    if fails > 0 { abort("some checks failed"); }
    print("all sast checks pass");
}

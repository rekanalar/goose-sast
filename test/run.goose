// The tests of the linter: each rule on a source text, the filters,
// the suppression comments and the escape of hostile bytes.
import std;
import sast from "..";

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

    if fails > 0 { abort("some checks failed"); }
    print("all sast checks pass");
}

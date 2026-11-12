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
    check(count_rule("listen(\"0.0.0.0\", p);\n", "G102") == 1, "G102 bind");
    check(count_rule("let a = \"0.0.0.0\";\n", "G102") == 0, "G102 no bind call");
    check(count_rule("let a = \"127.0.0.1\";\n", "G102") == 0, "G102 loopback");
    check(count_rule("put(out, \":86:\");\n", "G102") == 0, "G102 port tag text");
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
    check(count_rule("fn md5(x) { }\n", "G401") == 0, "G401 definition holds");
    check(count_rule("let sha1 = 5;\n", "G401") == 0, "G401 plain name holds");
    check(count_rule("fn rand_int(n) { }\n", "G404") == 0, "G404 definition holds");
    check(count_rule("let shuffle = 1;\n", "G404") == 0, "G404 plain name holds");
    check(count_rule("run(\"*\", a);\n", "B609") == 1, "B609 process call");
    check(count_rule("out.push(\"*\");\n", "B609") == 0, "B609 no process call");
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
    check(count_rule("read_file(\"/\", out);\n", "G111") == 1, "G111 root");
    check(count_rule("tmp.push('/');\n", "G111") == 0, "G111 separator");

    check(count_rule("write_file(\"a\", d);\n", "G104") == 1, "G104 dropped result");
    check(count_rule("let ok = write_file(\"a\", d);\n", "G104") == 0, "G104 bound result");
    check(count_rule("if file_exists(\"a\") { }\n", "G104") == 0, "G104 guarded result");

    check(count_rule("extern \"c_fn\" fn f(x: i64);\n", "G103") == 1, "G103 extern");
    check(count_rule("json::format_string(out, api_token);\n", "G117") == 1, "G117 secret into json");
    check(count_rule("json::format_string(out, name);\n", "G117") == 0, "G117 clean");

    // The aliases resolve to their rule.
    check(sast::reg_find("B311") == sast::reg_find("G404"), "alias B311");
    check(sast::reg_find("B613") == sast::reg_find("G116"), "alias B613");
    check(sast::reg_find("B608") == sast::reg_find("G202"), "alias B608");
    check(sast::reg_find("XXXX") < 0, "unknown ID");

    // Suppression comments.
    check(count_rule("listen(\"0.0.0.0\", p); // nosec\n", "G102") == 0, "nosec all");
    check(count_rule("listen(\"0.0.0.0\", p); // nosec G102\n", "G102") == 0, "nosec named");
    check(count_rule("listen(\"0.0.0.0\", p); // nosec G999\n", "G102") == 1, "nosec other rule");
    check(count_rule("listen(\"0.0.0.0\", p); // noqa: B104\n", "G102") == 0, "noqa alias");
    check(count_rule("listen(\"0.0.0.0\", p); // nosemgrep\n", "G102") == 0, "nosemgrep");

    // Filters.
    var o = sast::default_options();
    o.min_severity = sast::SEV_HIGH;
    check(count_rule_with("listen(\"0.0.0.0\", p);\n", "G102", o) == 0, "severity floor");
    o = sast::default_options();
    sast::opt_exclude("B104");
    check(count_rule_with("listen(\"0.0.0.0\", p);\n", "G102", o) == 0, "exclude by alias");
    o = sast::default_options();
    sast::opt_include("G404");
    check(count_rule_with("listen(\"0.0.0.0\", p);\n", "G102", o) == 0, "include other");
    o = sast::default_options();

    // A string holding a rule trigger is no finding on its own.
    check(count_rule("// md5 here\n", "G401") == 0, "comment is no finding");

    // Hostile bytes: a path with a control byte is escaped.
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("a\x1b[31m.goose", "listen(\"0.0.0.0\", p);\n", o, fs);
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
    check(count_rule("// nosec:start\nlisten(\"0.0.0.0\", p);\n// nosec:end\n", "G102") == 0, "block suppression");
    check(count_rule("// nosec:start\nlisten(\"0.0.0.0\", p);\n", "G102") == 0, "block without an end");
    check(count_rule("// nosec:start\nlisten(\"0.0.0.0\", p);\n// nosec:end\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "block ends");
    check(count_rule("// nosec:start\nlisten(\"0.0.0.0\", p);\n// nosec:end\nlisten(\"0.0.0.0\", p);\n// nosec\n", "G102") == 1, "line after a block");

    // The rule ranges: a disable of one rule holds that rule only.
    check(count_rule("// goose-sast:disable G101\nlet password = \"hunter2hunter2\";\nlisten(\"0.0.0.0\", p);\n// goose-sast:enable G101\n", "G101") == 0, "disable holds the rule");
    check(count_rule("// goose-sast:disable G101\nlet password = \"hunter2hunter2\";\nlisten(\"0.0.0.0\", p);\n// goose-sast:enable G101\n", "G102") == 1, "disable holds one rule only");
    check(count_rule("// goose-sast:disable\nlisten(\"0.0.0.0\", p);\n// goose-sast:enable\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "a disable with no list holds every rule");
    check(count_rule("// goose-sast:disable G101\nlet password = \"hunter2hunter2\";\n", "G101") == 0, "a disable with no enable reaches the end");
    check(count_rule("// goose-sast:disable G101\n// goose-sast:disable G102\nlisten(\"0.0.0.0\", p);\n// goose-sast:enable G102\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "one enable closes one range");
    check(count_rule("// goose-sast:disable BAD\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "an unknown ID opens no range");
    // nosec:start takes a rule list too.
    check(count_rule("// nosec:start G102\nlisten(\"0.0.0.0\", p);\n// nosec:end\nlet password = \"hunter2hunter2\";\n", "G102") == 0, "nosec start holds one rule");
    check(count_rule("// nosec:start G102\nlisten(\"0.0.0.0\", p);\n// nosec:end\nlet password = \"hunter2hunter2\";\n", "G101") == 1, "nosec start holds one rule only");

    // The SARIF form: it parses and holds the level and the region.
    var sf: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("a\x1b.goose", "let h = md5(x);\nlisten(\"0.0.0.0\", p);\n", o, sf);
    var so: u8[>..] = [];
    let want_line = sf[0].line;
    let want_col = sf[0].col;
    sast::format_sarif(sf[..], so);
    var raws = false;
    for c in so { if c == 27 { raws = true; } }
    check(!raws, "sarif holds no control byte");
    var sdoc: json::Node[>..] = [];
    var sdec: u8[>..] = [];
    let sroot, serr = json::parse(so[..], sdoc, sdec);
    check(sroot != null, "sarif parses");
    if sroot {
        let version, vok = json::as_string(json::member(sroot, "version"));
        check(vok && version == "2.1.0", "sarif version");
        let runs = json::member(sroot, "runs");
        var nres: i64 = -1;
        if runs {
            json::each(runs) { run =>
                let results = json::member(run, "results");
                var cnt: i64 = 0;
                if results {
                    json::each(results) { r2 =>
                        let rid, rok = json::as_string(json::member(r2, "ruleId"));
                        check(rok, "a result holds a rule id");
                        let lvl, lok = json::as_string(json::member(r2, "level"));
                        check(lvl == "error" || lvl == "warning" || lvl == "note", "a level of the mapping");
                        cnt = cnt + 1;
                    };
                }
                nres = cnt;
            };
        }
        check(nres == 2, "one result per finding");
        // The region of the first result holds the line and the column.
        var rline: i64 = -1;
        var rcol: i64 = -1;
        if runs {
            json::each(runs) { run =>
                let results = json::member(run, "results");
                if results {
                    json::each(results) { r2 =>
                        let locs = json::member(r2, "locations");
                        if locs && rline < 0 {
                            json::each(locs) { loc =>
                                let phys = json::member(loc, "physicalLocation");
                                if phys {
                                    let reg = json::member(phys, "region");
                                    if reg {
                                        let a, aok = json::as_i64(json::member(reg, "startLine"));
                                        let b, bok = json::as_i64(json::member(reg, "startColumn"));
                                        if aok && bok && rline < 0 { rline = a; rcol = b; }
                                    }
                                }
                            };
                        }
                    };
                }
            };
        }
        check(rline == want_line && rcol == want_col, "the region holds the line and the column");
    }

    // A run with no findings holds an empty results list.
    sast::findings_reset();
    var ef: sast::Finding[>..] = [];
    sast::scan_text("clean.goose", "let x = 1;\n", o, ef);
    check(ef.len == 0, "the clean text has no findings");
    var eo: u8[>..] = [];
    sast::format_sarif(ef[..], eo);
    var edoc: json::Node[>..] = [];
    var edec: u8[>..] = [];
    let eroot, eerr = json::parse(eo[..], edoc, edec);
    check(eroot != null, "the empty sarif parses");
    if eroot {
        let runs2 = json::member(eroot, "runs");
        if runs2 {
            json::each(runs2) { run =>
                let results = json::member(run, "results");
                var cnt2: i64 = -1;
                if results {
                    cnt2 = 0;
                    json::each(results) { r3 => cnt2 = cnt2 + 1; };
                }
                check(cnt2 == 0, "the empty sarif holds no result");
            };
        }
    }

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

    // The custom rules join the registry and run like built-in rules.
    var cr: u8[>..] = [];
    read_file("test/custom/rules.json", cr);
    var cerr: u8[>..] = [];
    check(sast::read_custom(cr[..], cerr), "custom rules parse");
    let base_rules = sast::rule_count();
    check(base_rules > 4, "the registry holds the built-in rows");
    var fco: sast::Finding[>..] = [];
    sast::findings_reset();
    var oco = sast::default_options();
    sast::scan_text("src/a.goose", "eval(x);\nlet s = \"a TODO here\";\n// FIXME soon\nrun_cmd(a);\nrun_cmds(a);\n", oco, fco);
    var co1: i64 = 0;
    var co2: i64 = 0;
    var co3: i64 = 0;
    var co4: i64 = 0;
    for f in fco {
        let rid = sast::reg_id_s[f.rule];
        if rid == "CO001" { co1 = co1 + 1; }
        if rid == "CO002" { co2 = co2 + 1; }
        if rid == "CO003" { co3 = co3 + 1; }
        if rid == "CO004" { co4 = co4 + 1; }
    }
    check(co1 == 1, "custom ident rule");
    check(co2 == 1, "custom string rule");
    check(co3 == 1, "custom comment rule");
    check(co4 == 1, "custom exact rule");

    // A custom finding obeys a suppression comment.
    var fcs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "eval(x); // nosec\n", oco, fcs);
    check(fcs.len == 0, "custom rule suppressed");

    // A bad custom file faults with a message.
    var badc: u8[>..] = [];
    for c in "{ \"rules\": [{\"id\":\"\"}] }" { badc.push(c); }
    var bce: u8[>..] = [];
    check(!sast::read_custom(badc[..], bce), "a custom rule with no id faults");
    check(bce.len > 0, "the fault names the rule");

    // A second file replaces the first.
    var one: u8[>..] = [];
    for c in "{ \"rules\": [{\"id\":\"CO009\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zz\"}] }" { one.push(c); }
    var oerr: u8[>..] = [];
    check(sast::read_custom(one[..], oerr), "the second file parses");
    sast::custom_reset();

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

    // The rule files of a run merge. The second file adds its rules to
    // the rules of the first file.
    var cr2: u8[>..] = [];
    read_file("test/custom/rules.json", cr2);
    var cerr2: u8[>..] = [];
    check(sast::read_custom(cr2[..], cerr2), "the first rule file parses");
    let before_merge = sast::rule_count();
    var more: u8[>..] = [];
    for c in "{ \"rules\": [{\"id\":\"CO010\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zz\"}] }" { more.push(c); }
    var merr: u8[>..] = [];
    check(sast::read_custom_more(more[..], merr), "the second rule file parses");
    check(sast::reg_find("CO001") >= 0, "the first file keeps its rules");
    check(sast::reg_find("CO010") >= 0, "the second file adds its rules");
    check(sast::rule_count() == before_merge + 1, "the registry holds both files");
    // A rule ID that two files hold is a fault.
    var dup: u8[>..] = [];
    for c in "{ \"rules\": [{\"id\":\"CO010\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zz\"}] }" { dup.push(c); }
    var derr: u8[>..] = [];
    check(!sast::read_custom_more(dup[..], derr), "a duplicate rule ID faults");
    check(derr.len > 0, "the fault names the rule");
    sast::custom_reset();

    // The config file holds the settings of a run.
    var co = sast::default_options();
    var cpol: u8[>..] = [];
    var cadv: u8[>..] = [];
    var crules: u8[>..] = [];
    var cerr3: u8[>..] = [];
    var ctext: u8[>..] = [];
    for c in "{ \"min_severity\": \"high\", \"min_confidence\": \"medium\", \"max_files\": 12, \"max_depth\": 3, \"policy\": \"p.json\", \"rules\": \"a.json,b.json\" }" { ctext.push(c); }
    check(sast::read_config(ctext[..], 0, co, cpol, cadv, crules, cerr3), "the config file parses");
    check(co.min_severity == sast::SEV_HIGH, "the config sets the severity");
    check(co.min_confidence == sast::CONF_MEDIUM, "the config sets the confidence");
    check(co.max_files == 12, "the config sets the file bound");
    check(co.max_depth == 3, "the config sets the depth bound");
    check(cpol[..] == "p.json", "the config names the policy file");
    check(crules[..] == "a.json,b.json", "the config names the rule files");
    // A setting that the command line set keeps its value.
    var co2 = sast::default_options();
    co2.min_severity = sast::SEV_LOW;
    var cpol2: u8[>..] = [];
    var cadv2: u8[>..] = [];
    var crules2: u8[>..] = [];
    var cerr4: u8[>..] = [];
    check(sast::read_config(ctext[..], sast::CFG_SEV, co2, cpol2, cadv2, crules2, cerr4), "the masked config parses");
    check(co2.min_severity == sast::SEV_LOW, "the flag wins over the config");
    check(co2.max_files == 12, "the config fills the other settings");
    // A key that the command does not know is a fault.
    var cbad: u8[>..] = [];
    for c in "{ \"nope\": 1 }" { cbad.push(c); }
    var cberr: u8[>..] = [];
    check(!sast::read_config(cbad[..], 0, co2, cpol2, cadv2, crules2, cberr), "an unknown key faults");
    check(cberr.len > 0, "the fault names the key");
    // A value of the wrong shape is a fault.
    var cbad2: u8[>..] = [];
    for c in "{ \"min_severity\": 4 }" { cbad2.push(c); }
    var cberr2: u8[>..] = [];
    check(!sast::read_config(cbad2[..], 0, co2, cpol2, cadv2, crules2, cberr2), "a wrong shape faults");
    check(cberr2.len > 0, "the fault names the key");
    // A severity of an unknown name is a fault.
    var cbad3: u8[>..] = [];
    for c in "{ \"min_severity\": \"huge\" }" { cbad3.push(c); }
    var cberr3: u8[>..] = [];
    check(!sast::read_config(cbad3[..], 0, co2, cpol2, cadv2, crules2, cberr3), "an unknown severity faults");
    check(cberr3.len > 0, "the fault names the key");
    // A rule ID that no rule carries is a fault.
    var cbad4: u8[>..] = [];
    for c in "{ \"exclude\": \"NOPE\" }" { cbad4.push(c); }
    var cberr4: u8[>..] = [];
    check(!sast::read_config(cbad4[..], 0, co2, cpol2, cadv2, crules2, cberr4), "an unknown rule ID faults");
    check(cberr4.len > 0, "the fault names the key");

    // A bad value of the config file is a fault even when a flag owns
    // the setting.
    var co3 = sast::default_options();
    var cp3: u8[>..] = [];
    var ca3: u8[>..] = [];
    var cr3: u8[>..] = [];
    var ce3: u8[>..] = [];
    var bt: u8[>..] = [];
    for c in "{ \"min_severity\": \"huge\" }" { bt.push(c); }
    check(!sast::read_config(bt[..], sast::CFG_SEV, co3, cp3, ca3, cr3, ce3), "a bad severity faults under a flag");
    // A negative bound is a fault.
    var nb: u8[>..] = [];
    var ne: u8[>..] = [];
    for c in "{ \"max_files\": -5 }" { nb.push(c); }
    check(!sast::read_config(nb[..], 0, co3, cp3, ca3, cr3, ne), "a negative file bound faults");
    check(ne.len > 0, "the fault names the key");
    // The confidence names are low, medium and high.
    check(sast::conf_of_name("critical") < 0, "critical is no confidence");
    check(sast::conf_of_name("high") == sast::CONF_HIGH, "high is a confidence");
    // The comma splitter drops an empty part.
    var parts: const u8[:][>..] = [];
    sast::split_list(",a,,b,", parts);
    check(parts.len == 2 && parts[0] == "a" && parts[1] == "b", "the splitter drops empty parts");
    // A key that the file holds twice is a fault.
    var dupkey: u8[>..] = [];
    for c in "{ \"min_severity\": \"low\", \"min_severity\": \"high\" }" { dupkey.push(c); }
    var dke: u8[>..] = [];
    check(!sast::read_config(dupkey[..], 0, co3, cp3, ca3, cr3, dke), "a key that comes twice faults");
    check(dke.len > 0, "the fault names the key");
    // A bound of more than nine digits is a fault.
    var big: u8[>..] = [];
    for c in "{ \"max_files\": 1234567890 }" { big.push(c); }
    var bge: u8[>..] = [];
    check(!sast::read_config(big[..], 0, co3, cp3, ca3, cr3, bge), "a bound of ten digits faults");
    check(bge.len > 0, "the fault names the key");

    // A file that is no regular file is not read.
    var rb: u8[>..] = [];
    check(!sast::read_bounded("test", 1024, rb), "a directory is no regular file");
    check(!sast::read_bounded("test/run.goose", 4, rb), "a file above the bound is not read");
    var okb: u8[>..] = [];
    check(sast::read_bounded("test/run.goose", 1000000, okb), "a regular file reads");
    check(okb.len > 0, "the read holds the bytes");

    // A rule file that faults leaves the registry as it was.
    var cr3: u8[>..] = [];
    read_file("test/custom/rules.json", cr3);
    var ce2: u8[>..] = [];
    check(sast::read_custom(cr3[..], ce2), "the rule file parses");
    let before_fault = sast::rule_count();
    var badrules: u8[>..] = [];
    for c in "{ \"rules\": [{\"id\":\"CO900\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"aa\"},{\"id\":\"CO901\",\"severity\":\"nope\",\"kind\":\"ident\",\"text\":\"bb\"}] }" { badrules.push(c); }
    var bre: u8[>..] = [];
    check(!sast::read_custom_more(badrules[..], bre), "a bad rule faults");
    check(sast::rule_count() == before_fault, "the faulty file leaves the registry as it was");
    check(sast::reg_find("CO900") < 0, "the faulty file leaves no rule");
    sast::custom_reset();

    // The next-line directive covers the line below it and no other.
    check(count_rule("// nosec:next\nlisten(\"0.0.0.0\", p);\n", "G102") == 0, "next-line directive covers the line below");
    check(count_rule("// goose-sast:disable-next-line\nlisten(\"0.0.0.0\", p);\n", "G102") == 0, "next-line long form");
    check(count_rule("// nosec:next G102\nlisten(\"0.0.0.0\", p);\n", "G102") == 0, "next-line with the rule");
    check(count_rule("// nosec:next B104\nlisten(\"0.0.0.0\", p);\n", "G102") == 0, "next-line with an alias");
    check(count_rule("// nosec:next G204\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "next-line with another rule reports");
    check(count_rule("// nosec:next G999\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "next-line with an unknown ID covers nothing");
    check(count_rule("// nosec:next\nlet a = 1;\nlisten(\"0.0.0.0\", p);\n", "G102") == 1, "next-line covers one line only");
    check(count_rule("listen(\"0.0.0.0\", p);\n// nosec:next\n", "G102") == 1, "next-line on the last line covers nothing");
    check(count_rule("listen(\"0.0.0.0\", p); // nosec:next\nlet a = 1;\n", "G102") == 1, "a trailing next-line comment covers nothing");
    check(count_rule("// nosec:next\nlet a = 1;\n// nosec:next\nlisten(\"0.0.0.0\", p);\n", "G102") == 0, "two directives cover two lines");

    // The unused report names the suppressions that silenced nothing.
    var ud = sast::default_options();
    ud.report_unused = true;
    var ufs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::unused_text.resize(0, 0);
    sast::scan_text("src/u.goose", "// nosec G102\nlet a = 1; // nosec G102,G204\nlisten(\"0.0.0.0\", p);\n// nosec:next G204\nlet b = 2;\n// nosec:next\nlet c = 3;\n// nosec:next G999\nlet d = 4;\n", ud, ufs);
    let rows = sast::unused_text[..];
    check(sast::has_word(rows, "src/u.goose:1: unused suppression [G102]"), "unused same-line ID");
    check(sast::has_word(rows, "src/u.goose:2: unused suppression [G102]"), "unused first ID of a list");
    check(sast::has_word(rows, "src/u.goose:2: unused suppression [G204]"), "unused second ID of a list");
    check(sast::has_word(rows, "src/u.goose:4: unused suppression [G204]"), "unused next-line ID");
    check(sast::has_word(rows, "src/u.goose:6: unused suppression\n"), "unused next-line with no list");
    check(!sast::has_word(rows, "G999"), "an ID no rule carries gives no row");
    sast::unused_text.resize(0, 0);
    sast::scan_text("src/v.goose", "// nosec:next\nlisten(\"0.0.0.0\", p);\n", ud, ufs);
    check(sast::unused_text.len == 0, "a used suppression gives no row");
    sast::scan_text("src/w.goose", "// nosec:start G102\nlisten(\"0.0.0.0\", p);\n// nosec:end\n// nosec:start G204\nlet a = 1;\n// nosec:end\n", ud, ufs);
    check(sast::has_word(sast::unused_text[..], "src/w.goose:4: unused suppression [G204]"), "unused block names its opening line");
    check(!sast::has_word(sast::unused_text[..], "src/w.goose:1:"), "a used block gives no row");
    ud.report_unused = false;
    sast::unused_text.resize(0, 0);
    sast::scan_text("src/x.goose", "// nosec G102\nlet a = 1;\n", ud, ufs);
    check(sast::unused_text.len == 0, "the report is off by default");

    // A call through the module name reports.
    check(count_rule("let a = md5::sum(x);\n", "G401") == 1, "qualified weak hash");
    check(count_rule("let a = sha1::digest(x);\n", "G401") == 1, "qualified sha1");
    check(count_rule("let a = other::sum(x);\n", "G401") == 0, "another module is no weak hash");
    check(count_rule("let a = md5::sum;\n", "G401") == 0, "a qualified name with no call");
    check(count_rule("let a = \"md5::sum(x)\"; // md5::sum(y)\n", "G401") == 0, "a string and a comment hold no call");
    check(count_rule("let a = md5::md5(x);\n", "G401") == 1, "a weak name behind a weak module reports once");
    check(count_rule("let a = rand::int(10);\n", "G404") == 1, "qualified weak random");
    check(count_rule("let a = crypto::int(10);\n", "G404") == 0, "another module is no weak random");

    // A name of one scope stays out of a sibling scope.
    let two_fn = "fn one() {\n    let cmd = args();\n    run(cmd);\n}\nfn two() {\n    let cmd = \"ls\";\n    run(cmd);\n}\n";
    check(count_rule(two_fn, "G702") == 1, "sibling functions: one finding");
    var sib_line: i64 = 0;
    var sfs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/s.goose", two_fn, sast::default_options(), sfs);
    for f in sfs { if f.rule == sast::reg_find("G702") { sib_line = f.line; } }
    check(sib_line == 3, "the finding sits in the function that holds the value");
    check(count_rule("fn a() {\n    let x = args();\n    if true {\n        run(x);\n    }\n}\n", "G702") == 1, "an outer name reaches an inner scope");
    check(count_rule("fn a() {\n    if true {\n        let x = args();\n    }\n    run(x);\n}\n", "G702") == 0, "an inner name does not reach the outer scope");
    check(count_rule("fn a() {\n    if true {\n        let x = args();\n    }\n    if true {\n        run(x);\n    }\n}\n", "G702") == 0, "two blocks of one function are siblings");
    check(count_rule("fn a() { let password = 1; }\nfn b() {\n    let k = \"abcdefgh\";\n}\n", "G101") == 0, "a secret name and a literal of two functions");

    // A regex rule reports every match with its line and column.
    var rxe: u8[>..] = [];
    var rxj: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO801\",\"severity\":\"high\",\"kind\":\"regex\",\"text\":\"TODO\\\\([a-z]+\\\\)\"}]}" { rxj.push(c); }
    check(sast::read_custom(rxj[..], rxe), "a regex rule file reads");
    check(count_rule("a\n  TODO(jim) x TODO(ann)\nnone\n", "CO801") == 2, "a regex rule reports both matches");
    check(count_rule("nothing here\n", "CO801") == 0, "a regex rule reports nothing without a match");
    var rfs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/r.goose", "a\n  TODO(jim) x TODO(ann)\n", sast::default_options(), rfs);
    var rl: i64 = 0;
    var rc: i64 = 0;
    for f in rfs { if f.rule == sast::reg_find("CO801") && f.col > 3 { rl = f.line; rc = f.col; } }
    check(rl == 2 && rc == 15, "a regex match holds the line and the column");
    var rxf: u8[>..] = [];
    var rxbad: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO802\",\"severity\":\"low\",\"kind\":\"regex\",\"text\":\"^abc\"}]}" { rxbad.push(c); }
    let rx_before = sast::rule_count();
    check(!sast::read_custom_more(rxbad[..], rxf), "an anchor is a fault");
    check(sast::has_word(rxf[..], "CO802"), "the fault names the rule");
    check(sast::rule_count() == rx_before, "a regex fault leaves the registry as it was");
    var rxbad2: u8[>..] = [];
    var rxf2: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO803\",\"severity\":\"low\",\"kind\":\"regex\",\"text\":\"a(\"}]}" { rxbad2.push(c); }
    check(!sast::read_custom_more(rxbad2[..], rxf2), "an expression that does not parse is a fault");
    sast::custom_reset();
    check(count_rule("TODO(jim)\n", "CO801") == 0, "the reset drops the regex rules");

    // Two regex rules report under their own id.
    var twoj: u8[>..] = [];
    var twoe: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO820\",\"severity\":\"low\",\"kind\":\"regex\",\"text\":\"TODO\"},{\"id\":\"CO821\",\"severity\":\"high\",\"kind\":\"regex\",\"text\":\"eval\\\\(\"}]}" { twoj.push(c); }
    check(sast::read_custom(twoj[..], twoe), "two regex rules read");
    check(count_rule("TODO(jim)\n", "CO820") == 1, "the first regex rule reports under its own id");
    check(count_rule("TODO(jim)\n", "CO821") == 0, "the first rule does not report under the second id");
    check(count_rule("eval(x)\n", "CO821") == 1, "the second regex rule reports under its own id");
    check(count_rule("eval(x)\n", "CO820") == 0, "the second rule does not report under the first id");
    sast::custom_reset();

    // An empty match reports once, at the start of the file.
    var emj: u8[>..] = [];
    var eme: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO810\",\"severity\":\"low\",\"kind\":\"regex\",\"text\":\"z*\"}]}" { emj.push(c); }
    check(sast::read_custom(emj[..], eme), "an empty-matching rule reads");
    check(count_rule("abc\ndef\n", "CO810") == 1, "an empty match reports once");
    // A run holds a bounded count of custom rules.
    var many: u8[>..] = [];
    for c in "{\"rules\":[" { many.push(c); }
    var mi: i64 = 0;
    while mi < 1100 {
        if mi > 0 { many.push(44); }
        format(many, "{\"id\":\"CM", mi, "\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zzq", mi, "\"}");
        mi = mi + 1;
    }
    for c in "]}" { many.push(c); }
    var mer: u8[>..] = [];
    check(!sast::read_custom(many[..], mer), "more than 1024 custom rules is a fault");
    check(sast::has_word(mer[..], "1024"), "the fault names the bound");
    // The matches of one file stop at the bound of the findings.
    var flood: u8[>..] = [];
    var fj: u8[>..] = [];
    var fe: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO811\",\"severity\":\"low\",\"kind\":\"regex\",\"text\":\"a\"}]}" { fj.push(c); }
    check(sast::read_custom(fj[..], fe), "the flood rule reads");
    var fi: i64 = 0;
    while fi < 70000 { flood.push(97); fi = fi + 1; }
    var ffs: sast::Finding[>..] = [];
    sast::findings_reset();
    let fkept = sast::scan_text("src/f.goose", flood[..], sast::default_options(), ffs);
    check(ffs.len == 65536 && fkept == 65536, "the matches of one file stop at the bound");
    sast::custom_reset();

    if fails > 0 { abort("some checks failed"); }
    print("all sast checks pass");
}

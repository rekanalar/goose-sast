// The tests of the group id_site.
namespace id_site_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import common;

// id_site_tests checks every site that names a registry row. The
// finding must carry the ID of the row, and the severity, the
// confidence and the CWE of that row.
fn id_site_tests() {
    common::site_src = [];
    common::site_id = [];
    common::site_kind = [];
    // The credential and file rules.
    common::site("let password = \"hunter2hunter2\";\n", "G101", 0);
    common::site("listen(\"0.0.0.0\", p);\n", "G102", 0);
    common::site("read_file(\"/\", out);\n", "G111", 0);
    common::site("write_file(\"/tmp/x\", d);\n", "G303", 0);
    common::site("read_file(p, out);\n", "G304", 0);
    common::site("f(0o777);\n", "G302", 0);
    common::site("write_file(\"a\", d, 0o644);\n", "G306", 0);
    common::site("make_dir(\"d\", 0o755);\n", "G301", 0);
    common::site("f(0o700);\n", "G302", 0);
    // The crypto rules.
    common::site("let h = md5(x);\n", "G401", 0);
    common::site("md5::sum(data);\n", "G401", 0);
    common::site("let r = rand_int(5);\n", "G404", 0);
    common::site("let r = rng { 42 };\n", "G404", 0);
    common::site("rand::int(10);\n", "G404", 0);
    // The language rules.
    common::site("let c = x as! i8;\n", "G109", 0);
    common::site("", "G116", 1);
    common::site("", "G116", 2);
    common::site("assert(x > 0);\n", "B101", 0);
    common::site("exception::try<u8[]>(load) { };\n", "B110", 0);
    common::site("let w = wait(h, 0);\n", "B113", 0);
    // The injection rules.
    common::site("let a = \"select \" + str(x);\n", "G201", 0);
    common::site("let a = \"select * from t where a=\" + x;\n", "G202", 0);
    common::site("let h = \"<b>\" + name;\n", "G203", 0);
    common::site("run(cmd, args);\n", "G204", 0);
    common::site("run(\"ls\", args);\n", "B607", 0);
    common::site("run(\"*\", a);\n", "B609", 0);
    // The import rules.
    common::site("import m from \"a/goose-md5@v1.0.0\";\n", "G501", 0);
    common::site("import m from \"a/goose-des@v1.0.0\";\n", "G502", 0);
    common::site("import m from \"a/goose-rc4@v1.0.0\";\n", "G503", 0);
    common::site("import m from \"a/goose-cgi@v1.0.0\";\n", "G504", 0);
    common::site("import m from \"a/goose-sha1@v1.0.0\";\n", "G505", 0);
    common::site("import m from \"a/goose-md4@v1.0.0\";\n", "G506", 0);
    common::site("import m from \"a/goose-ripemd160@v1.0.0\";\n", "G507", 0);
    common::site("import m from \"a/goose-telnet@v1.0.0\";\n", "B401", 0);
    common::site("import m from \"a/goose-ftp@v1.0.0\";\n", "B402", 0);
    common::site("import m from \"a/goose-pickle@v1.0.0\";\n", "B403", 0);
    common::site("import m from \"a/goose-process@v1.0.0\";\n", "B404", 0);
    common::check(common::site_src.len == 37, "the table of the sites holds 37 rows");

    var i: i64 = 0;
    while i < common::site_src.len {
        var idb: u8[>..] = [];
        common::put(idb, common::site_id[i]);
        let id = idb[..];
        let want = sast::reg_find(id);
        var buf: u8[>..] = [];
        if common::site_kind[i] > 0 {
            common::bidi_src(common::site_kind[i], buf);
        } else {
            common::put(buf, common::site_src[i]);
        }
        let src = buf[..];
        var o = sast::default_options();
        o.profile = sast::PROFILE_ALL;
        var fs: sast::Finding[>..] = [];
        sast::findings_reset();
        sast::scan_text("src/a.goose", src, o, fs);
        var found = false;
        for f in fs {
            if f.rule == want {
                found = true;
                common::check(f.sev == sast::reg_sev_s[want], "the severity of the site");
                common::check(f.conf == sast::reg_conf_s[want], "the confidence of the site");
                common::check(f.cwe == sast::reg_cwe_s[want], "the CWE of the site");
                break;
            }
        }
        var what: u8[>..] = [];
        common::put(what, "a site reports under another ID: ");
        common::put(what, id);
        if common::site_kind[i] == 1 { common::put(what, " kind 1"); }
        else if common::site_kind[i] == 2 { common::put(what, " kind 2"); }

        common::check(found, what[..]);
        i = i + 1;
    }
}

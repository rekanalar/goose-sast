// The tests of the group baseline.
namespace baseline_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import common;

fn baseline_tests() {
    // The hash of the empty text is the offset basis.
    common::check(sast::fnv64("") == 14695981039346656037, "fnv64 of the empty text");
    common::check(sast::fnv64("a") == sast::fnv64("a"), "fnv64 is stable");
    common::check(sast::fnv64("a") != sast::fnv64("b"), "fnv64 of different bytes");

    // A fingerprint is 48 bytes of lowercase hex.
    var fp: u8[>..] = [];
    sast::fingerprint("G101", "src/a.goose", "let password = 1;", fp);
    common::check(fp.len == 48, "a fingerprint is 48 bytes");
    var allhex = true;
    for b in fp {
        if !((b >= 48 && b <= 57) || (b >= 97 && b <= 102)) { allhex = false; }
    }
    common::check(allhex, "a fingerprint holds lowercase hex");

    // Two scans of the same text give the same fingerprint.
    var o = sast::default_options();
    o.profile = sast::PROFILE_ALL;
    var fs1: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter2\";\n", o, fs1);
    var fp1: u8[>..] = [];
    if fs1.len == 1 { common::put(fp1, sast::fp_of(fs1[0])); }
    var fs2: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter2\";\n", o, fs2);
    var fp2: u8[>..] = [];
    if fs2.len == 1 { common::put(fp2, sast::fp_of(fs2[0])); }
    common::check(fs1.len == 1 && fs2.len == 1, "the scan of the fixture gives one finding");
    common::check(fp1 == fp2, "the fingerprint is stable across scans");
    common::check(fp1.len == 48, "the fingerprint of a finding is 48 bytes");

    // A line above the finding does not change the fingerprint. A
    // change of the line of the finding does.
    var fs3: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let a = 1;\nlet password = \"hunter2hunter2\";\n", o, fs3);
    var fp3: u8[>..] = [];
    if fs3.len == 1 { common::put(fp3, sast::fp_of(fs3[0])); }
    var fs4: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter3\";\n", o, fs4);
    var fp4: u8[>..] = [];
    if fs4.len == 1 { common::put(fp4, sast::fp_of(fs4[0])); }
    if fs1.len == 1 && fs3.len == 1 && fs4.len == 1 {
        common::check(fp3 == fp1, "a line above keeps the fingerprint");
        common::check(fp4 != fp1, "a changed line changes the fingerprint");
    }
    var fs5: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/b.goose", "let password = \"hunter2hunter2\";\n", o, fs5);
    var fp5: u8[>..] = [];
    if fs5.len == 1 { common::put(fp5, sast::fp_of(fs5[0])); }
    if fs1.len == 1 && fs5.len == 1 {
        common::check(fp5 != fp1, "another path changes the fingerprint");
    }

    // The baseline set. The store holds the fingerprint of the last
    // scan, so the scan of the fixture runs again into a new list.
    var fsb: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter2\";\n", o, fsb);
    sast::baseline_reset();
    var set_err: u8[>..] = [];
    var one: u8[>..] = [];
    common::put(one, sast::fp_of(fsb[0]));
    one.push(10);
    common::check(sast::baseline_read(one[..], set_err), "the baseline read of one line");
    common::check(set_err.len == 0, "a good baseline writes no fault");
    common::check(sast::baseline_has(sast::fp_of(fsb[0])), "the set holds the fingerprint");
    var other: u8[>..] = [];
    sast::fingerprint("G102", "src/a.goose", "x", other);
    common::check(!sast::baseline_has(other[..]), "the set holds no other fingerprint");
    sast::baseline_reset();

    // An empty baseline is good and holds nothing.
    common::check(sast::baseline_read("", set_err), "an empty baseline is good");
    common::check(!sast::baseline_has(sast::fp_of(fsb[0])), "an empty baseline holds nothing");
    sast::baseline_reset();

    // A bad line is a fault with the line number.
    var bad: u8[>..] = [];
    common::put(bad, "zz\n");
    var e2: u8[>..] = [];
    common::check(!sast::baseline_read(bad[..], e2), "a short line is a fault");
    common::check(common::holds(e2[..], "line 1"), "the fault names the line");
    sast::baseline_reset();
    bad = [];
    common::put(bad, "0123456789abcdef0123456789abcdef0123456789abcde\n");
    e2 = [];
    common::check(!sast::baseline_read(bad[..], e2), "a long line is a fault");
    common::check(common::holds(e2[..], "line 1"), "the fault names the line");
    sast::baseline_reset();
    bad = [];
    common::put(bad, "0123456789ABCDEF0123456789abcdef0123456789abcdef\n");
    e2 = [];
    common::check(!sast::baseline_read(bad[..], e2), "an uppercase line is a fault");
    sast::baseline_reset();
    bad = [];
    common::put(bad, "0123456789abcdef0123456789abcdef0123456789abcde\r\n");
    e2 = [];
    common::check(!sast::baseline_read(bad[..], e2), "a line with a carriage return is a fault");
    sast::baseline_reset();
    bad = [];
    common::put(bad, "0123456789abcdef0123456789abcdef0123456789abcdef\nzz\n");
    e2 = [];
    common::check(!sast::baseline_read(bad[..], e2), "a bad line after a good one is a fault");
    common::check(common::holds(e2[..], "line 2"), "the fault names the second line");
    sast::baseline_reset();

    // The write of the baseline.
    var wr: u8[>..] = [];
    sast::baseline_write(fsb[..], wr);
    common::check(wr.len == 49, "the write holds one line of 48 bytes");
    common::check(wr[48] == 10, "the written line ends with a newline");
    common::check(wr[..48] == sast::fp_of(fsb[0]), "the written line is the fingerprint");

    // The JSON and SARIF fields hold the same text.
    var cj: u8[>..] = [];
    sast::format_json(fsb[..], 1, 0, cj);
    var cdoc: json::Node[>..] = [];
    var cdec: u8[>..] = [];
    let croot, cerr = json::parse(cj[..], cdoc, cdec);
    common::check(croot != null, "the JSON with a fingerprint parses");
    var jfpbuf: u8[>..] = [];
    if croot {
        let fl = json::member(croot, "findings");
        if fl { json::each(fl) { f1 => common::take_fp(f1, jfpbuf) }; }
    }
    let jfp = jfpbuf[..];
    common::check(jfp == sast::fp_of(fsb[0]), "the JSON holds the fingerprint");
    var cs: u8[>..] = [];
    sast::format_sarif(fsb[..], cs);
    var sdoc2: json::Node[>..] = [];
    var sdec2: u8[>..] = [];
    let sroot2, serr2 = json::parse(cs[..], sdoc2, sdec2);
    var sfpbuf: u8[>..] = [];
    if sroot2 {
        let runs2 = json::member(sroot2, "runs");
        if runs2 {
            json::each(runs2) { run =>
                let results_n = json::member(run, "results");
                if results_n { json::each(results_n) { res => common::take_sfp(res, sfpbuf) }; }
            };
        }
    }
    let sfp = sfpbuf[..];
    common::check(sfp == sast::fp_of(fsb[0]), "the SARIF holds the fingerprint");
    common::check(jfp == sfp, "the JSON and the SARIF hold the same fingerprint");
}

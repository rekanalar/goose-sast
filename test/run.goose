// The tests of the linter: each rule on a source text, the filters,
// the suppression comments and the escape of hostile bytes.
import std;
import os;
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
// The helper uses the strict profile, so every rule of the package
// runs. The default profile leaves three rules out.
fn count_rule(src: const u8[:], id: const u8[:]) -> i64 {
    var o = sast::default_options();
    o.profile = sast::PROFILE_STRICT;
    return count_rule_with(src, id, o);
}

// count_rule_profile gives how many findings of the rule ID the text
// yields under the given profile.
fn count_rule_profile(src: const u8[:], id: const u8[:], profile: i64) -> i64 {
    var o = sast::default_options();
    o.profile = profile;
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

// scan_tree scans the tree at the path under the given profile. It
// gives the count of the scanned files.
fn scan_tree(path: const u8[:], profile: i64) -> i64 {
    var o = sast::default_options();
    o.profile = profile;
    var fs: sast::Finding[>..] = [];
    sast::scan_reset();
    var budget = o.max_files;
    let scanned, skipped = sast::scan_dir_budget(path, o, fs, budget);
    return scanned;
}


// The shape tests build each value from pieces at run time, so that no
// file of the package holds a whole shape.
fn put(b: u8[>..]&, s: const u8[:]) { for c in s { b.push(c); } }

fn fill(b: u8[>..]&, c: u8, n: i64) {
    var i: i64 = 0;
    while i < n { b.push(c); i = i + 1; }
}

// s_count gives the findings of the rule ID under the default profile.
fn s_count(src: const u8[:], id: const u8[:]) -> i64 {
    return count_rule_profile(src, id, sast::PROFILE_DEFAULT);
}

// chk builds lead, a, b, n bytes of c and tail. It checks the count of
// the rule ID.
fn chk(lead: const u8[:], a: const u8[:], b: const u8[:], c: u8, n: i64,
       tail: const u8[:], id: const u8[:], want: i64, what: const u8[:]) {
    var buf: u8[>..] = [];
    put(buf, lead); put(buf, a); put(buf, b);
    fill(buf, c, n);
    put(buf, tail);
    check(s_count(buf[..], id) == want, what);
}

// holds reports whether the text holds the needle.
fn holds(hay: const u8[:], needle: const u8[:]) -> bool {
    return find(hay, needle) >= 0;
}

// shape_id gives the ID of the shape rule at the place i.
fn shape_id(i: i64) -> const u8[:] {
    if i == 0 { return "S101"; }
    if i == 1 { return "S102"; }
    if i == 2 { return "S103"; }
    return "S104";
}

// key_type gives the type word of a private key header and a space.
fn key_type(i: i64) -> const u8[:] {
    if i == 0 { return ""; }
    if i == 1 { return "RSA "; }
    if i == 2 { return "EC "; }
    if i == 3 { return "DSA "; }
    if i == 4 { return "OPENSSH "; }
    if i == 5 { return "PGP "; }
    return "ENCRYPTED ";
}

// no_secret checks that an output holds no secret and no run of its body.
fn no_secret(out: const u8[:], a: const u8[:], b: const u8[:], c: const u8[:]) {
    check(!holds(out, a) && !holds(out, b) && !holds(out, c), "no output holds a secret");
    check(!holds(out, "22222222") && !holds(out, "aaaaaaaa") && !holds(out, "bbbbbbbb"), "no output holds a body");
}

// self_scan gives the count of the shape findings in a file of the package.
fn self_scan(path: const u8[:]) -> i64 {
    var text: u8[>..] = [];
    read_file(path, text);
    var n: i64 = 0;
    var i: i64 = 0;
    while i < 4 { n = n + s_count(text[..], shape_id(i)); i = i + 1; }
    return n;
}

// count_words gives the words of the text. A space ends a word.
fn count_words(t: const u8[:]) -> i64 {
    var n: i64 = 0;
    var inside = false;
    for c in t {
        if c == 32 || c == 10 { inside = false; }
        else if !inside { inside = true; n = n + 1; }
    }
    return n;
}

// longest_sentence gives the most words in one sentence. A full stop
// ends a sentence. The count of the sentences goes to the second value.
fn longest_sentence(t: const u8[:]) -> i64, i64 {
    var most: i64 = 0;
    var sentences: i64 = 0;
    var start: i64 = 0;
    var i: i64 = 0;
    while i < t.len {
        if t[i] == 46 {
            let w = count_words(t[start..i]);
            if w > most { most = w; }
            sentences = sentences + 1;
            start = i + 1;
        }
        i = i + 1;
    }
    return most, sentences;
}

// shape_free reports whether the text holds none of the four shapes.
// The scan runs once and the four rules share it.
fn shape_free(text: const u8[:]) -> bool {
    var o = sast::default_options();
    o.profile = sast::PROFILE_ALL;
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", text, o, fs);
    for f in fs {
        if f.rule == sast::reg_find("S101") || f.rule == sast::reg_find("S102")
            || f.rule == sast::reg_find("S103") || f.rule == sast::reg_find("S104") {
            return false;
        }
    }
    return true;
}

// scan_profile gives the findings of the text under the profile.
fn scan_profile(src: const u8[:], profile: i64, fs: sast::Finding[>..]&) {
    var o = sast::default_options();
    o.profile = profile;
    sast::findings_reset();
    sast::scan_text("src/a.goose", src, o, fs);
}

// field_table checks the key names of a JSON object. The table lists
// the keys with a bar before and after each. Every key must be in the
// table, and the table must hold no key that the object lacks.
fn field_table(node: json::Node?, table: const u8[:], what: const u8[:]) {
    if !node { check(false, what); return; }
    var seen: i64 = 0;
    var unknown: i64 = 0;
    json::each(node) { child =>
        var pat: u8[>..] = [];
        pat.push(124); put(pat, child.key); pat.push(124);
        if find(table, pat[..]) < 0 { unknown = unknown + 1; }
        seen = seen + 1;
    };
    var listed: i64 = 0;
    for c in table { if c == 124 { listed = listed + 1; } }
    check(unknown == 0 && seen == listed - 1, what);
}

// shape_time gives the milliseconds that nl_build and rule_shapes take
// on the buffer, and the count of the findings.
fn shape_time(buf: const u8[:]) -> i64, i64 {
    var out: sast::Finding[>..] = [];
    let t0 = clock_ns();
    let n = sast::rule_shapes(buf, 0, out);
    return (clock_ns() - t0) / 1000000, n;
}

// metadata_tests checks the explanation, the examples and the contract
// of the output fields.
// baseline_tests check the fingerprint, the baseline set and the
// output fields.

// take_fp copies the fingerprint of a JSON finding into out.
fn take_fp(node: json::Node&, out: u8[>..]&) {
    let v, ok = json::as_string(json::member(node, "fingerprint"));
    if ok { put(out, v); }
}

// take_sfp copies the fingerprint of a SARIF result into out.
fn take_sfp(node: json::Node&, out: u8[>..]&) {
    let pf = json::member(node, "partialFingerprints");
    if pf {
        let v, ok = json::as_string(json::member(pf, "goose-sast/finding"));
        if ok { put(out, v); }
    }
}

fn baseline_tests() {
    // The hash of the empty text is the offset basis.
    check(sast::fnv64("") == 14695981039346656037, "fnv64 of the empty text");
    check(sast::fnv64("a") == sast::fnv64("a"), "fnv64 is stable");
    check(sast::fnv64("a") != sast::fnv64("b"), "fnv64 of different bytes");

    // A fingerprint is 48 bytes of lowercase hex.
    var fp: u8[>..] = [];
    sast::fingerprint("G101", "src/a.goose", "let password = 1;", fp);
    check(fp.len == 48, "a fingerprint is 48 bytes");
    var allhex = true;
    for b in fp {
        if !((b >= 48 && b <= 57) || (b >= 97 && b <= 102)) { allhex = false; }
    }
    check(allhex, "a fingerprint holds lowercase hex");

    // Two scans of the same text give the same fingerprint.
    var o = sast::default_options();
    o.profile = sast::PROFILE_ALL;
    var fs1: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter2\";\n", o, fs1);
    var fp1: u8[>..] = [];
    if fs1.len == 1 { put(fp1, sast::fp_of(fs1[0])); }
    var fs2: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter2\";\n", o, fs2);
    var fp2: u8[>..] = [];
    if fs2.len == 1 { put(fp2, sast::fp_of(fs2[0])); }
    check(fs1.len == 1 && fs2.len == 1, "the scan of the fixture gives one finding");
    check(fp1 == fp2, "the fingerprint is stable across scans");
    check(fp1.len == 48, "the fingerprint of a finding is 48 bytes");

    // A line above the finding does not change the fingerprint. A
    // change of the line of the finding does.
    var fs3: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let a = 1;\nlet password = \"hunter2hunter2\";\n", o, fs3);
    var fp3: u8[>..] = [];
    if fs3.len == 1 { put(fp3, sast::fp_of(fs3[0])); }
    var fs4: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter3\";\n", o, fs4);
    var fp4: u8[>..] = [];
    if fs4.len == 1 { put(fp4, sast::fp_of(fs4[0])); }
    if fs1.len == 1 && fs3.len == 1 && fs4.len == 1 {
        check(fp3 == fp1, "a line above keeps the fingerprint");
        check(fp4 != fp1, "a changed line changes the fingerprint");
    }
    var fs5: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/b.goose", "let password = \"hunter2hunter2\";\n", o, fs5);
    var fp5: u8[>..] = [];
    if fs5.len == 1 { put(fp5, sast::fp_of(fs5[0])); }
    if fs1.len == 1 && fs5.len == 1 {
        check(fp5 != fp1, "another path changes the fingerprint");
    }

    // The baseline set. The store holds the fingerprint of the last
    // scan, so the scan of the fixture runs again into a new list.
    var fsb: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", "let password = \"hunter2hunter2\";\n", o, fsb);
    sast::baseline_reset();
    var set_err: u8[>..] = [];
    var one: u8[>..] = [];
    put(one, sast::fp_of(fsb[0]));
    one.push(10);
    check(sast::baseline_read(one[..], set_err), "the baseline read of one line");
    check(set_err.len == 0, "a good baseline writes no fault");
    check(sast::baseline_has(sast::fp_of(fsb[0])), "the set holds the fingerprint");
    var other: u8[>..] = [];
    sast::fingerprint("G102", "src/a.goose", "x", other);
    check(!sast::baseline_has(other[..]), "the set holds no other fingerprint");
    sast::baseline_reset();

    // An empty baseline is good and holds nothing.
    check(sast::baseline_read("", set_err), "an empty baseline is good");
    check(!sast::baseline_has(sast::fp_of(fsb[0])), "an empty baseline holds nothing");
    sast::baseline_reset();

    // A bad line is a fault with the line number.
    var bad: u8[>..] = [];
    put(bad, "zz\n");
    var e2: u8[>..] = [];
    check(!sast::baseline_read(bad[..], e2), "a short line is a fault");
    check(holds(e2[..], "line 1"), "the fault names the line");
    sast::baseline_reset();
    bad = [];
    put(bad, "0123456789abcdef0123456789abcdef0123456789abcde\n");
    e2 = [];
    check(!sast::baseline_read(bad[..], e2), "a long line is a fault");
    check(holds(e2[..], "line 1"), "the fault names the line");
    sast::baseline_reset();
    bad = [];
    put(bad, "0123456789ABCDEF0123456789abcdef0123456789abcdef\n");
    e2 = [];
    check(!sast::baseline_read(bad[..], e2), "an uppercase line is a fault");
    sast::baseline_reset();
    bad = [];
    put(bad, "0123456789abcdef0123456789abcdef0123456789abcde\r\n");
    e2 = [];
    check(!sast::baseline_read(bad[..], e2), "a line with a carriage return is a fault");
    sast::baseline_reset();
    bad = [];
    put(bad, "0123456789abcdef0123456789abcdef0123456789abcdef\nzz\n");
    e2 = [];
    check(!sast::baseline_read(bad[..], e2), "a bad line after a good one is a fault");
    check(holds(e2[..], "line 2"), "the fault names the second line");
    sast::baseline_reset();

    // The write of the baseline.
    var wr: u8[>..] = [];
    sast::baseline_write(fsb[..], wr);
    check(wr.len == 49, "the write holds one line of 48 bytes");
    check(wr[48] == 10, "the written line ends with a newline");
    check(wr[..48] == sast::fp_of(fsb[0]), "the written line is the fingerprint");

    // The JSON and SARIF fields hold the same text.
    var cj: u8[>..] = [];
    sast::format_json(fsb[..], 1, 0, cj);
    var cdoc: json::Node[>..] = [];
    var cdec: u8[>..] = [];
    let croot, cerr = json::parse(cj[..], cdoc, cdec);
    check(croot != null, "the JSON with a fingerprint parses");
    var jfpbuf: u8[>..] = [];
    if croot {
        let fl = json::member(croot, "findings");
        if fl { json::each(fl) { f1 => take_fp(f1, jfpbuf) }; }
    }
    let jfp = jfpbuf[..];
    check(jfp == sast::fp_of(fsb[0]), "the JSON holds the fingerprint");
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
                if results_n { json::each(results_n) { res => take_sfp(res, sfpbuf) }; }
            };
        }
    }
    let sfp = sfpbuf[..];
    check(sfp == sast::fp_of(fsb[0]), "the SARIF holds the fingerprint");
    check(jfp == sfp, "the JSON and the SARIF hold the same fingerprint");
}

fn metadata_tests() {
    sast::docs_ensure();
    let n = sast::rule_count();

    // Every rule holds complete text in the limits of the contract.
    var i: i64 = 0;
    while i < n {
        let id = sast::reg_id_s[i];
        let ex = sast::doc_explain(i);
        let fl = sast::doc_flagged(i);
        let cl = sast::doc_clean(i);
        let fx = sast::doc_fix(i);
        check(ex.len > 0 && fl.len > 0 && cl.len > 0 && fx.len > 0, "a rule holds an empty metadata field");
        check(ex.len <= 1200, "an explanation is above 1200 bytes");
        check(fx.len <= 400 && fl.len <= 400 && cl.len <= 400, "a fix or an example is above 400 bytes");
        let wex, sex = longest_sentence(ex);
        let wfx, sfx = longest_sentence(fx);
        check(sex >= 1 && sex <= 6 && wex <= 20, "an explanation is above 6 sentences or 20 words");
        check(sfx >= 1 && sfx <= 2 && wfx <= 20, "a fix is not one or two sentences of 20 words");
        var alltxt: u8[>..] = [];
        put(alltxt, ex); alltxt.push(10); put(alltxt, fl); alltxt.push(10); put(alltxt, cl); alltxt.push(10); put(alltxt, fx);
        var printable = true;
        for c in alltxt { if (c < 32 && c != 10) || c > 126 { printable = false; } }
        check(printable, "metadata holds a byte outside printable ASCII");
        check(shape_free(alltxt[..]), "metadata holds a whole secret shape");
        i = i + 1;
    }
    check(n == 57, "the registry holds 57 rules");

    // The IDs of this release are pinned.
    var ids: u8[>..] = [];
    i = 0;
    while i < n { ids.push(124); put(ids, sast::reg_id_s[i]); i = i + 1; }
    ids.push(124);
    check(ids[..] == "|G101|G102|G109|G116|G201|G202|G203|G204|G301|G302|G303|G304|G306|G401|G404|G111|B101|B110|B113|B607|B609|G501|G502|G503|G504|G505|G506|G507|B401|B402|B403|B404|B405|B406|B407|B408|B409|B410|B411|B412|B413|B414|G103|G104|G602|G702|G703|BAN|LICENSE|SOURCE|ADVISORY|G117|B415|S101|S102|S103|S104|", "the rule IDs of the release changed");

    // The flagged example fires its rule and the clean example does not.
    var exempt_count: i64 = 0;
    i = 0;
    while i < n {
        var idb: u8[>..] = [];
        put(idb, sast::reg_id_s[i]);
        let id = idb[..];
        if sast::doc_is_exempt(i) {
            exempt_count = exempt_count + 1;
        } else {
            var fx: u8[>..] = [];
            sast::doc_fixture(i, fx);
            check(count_rule_profile(fx[..], id, sast::PROFILE_ALL) >= 1, id);
            var cb: u8[>..] = [];
            put(cb, sast::doc_clean(i));
            check(count_rule_profile(cb[..], id, sast::PROFILE_ALL) == 0, id);
        }
        i = i + 1;
    }
    check(exempt_count == 14, "the list of rules with no scanned example changed");
    check(sast::doc_reason(sast::reg_find("BAN")).len > 0, "an exempt rule names its reason");
    check(sast::doc_reason(sast::reg_find("G602")).len > 0, "an exempt rule names its reason");

    // The precision of the default profile on the fixture set.
    var true_hits: i64 = 0;
    var false_hits: i64 = 0;
    i = 0;
    while i < n {
        var idb: u8[>..] = [];
        put(idb, sast::reg_id_s[i]);
        let id = idb[..];
        if !sast::doc_is_exempt(i) && sast::reg_tier_s[i] == sast::TIER_DEFAULT {
            var fx: u8[>..] = [];
            sast::doc_fixture(i, fx);
            var got: sast::Finding[>..] = [];
            scan_profile(fx[..], sast::PROFILE_DEFAULT, got);
            for f in got { if f.rule == i { true_hits = true_hits + 1; } else { false_hits = false_hits + 1; } }
            var got2: sast::Finding[>..] = [];
            var cb: u8[>..] = [];
            put(cb, sast::doc_clean(i));
            scan_profile(cb[..], sast::PROFILE_DEFAULT, got2);
            false_hits = false_hits + got2.len;
        }
        i = i + 1;
    }
    print("precision of the default profile on the fixture set: ", true_hits, " true, ", false_hits, " false");
    check(true_hits > 0 && false_hits == 0, "the precision of the fixture set is below 1.0");

    // The flag -explain: the text form.
    var tx: u8[>..] = [];
    check(sast::explain_rule("G304", false, tx), "explain G304");
    let t_id = find(tx[..], "ID:");
    let t_sev = find(tx[..], "Severity:");
    let t_conf = find(tx[..], "Confidence:");
    let t_cwe = find(tx[..], "CWE:");
    let t_pro = find(tx[..], "Profile:");
    let t_exp = find(tx[..], "Explanation:");
    let t_fl = find(tx[..], "Flagged:");
    let t_cl = find(tx[..], "Clean:");
    let t_fix = find(tx[..], "Fix:");
    check(t_id == 0 && t_sev > t_id && t_conf > t_sev && t_cwe > t_conf && t_pro > t_cwe
          && t_exp > t_pro && t_fl > t_exp && t_cl > t_fl && t_fix > t_cl, "the explain labels and their order");
    check(holds(tx[..], "G304") && holds(tx[..], "strict") && holds(tx[..], " 22"), "explain G304 values");
    check(tx.len <= 4096, "an explain answer is above 4096 bytes");

    // A rule with no CWE.
    var ta: u8[>..] = [];
    check(sast::explain_rule("ADVISORY", false, ta), "explain ADVISORY");
    check(holds(ta[..], "CWE:") && holds(ta[..], "none"), "a rule with no CWE says none");
    var tj: u8[>..] = [];
    check(sast::explain_rule("ADVISORY", true, tj), "explain ADVISORY as JSON");
    var jdoc: json::Node[>..] = [];
    var jdec: u8[>..] = [];
    let jroot, jerr = json::parse(tj[..], jdoc, jdec);
    check(jroot != null, "the explain JSON parses");
    field_table(jroot, "|id|severity|confidence|cwe|profile|explanation|flagged|clean|fix|", "the explain JSON keys");
    if jroot {
        let cw, cwok = json::as_i64(json::member(jroot, "cwe"));
        check(cwok && cw == 0, "the explain JSON cwe of a rule with none is 0");
    }

    // Every rule answers in the bound.
    i = 0;
    while i < n {
        var one: u8[>..] = [];
        check(sast::explain_rule(sast::reg_id_s[i], false, one) && one.len <= 4096, "an explain answer is above 4096 bytes");
        var onej: u8[>..] = [];
        check(sast::explain_rule(sast::reg_id_s[i], true, onej) && onej.len <= 4096, "an explain JSON answer is above 4096 bytes");
        i = i + 1;
    }

    // Unknown IDs.
    var bad: u8[>..] = [];
    check(!sast::explain_rule("g304", false, bad), "explain a lower case ID");
    check(!sast::explain_rule("", false, bad), "explain an empty ID");
    check(!sast::explain_rule("S105", false, bad), "explain an ID that is free");
    check(!sast::explain_rule("G304G304G304G304G", false, bad), "explain an ID of 17 bytes");
    check(sast::explain_known("g304") == -1 && sast::explain_known("") == -1, "explain_known of a bad ID");
    check(sast::explain_known("G304") == sast::reg_find("G304"), "explain_known of a good ID");
    check(bad.len == 0, "a bad ID writes no answer");

    // The secret rules print no whole shape.
    var si: i64 = 0;
    while si < 4 {
        var so2: u8[>..] = [];
        check(sast::explain_rule(shape_id(si), false, so2), "explain a shape rule");
        check(shape_free(so2[..]), "the explain text of a shape rule holds a whole shape");
        si = si + 1;
    }

    // The JSON and SARIF fields.
    var cf: sast::Finding[>..] = [];
    sast::findings_reset();
    scan_profile("let h = md5::sum(x);\n", sast::PROFILE_ALL, cf);
    check(cf.len >= 1, "the contract run has a finding");
    var cj: u8[>..] = [];
    sast::format_json(cf[..], 1, 0, cj);
    var cdoc: json::Node[>..] = [];
    var cdec: u8[>..] = [];
    let croot, cerr = json::parse(cj[..], cdoc, cdec);
    check(croot != null, "the contract JSON parses");
    field_table(croot, "|findings|totals|scanned|skipped|left_out|", "the JSON run fields");
    if croot {
        field_table(json::member(croot, "totals"), "|low|medium|high|critical|", "the JSON totals fields");
        let fl = json::member(croot, "findings");
        if fl {
            json::each(fl) { f1 =>
                field_table(f1, "|rule|severity|confidence|cwe|file|line|column|message|fingerprint|", "the JSON finding fields");
            };
        }
    }
    var cs: u8[>..] = [];
    sast::format_sarif(cf[..], cs);
    var sdoc2: json::Node[>..] = [];
    var sdec2: u8[>..] = [];
    let sroot2, serr2 = json::parse(cs[..], sdoc2, sdec2);
    check(sroot2 != null, "the contract SARIF parses");
    field_table(sroot2, "|$schema|version|runs|", "the SARIF run fields");
    if sroot2 {
        let runs2 = json::member(sroot2, "runs");
        if runs2 {
            json::each(runs2) { run =>
                let tool = json::member(run, "tool");
                let driver = json::member(tool, "driver");
                field_table(driver, "|name|version|rules|", "the SARIF driver fields");
                let dv, dvok = json::as_string(json::member(driver, "version"));
                check(dvok && dv == sast::VERSION, "the SARIF driver version is the package version");
                var s101_tag = false;
                var adv_tag = false;
                var rules_seen: i64 = 0;
                let rules_n = json::member(driver, "rules");
                if !rules_n { check(false, "the SARIF driver holds no rules"); return; }
                json::each(rules_n) { rule =>
                    field_table(rule, "|id|shortDescription|fullDescription|help|properties|", "the SARIF rule fields");
                    let rid, rok = json::as_string(json::member(rule, "id"));
                    let tags = json::member(json::member(rule, "properties"), "tags");
                    var cwe_tags: i64 = 0;
                    var wants: bool = false;
                    if tags { json::each(tags) { t =>
                        let tv, tok = json::as_string(t);
                        if tok && find(tv, "external/cwe/cwe-") == 0 { cwe_tags = cwe_tags + 1; }
                        if tok && tv == "external/cwe/cwe-798" { wants = true; }
                    }; }
                    if rok && rid == "S101" && wants { s101_tag = true; }
                    if rok && rid == "ADVISORY" && cwe_tags == 0 { adv_tag = true; }
                    rules_seen = rules_seen + 1;
                };
                check(s101_tag, "the SARIF rule S101 holds the CWE tag");
                check(adv_tag, "the SARIF rule ADVISORY holds no CWE tag");
                check(rules_seen == sast::rule_count(), "the SARIF rules list holds every registry rule");
                let results_n = json::member(run, "results");
                if results_n { json::each(results_n) { res =>
                    field_table(res, "|ruleId|level|message|locations|partialFingerprints|", "the SARIF result fields");
                }; }
            };
        }
    }

    // The README names every key of the field tables.
    var rd2: u8[>..] = [];
    read_file("README.md", rd2);
    let rdt = rd2[..];
    let keys = "findings totals scanned skipped left_out rule severity confidence cwe file line column message low medium high critical id profile explanation flagged clean fix name version rules shortDescription fullDescription help properties ruleId level locations";
    var ks: i64 = 0;
    while ks < keys.len {
        var ke = ks;
        while ke < keys.len && keys[ke] != 32 { ke = ke + 1; }
        var pat: u8[>..] = [];
        pat.push(96); put(pat, keys[ks..ke]); pat.push(96);
        check(find(rdt, pat[..]) >= 0, "the README names a field key");
        ks = ke + 1;
    }

    // The README import line names the version of the package.
    var rd: u8[>..] = [];
    read_file("README.md", rd);
    let imp = find(rd[..], "goose-sast@v");
    check(imp >= 0, "the README holds an import line");
    if imp >= 0 {
        let from = imp + 12;
        var to = from;
        while to < rd.len && rd[to] != 34 { to = to + 1; }
        check(rd[from..to] == sast::VERSION, "the README version equals the package version");
    }
}

fn main() {
    check(count_rule("let password = \"hunter2hunter2\";\n", "G101") == 1, "G101 literal");
    check(count_rule("let name = \"hello\";\n", "G101") == 0, "G101 clean");
    check(count_rule("listen(\"0.0.0.0\", p);\n", "G102") == 1, "G102 bind");
    check(count_rule("listen(Cfg { a: 1 }, \"0.0.0.0\");\n", "G102") == 1, "G102 brace value before the literal");
    check(count_rule("f(); { listen(\"x\"); } let a = \"0.0.0.0\";\n", "G102") == 0, "G102 closed block is no call");
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
    check(count_rule("exception::try<u8[]>(load) { };\n", "B110") == 1, "B110 an empty catch block");
    check(count_rule("exception::try<u8[]>(load) { e => print(e); };\n", "B110") == 0, "B110 a catch block with a call");
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

    // The profiles. The default profile leaves three rules out, and the
    // walk leaves out the test and the example directories it finds.
    check(count_rule_profile("read_file(p, out);\n", "G304",
        sast::PROFILE_DEFAULT) == 0, "the default profile leaves G304 out");
    check(count_rule_profile("write_file(\"a\", d);\n", "G104",
        sast::PROFILE_DEFAULT) == 0, "the default profile leaves G104 out");
    check(count_rule_profile("assert(x > 0);\n", "B101",
        sast::PROFILE_DEFAULT) == 0, "the default profile leaves B101 out");
    check(count_rule_profile("read_file(p, out);\n", "G304",
        sast::PROFILE_STRICT) == 1, "the strict profile holds G304");
    check(count_rule_profile("write_file(\"a\", d);\n", "G104",
        sast::PROFILE_STRICT) == 1, "the strict profile holds G104");
    check(count_rule_profile("assert(x > 0);\n", "B101",
        sast::PROFILE_STRICT) == 1, "the strict profile holds B101");
    check(count_rule_profile("let a = md5::sum(x);\n", "G401",
        sast::PROFILE_DEFAULT) == 1, "a rule of the default tier runs");

    // The walk leaves out the test and the example directories that it
    // finds below the target. The profile all reads them.
    check(scan_tree("test/walk", sast::PROFILE_DEFAULT) == 1,
        "the default profile leaves out the two directories");
    check(sast::dirs_left_out == 2, "the count of the left-out directories");
    check(scan_tree("test/walk", sast::PROFILE_STRICT) == 1,
        "the strict profile leaves out the two directories");
    check(scan_tree("test/walk", sast::PROFILE_ALL) == 3,
        "the profile all reads the two directories");
    // A target that the user names is always scanned.
    check(scan_tree("test/walk/test", sast::PROFILE_DEFAULT) == 1,
        "a target named test is scanned");
    check(scan_tree("test/walk/examples", sast::PROFILE_DEFAULT) == 1,
        "a target named examples is scanned");

    // The summary holds the clause of the left-out directories, and the
    // JSON holds the same count under the key left_out.
    var sum: u8[>..] = [];
    sast::scan_reset();
    var sfs: sast::Finding[>..] = [];
    var sbudget: i64 = 4096;
    let sscanned, sskipped = sast::scan_dir_budget("test/walk", sast::default_options(), sfs, sbudget);
    sast::format_summary(sfs.len, sscanned, sskipped, sum);
    check(sast::has_word(sum[..], "director(ies) left out by the profile, use -profile all"),
        "the summary holds the clause");
    check(sast::has_word(sum[..], "2 director(ies)"), "the clause holds the count");
    var jout: u8[>..] = [];
    sast::format_json(sfs[..], sscanned, sskipped, jout);
    check(sast::has_word(jout[..], "\"left_out\":2"), "the JSON holds the count");
    // A run that leaves out nothing holds no clause.
    var s2: u8[>..] = [];
    sast::scan_reset();
    var s2fs: sast::Finding[>..] = [];
    var s2budget: i64 = 4096;
    let s2scanned, s2skipped = sast::scan_dir_budget("test/walk/a.goose", sast::default_options(), s2fs, s2budget);
    sast::format_summary(s2fs.len, s2scanned, s2skipped, s2);
    if sast::has_word(s2[..], "left out") {
        check(false, "a run that leaves out nothing holds no clause");
    }

    // The rule list names the profile that first holds each rule.
    var lr: u8[>..] = [];
    sast::list_rules(lr);
    check(sast::has_word(lr[..], "G304 sev=2 conf=3 cwe=22 profile=strict"),
        "the list marks the strict rules");
    check(sast::has_word(lr[..], "G102 sev=2 conf=3 cwe=605 profile=default"),
        "the list marks the default rules");

    // A function declaration is no call.
    check(count_rule("fn run(cmd: const u8[:], args: u8[:]) -> i64 {\n", "G204") == 0, "G204 a declaration");
    check(count_rule("fn read_file(p: const u8[:]) {\n", "G304") == 0, "G304 a declaration");
    check(count_rule("let r = run(cmd, args);\n", "G204") == 1, "G204 a call");

    // The G102 rule needs a bind call.
    check(count_rule("listen(\"0.0.0.0\", p);\n", "G102") == 1, "G102 listen");
    check(count_rule("serve(\"::\", p);\n", "G102") == 1, "G102 serve");
    check(count_rule("s.Accept(\"[::]\");\n", "G102") == 1, "G102 accept");
    check(count_rule("listen(\n\"0.0.0.0\", p);\n", "G102") == 1, "G102 call over two lines");
    check(count_rule("out.append(\"::\");\n", "G102") == 0, "G102 no bind call");
    check(count_rule("let a = \"0.0.0.0\";\n", "G102") == 0, "G102 no call");
    check(count_rule("listen(\"127.0.0.1\", p);\n", "G102") == 0, "G102 loopback");
    check(count_rule("listen(host_or(\"0.0.0.0\"), p);\n", "G102") == 0, "G102 nested call");

    // The G101 rule needs a credential-like literal.
    check(count_rule("let password = \"admin\";\n", "G101") == 1, "G101 strong name");
    check(count_rule("let token = \"abcdef123456\";\n", "G101") == 1, "G101 token");
    check(count_rule("let pass = \"hunter2hunter2\";\n", "G101") == 1, "G101 weak name");
    check(count_rule("let pass = \" \";\n", "G101") == 0, "G101 a space");
    check(count_rule("let pass = \"abc1234\";\n", "G101") == 0, "G101 a short weak literal");
    check(count_rule("let pass = \"aaaaaaaa\";\n", "G101") == 0, "G101 one repeated byte");
    check(count_rule("let pass = \"abc defgh\";\n", "G101") == 0, "G101 a space inside");
    check(count_rule("let password = \"a\";\n", "G101") == 0, "G101 one byte");
    check(count_rule("let password = \"\";\n", "G101") == 0, "G101 an empty literal");
    check(count_rule("let password = \"  \";\n", "G101") == 0, "G101 spaces only");
    check(count_rule("let bypass = \"abcdefgh\";\n", "G101") == 1, "G101 bypass is weak");
    check(count_rule("let key = \"abcdefgh\";\n", "G101") == 0, "G101 key is no name");
    // A strong name reports a body with a space inside. A body of spaces
    // only reports nothing.
    check(count_rule("let password = \"my pass\";\n", "G101") == 1, "G101 strong name, space inside");
    check(count_rule("let token = \"  x\";\n", "G101") == 1, "G101 strong name, leading spaces");
    check(count_rule("let secret = \"   \";\n", "G101") == 0, "G101 strong name, spaces only");

    // A custom rule runs in every profile.
    var cpj: u8[>..] = [];
    var cpe: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"CO830\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zzprof\"}]}" { cpj.push(c); }
    check(sast::read_custom(cpj[..], cpe), "the profile rule reads");
    check(count_rule_profile("zzprof(x);\n", "CO830", sast::PROFILE_DEFAULT) == 1, "a custom rule runs in the default profile");
    check(count_rule_profile("zzprof(x);\n", "CO830", sast::PROFILE_STRICT) == 1, "a custom rule runs in the strict profile");
    check(count_rule_profile("zzprof(x);\n", "CO830", sast::PROFILE_ALL) == 1, "a custom rule runs in the profile all");
    sast::custom_reset();

    // The built-in secret shapes S101 to S104.
    sast::opt_reset();
    chk("let k = \"", "AK", "IA", 50, 16, "\";\n", "S101", 1, "S101 AKIA");
    chk("let k = \"", "AS", "IA", 50, 16, "\";\n", "S101", 1, "S101 ASIA");
    chk("let k = \"", "AB", "IA", 50, 16, "\";\n", "S101", 1, "S101 ABIA");
    chk("let k = \"", "AC", "CA", 50, 16, "\";\n", "S101", 1, "S101 ACCA");
    chk("// the key ", "AK", "IA", 50, 16, "\n", "S101", 1, "S101 in a comment");
    chk("let k = r\"", "AK", "IA", 50, 16, "\";\n", "S101", 1, "S101 in a raw string");
    chk("", "AK", "IA", 50, 16, "", "S101", 1, "S101 at byte 0 at the end of the file");
    chk("let k = \"", "AK", "IA", 50, 15, "\";\n", "S101", 0, "S101 body too short");
    chk("let k = \"", "AK", "IA", 50, 17, "\";\n", "S101", 0, "S101 body too long");
    chk("let k = \"x", "AK", "IA", 50, 16, "\";\n", "S101", 0, "S101 letter before");
    chk("let k = \"9", "AK", "IA", 50, 16, "\";\n", "S101", 0, "S101 digit before");
    chk("let k = \"", "ak", "ia", 50, 16, "\";\n", "S101", 0, "S101 lower case prefix");
    chk("let k = \"", "AK", "IB", 50, 16, "\";\n", "S101", 0, "S101 wrong prefix");
    chk("let k = \"", "AK", "IA", 48, 16, "\";\n", "S101", 0, "S101 body byte 0");
    chk("let k = \"", "AK", "IA", 56, 16, "\";\n", "S101", 0, "S101 body byte 8");
    chk("let k = \"", "AK", "IA", 97, 16, "\";\n", "S101", 0, "S101 lower case body");
    // The documented example key of the AWS documentation reports.
    var ex: u8[>..] = [];
    put(ex, "let k = \"AK"); put(ex, "IAIOSFODNN7"); put(ex, "EXAMPLE\";\n");
    check(s_count(ex[..], "S101") == 1, "S101 documented example key");
    // A byte above 127 before the prefix is a boundary.
    var hi: u8[>..] = [];
    hi.push(195); put(hi, "AK"); put(hi, "IA"); fill(hi, 50, 16);
    check(s_count(hi[..], "S101") == 1, "S101 after a byte above 127");
    // Two keys on one line, and CRLF line ends.
    var two: u8[>..] = [];
    put(two, "a(\"AK"); put(two, "IA"); fill(two, 50, 16); put(two, "\", \"AK"); put(two, "IA"); fill(two, 51, 16); put(two, "\");\n");
    check(s_count(two[..], "S101") == 2, "S101 two keys on a line");
    var crlf: u8[>..] = [];
    crlf.push(120); crlf.push(13); crlf.push(10);
    put(crlf, "let k = \"AK"); put(crlf, "IA"); fill(crlf, 50, 16); put(crlf, "\";"); crlf.push(13); crlf.push(10);
    check(s_count(crlf[..], "S101") == 1, "S101 with CRLF line ends");
    // A key split across a line break is no key.
    var split: u8[>..] = [];
    put(split, "AK"); put(split, "IA"); fill(split, 50, 8); split.push(10); fill(split, 50, 8);
    check(s_count(split[..], "S101") == 0, "S101 split across a line break");
    // The position is the first byte of the key.
    var pos: sast::Finding[>..] = [];
    var pb: u8[>..] = [];
    put(pb, "let k = \"AK"); put(pb, "IA"); fill(pb, 50, 16); put(pb, "\";\n");
    sast::findings_reset();
    sast::scan_text("src/a.goose", pb[..], sast::default_options(), pos);
    var found_pos = false;
    for f in pos { if f.rule == sast::reg_find("S101") && f.line == 1 && f.col == 10 { found_pos = true; } }
    check(found_pos, "S101 line and column of the first byte");

    // S102: the five classic prefixes, the fine-grained prefix.
    let gl = "pousr";
    var gi: i64 = 0;
    while gi < 5 {
        chk("let t = \"gh", gl[gi..gi + 1], "_", 97, 36, "\";\n", "S102", 1, "S102 classic prefix");
        gi = gi + 1;
    }
    chk("let t = \"gh", "p", "_", 97, 35, "\";\n", "S102", 0, "S102 classic 35 bytes");
    chk("let t = \"gh", "p", "_", 97, 37, "\";\n", "S102", 0, "S102 classic 37 bytes");
    chk("let t = \"x", "gh", "p_", 97, 36, "\";\n", "S102", 0, "S102 letter before");
    chk("let t = \"_", "gh", "p_", 97, 36, "\";\n", "S102", 1, "S102 classic after an underscore");
    chk("let t = \"gh", "p", "_", 45, 36, "\";\n", "S102", 0, "S102 body byte outside the class");
    chk("let t = \"GH", "P", "_", 97, 36, "\";\n", "S102", 0, "S102 upper case prefix");
    chk("let t = \"gh", "z", "_", 97, 36, "\";\n", "S102", 0, "S102 wrong prefix letter");
    chk("let t = \"github", "_", "pat_", 97, 82, "\";\n", "S102", 1, "S102 fine-grained");
    chk("let t = \"github", "_", "pat_", 95, 82, "\";\n", "S102", 1, "S102 fine-grained underscore body");
    chk("let t = \"github", "_", "pat_", 97, 81, "\";\n", "S102", 0, "S102 fine-grained 81 bytes");
    chk("let t = \"github", "_", "pat_", 97, 83, "\";\n", "S102", 0, "S102 fine-grained 83 bytes");
    chk("let t = \"_github", "_", "pat_", 97, 82, "\";\n", "S102", 0, "S102 underscore before the fine-grained prefix");
    // The example token of the GitHub documentation reports.
    var gx: u8[>..] = [];
    put(gx, "let t = \"gh"); put(gx, "p_"); put(gx, "16C7e42F292c6912E7710c838347Ae178B4a\";\n");
    check(s_count(gx[..], "S102") == 1, "S102 documented example token");
    // A classic token inside a fine-grained token gives two findings.
    var nest: u8[>..] = [];
    put(nest, "let t = \"github"); put(nest, "_pat_"); put(nest, "gh"); put(nest, "p_"); fill(nest, 65, 36); put(nest, "_"); fill(nest, 66, 41); put(nest, "\";\n");
    check(s_count(nest[..], "S102") == 2, "S102 classic token inside a fine-grained token");

    // S103.
    let sl = "bparsx";
    var si: i64 = 0;
    while si < 5 {
        chk("let t = \"xox", sl[si..si + 1], "-", 97, 10, "\";\n", "S103", 1, "S103 prefix, 10 bytes");
        chk("let t = \"xox", sl[si..si + 1], "-", 45, 72, "\";\n", "S103", 1, "S103 prefix, 72 bytes");
        si = si + 1;
    }
    chk("let t = \"xapp", "-", "1-", 97, 10, "\";\n", "S103", 1, "S103 app, 10 bytes");
    chk("let t = \"xapp", "-", "1-", 97, 80, "\";\n", "S103", 1, "S103 app, 80 bytes");
    chk("let t = \"xox", "b", "-", 97, 73, "\";\n", "S103", 0, "S103 bot body of 73 bytes");
    chk("let t = \"xapp", "-", "1-", 97, 81, "\";\n", "S103", 0, "S103 app body of 81 bytes");
    chk("let t = \"xox", "o", "-", 97, 20, "\";\n", "S103", 0, "S103 prefix with the letter o");
    chk("let t = \"xox", "b", "-", 97, 9, "\";\n", "S103", 0, "S103 body of 9 bytes");
    chk("let t = \"xox", "z", "-", 97, 20, "\";\n", "S103", 0, "S103 wrong prefix");
    chk("let t = \"x", "xo", "xb-", 97, 20, "\";\n", "S103", 0, "S103 letter before");
    chk("let t = \"xapp", "-", "x-", 97, 20, "\";\n", "S103", 0, "S103 app without a digit");
    // Two tokens joined by one hyphen are one long body: one finding.
    var hy: u8[>..] = [];
    put(hy, "a(\"xox"); put(hy, "b-"); fill(hy, 97, 12); put(hy, "-xox"); put(hy, "b-"); fill(hy, 98, 12); put(hy, "\");\n");
    check(s_count(hy[..], "S103") == 1, "S103 two tokens joined by a hyphen");
    // Two tokens in two strings are two findings.
    var hy2: u8[>..] = [];
    put(hy2, "a(\"xox"); put(hy2, "b-"); fill(hy2, 97, 12); put(hy2, "\", \"xox"); put(hy2, "b-"); fill(hy2, 98, 12); put(hy2, "\");\n");
    check(s_count(hy2[..], "S103") == 2, "S103 two tokens in two strings");

    // S104.
    var ti: i64 = 0;
    while ti < 7 {
        var hd: u8[>..] = [];
        put(hd, "let p = \"-----"); put(hd, "BEGIN "); put(hd, key_type(ti)); put(hd, "PRIVATE"); put(hd, " KEY"); put(hd, "-----\";\n");
        check(s_count(hd[..], "S104") == 1, "S104 header");
        ti = ti + 1;
    }
    var pg: u8[>..] = [];
    put(pg, "// -----"); put(pg, "BEGIN PGP "); put(pg, "PRIVATE KEY"); put(pg, " BLOCK-----\n");
    check(s_count(pg[..], "S104") == 1, "S104 PGP block in a comment");
    var blk: u8[>..] = [];
    put(blk, "let p = \"-----"); put(blk, "BEGIN RSA "); put(blk, "PRIVATE KEY"); put(blk, " BLOCK-----\";\n");
    check(s_count(blk[..], "S104") == 0, "S104 block text after a type word other than PGP");
    var pub: u8[>..] = [];
    put(pub, "let p = \"-----"); put(pub, "BEGIN PUBLIC"); put(pub, " KEY-----\";\n");
    check(s_count(pub[..], "S104") == 0, "S104 public key header");
    var d4: u8[>..] = [];
    put(d4, "let p = \"----"); put(d4, "BEGIN "); put(d4, "PRIVATE KEY"); put(d4, "-----\";\n");
    check(s_count(d4[..], "S104") == 0, "S104 four dashes");
    var sp4: u8[>..] = [];
    put(sp4, "-----"); put(sp4, "BEGIN "); sp4.push(10); put(sp4, "PRIVATE KEY"); put(sp4, "-----\n");
    check(s_count(sp4[..], "S104") == 0, "S104 split across a line break");

    // The registry rows, the filters and the suppression.
    var ri: i64 = 0;
    while ri < 4 {
        check(sast::reg_find(shape_id(ri)) >= 0, "the shape rule is in the registry");
        check(count_rule_profile("x\n", shape_id(ri), sast::PROFILE_ALL) == 0, "the shape rule is clean on clean text");
        ri = ri + 1;
    }
    var all4: u8[>..] = [];
    put(all4, "a(\"AK"); put(all4, "IA"); fill(all4, 50, 16); put(all4, "\");\n");
    put(all4, "b(\"gh"); put(all4, "p_"); fill(all4, 97, 36); put(all4, "\");\n");
    put(all4, "c(\"xox"); put(all4, "b-"); fill(all4, 97, 12); put(all4, "\");\n");
    put(all4, "d(\"-----"); put(all4, "BEGIN "); put(all4, "PRIVATE KEY"); put(all4, "-----\");\n");
    var pi: i64 = 0;
    while pi < 3 {
        var n4: i64 = 0;
        var qi: i64 = 0;
        while qi < 4 { n4 = n4 + count_rule_profile(all4[..], shape_id(qi), pi); qi = qi + 1; }
        check(n4 == 4, "the four shapes report in every profile");
        pi = pi + 1;
    }
    var oi = sast::default_options();
    sast::opt_include("S102");
    check(count_rule_with(all4[..], "S102", oi) == 1 && count_rule_with(all4[..], "S101", oi) == 0, "include S102 leaves S102 only");
    var ox = sast::default_options();
    sast::opt_exclude("S101");
    check(count_rule_with(all4[..], "S101", ox) == 0, "exclude S101");
    check(count_rule_with(all4[..], "S102", ox) == 1, "exclude S101 keeps S102");
    sast::opt_reset();
    var sup: u8[>..] = [];
    put(sup, "a(\"AK"); put(sup, "IA"); fill(sup, 50, 16); put(sup, "\"); // nosec S101\n");
    check(s_count(sup[..], "S101") == 0, "a shape in a suppression range stays out");
    // A config file with an exclude of S101 removes S101.
    var cfo = sast::default_options();
    var cfp: u8[>..] = [];
    var cfa: u8[>..] = [];
    var cfr: u8[>..] = [];
    var cfe: u8[>..] = [];
    var cft: u8[>..] = [];
    put(cft, "{ \"exclude\": \"S101\" }");
    check(sast::read_config(cft[..], 0, cfo, cfp, cfa, cfr, cfe), "the config with exclude S101 reads");
    check(count_rule_with(all4[..], "S101", cfo) == 0, "config exclude S101");
    sast::opt_reset();
    // A custom rule with a built-in ID is a fault, and S105 is free.
    var cs: u8[>..] = [];
    var cse: u8[>..] = [];
    put(cs, "{\"rules\":[{\"id\":\"S101\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zz\"}]}");
    check(!sast::read_custom(cs[..], cse), "a custom rule with the ID S101 is a fault");
    check(holds(cse[..], "S101"), "the fault names the ID");
    sast::custom_reset();
    var cs5: u8[>..] = [];
    var cse5: u8[>..] = [];
    put(cs5, "{\"rules\":[{\"id\":\"S105\",\"severity\":\"low\",\"kind\":\"ident\",\"text\":\"zz\"}]}");
    check(sast::read_custom(cs5[..], cse5), "a custom rule with the ID S105 loads");
    sast::custom_reset();
    // -list-rules holds the four rows.
    var lrs: u8[>..] = [];
    sast::list_rules(lrs);
    var li: i64 = 0;
    while li < 4 { check(holds(lrs[..], shape_id(li)), "list_rules holds the shape rule"); li = li + 1; }

    // No output channel holds a byte of a match.
    var secrets: u8[>..] = [];
    put(secrets, "AK"); put(secrets, "IA"); fill(secrets, 50, 16);
    var sc2: u8[>..] = [];
    put(sc2, "gh"); put(sc2, "p_"); fill(sc2, 97, 36);
    var sc3: u8[>..] = [];
    put(sc3, "xox"); put(sc3, "b-"); fill(sc3, 98, 12);
    var channel_fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", all4[..], sast::default_options(), channel_fs);
    var ctext: u8[>..] = [];
    var cjson: u8[>..] = [];
    var csarif: u8[>..] = [];
    sast::format_text(channel_fs[..], ctext);
    sast::format_json(channel_fs[..], 1, 0, cjson);
    sast::format_sarif(channel_fs[..], csarif);
    check(channel_fs.len == 4, "the channel check has four findings");
    no_secret(ctext[..], secrets[..], sc2[..], sc3[..]);
    no_secret(cjson[..], secrets[..], sc2[..], sc3[..]);
    no_secret(csarif[..], secrets[..], sc2[..], sc3[..]);

    // The hostile files stay inside the time bound.
    var hostile: u8[>..] = [];
    fill(hostile, 65, 10000000);
    let ms_a, n_a = shape_time(hostile[..]);
    check(n_a == 0 && ms_a < 4000, "10 MB of the letter A");
    var hostile2: u8[>..] = [];
    var hi2: i64 = 0;
    while hi2 < 2500000 { put(hostile2, "AKIA"); hi2 = hi2 + 1; }
    let ms_b, n_b = shape_time(hostile2[..]);
    check(ms_b < 2000, "2.5 million repeats of AKIA");
    var hostile3: u8[>..] = [];
    put(hostile3, "xox"); put(hostile3, "b-"); fill(hostile3, 45, 1000000);
    let ms_c, n_c = shape_time(hostile3[..]);
    check(n_c == 0 && ms_c < 1000, "xoxb- and a million hyphens");
    // More matches than the bound: the cap holds.
    var many: u8[>..] = [];
    var mi: i64 = 0;
    while mi < 70000 {
        put(many, " AK"); put(many, "IA"); fill(many, 50, 16);
        mi = mi + 1;
    }
    var mfs: sast::Finding[>..] = [];
    sast::nl_build(many[..]);
    let nm = sast::rule_shapes(many[..], 0, mfs);
    check(nm <= sast::MAX_FILE_MATCHES && nm > 0, "the cap of the matches of one file");

    // The package files hold no whole shape.
    check(self_scan("test/run.goose") == 0, "test/run.goose holds a whole shape");
    check(self_scan("README.md") == 0, "README.md holds a whole shape");
    check(self_scan("examples/rules/secrets.json") == 0, "secrets.json holds a whole shape");
    check(self_scan("examples/rules/regex.json") == 0, "regex.json holds a whole shape");
    check(self_scan("examples/samples/secrets.goose") == 0, "the sample holds a whole shape");

    metadata_tests();
    baseline_tests();

    if fails > 0 { abort("some checks failed"); }
    print("all sast checks pass");
}

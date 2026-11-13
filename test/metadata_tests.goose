// The tests of the group metadata.
namespace metadata_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import sast_checks;

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
        sast_checks::check(ex.len > 0 && fl.len > 0 && cl.len > 0 && fx.len > 0, "a rule holds an empty metadata field");
        sast_checks::check(ex.len <= 1200, "an explanation is above 1200 bytes");
        sast_checks::check(fx.len <= 400 && fl.len <= 400 && cl.len <= 400, "a fix or an example is above 400 bytes");
        let wex, sex = sast_checks::longest_sentence(ex);
        let wfx, sfx = sast_checks::longest_sentence(fx);
        sast_checks::check(sex >= 1 && sex <= 6 && wex <= 20, "an explanation is above 6 sentences or 20 words");
        sast_checks::check(sfx >= 1 && sfx <= 2 && wfx <= 20, "a fix is not one or two sentences of 20 words");
        var alltxt: u8[>..] = [];
        sast_checks::put(alltxt, ex); alltxt.push(10); sast_checks::put(alltxt, fl); alltxt.push(10); sast_checks::put(alltxt, cl); alltxt.push(10); sast_checks::put(alltxt, fx);
        var printable = true;
        for c in alltxt { if (c < 32 && c != 10) || c > 126 { printable = false; } }
        sast_checks::check(printable, "metadata holds a byte outside printable ASCII");
        sast_checks::check(sast_checks::shape_free(alltxt[..]), "metadata holds a whole secret shape");
        i = i + 1;
    }
    sast_checks::check(n == 50, "the registry holds 50 rules");

    // The IDs of this release are pinned.
    var ids: u8[>..] = [];
    i = 0;
    while i < n { ids.push(124); sast_checks::put(ids, sast::reg_id_s[i]); i = i + 1; }
    ids.push(124);
    sast_checks::check(ids[..] == "|G101|G102|G109|G116|G201|G202|G203|G204|G301|G302|G303|G304|G306|G401|G404|G111|B101|B110|B113|B607|B609|G501|G502|G503|G504|G505|G506|G507|B401|B402|B403|B404|B410|B411|G103|G104|G602|G702|G703|BAN|LICENSE|SOURCE|ADVISORY|G117|S101|S102|S103|S104|PIN|CPART|", "the rule IDs of the release changed");

    // The flagged example fires its rule and the clean example does not.
    var exempt_count: i64 = 0;
    i = 0;
    while i < n {
        var idb: u8[>..] = [];
        sast_checks::put(idb, sast::reg_id_s[i]);
        let id = idb[..];
        if sast::doc_is_exempt(i) {
            exempt_count = exempt_count + 1;
        } else {
            var fx: u8[>..] = [];
            sast::doc_fixture(i, fx);
            sast_checks::check(sast_checks::count_rule_profile(fx[..], id, sast::PROFILE_ALL) >= 1, id);
            var cb: u8[>..] = [];
            sast_checks::put(cb, sast::doc_clean(i));
            sast_checks::check(sast_checks::count_rule_profile(cb[..], id, sast::PROFILE_ALL) == 0, id);
        }
        i = i + 1;
    }
    sast_checks::check(exempt_count == 6, "the list of rules with no scanned example changed");
    sast_checks::check(sast::doc_reason(sast::reg_find("BAN")).len > 0, "an exempt rule names its reason");

    // The precision of the default profile on the fixture set.
    var true_hits: i64 = 0;
    var false_hits: i64 = 0;
    i = 0;
    while i < n {
        var idb: u8[>..] = [];
        sast_checks::put(idb, sast::reg_id_s[i]);
        let id = idb[..];
        if !sast::doc_is_exempt(i) && sast::reg_tier_s[i] == sast::TIER_DEFAULT {
            var fx: u8[>..] = [];
            sast::doc_fixture(i, fx);
            var got: sast::Finding[>..] = [];
            sast_checks::scan_profile(fx[..], sast::PROFILE_DEFAULT, got);
            for f in got { if f.rule == i { true_hits = true_hits + 1; } else { false_hits = false_hits + 1; } }
            var got2: sast::Finding[>..] = [];
            var cb: u8[>..] = [];
            sast_checks::put(cb, sast::doc_clean(i));
            sast_checks::scan_profile(cb[..], sast::PROFILE_DEFAULT, got2);
            false_hits = false_hits + got2.len;
        }
        i = i + 1;
    }
    print("precision of the default profile on the fixture set: ", true_hits, " true, ", false_hits, " false");
    sast_checks::check(true_hits > 0 && false_hits == 0, "the precision of the fixture set is below 1.0");

    // The flag -explain: the text form.
    var tx: u8[>..] = [];
    sast_checks::check(sast::explain_rule("G304", false, tx), "explain G304");
    let t_id = find(tx[..], "ID:");
    let t_sev = find(tx[..], "Severity:");
    let t_conf = find(tx[..], "Confidence:");
    let t_cwe = find(tx[..], "CWE:");
    let t_pro = find(tx[..], "Profile:");
    let t_exp = find(tx[..], "Explanation:");
    let t_fl = find(tx[..], "Flagged:");
    let t_cl = find(tx[..], "Clean:");
    let t_fix = find(tx[..], "Fix:");
    sast_checks::check(t_id == 0 && t_sev > t_id && t_conf > t_sev && t_cwe > t_conf && t_pro > t_cwe
          && t_exp > t_pro && t_fl > t_exp && t_cl > t_fl && t_fix > t_cl, "the explain labels and their order");
    sast_checks::check(sast_checks::holds(tx[..], "G304") && sast_checks::holds(tx[..], "strict") && sast_checks::holds(tx[..], " 22"), "explain G304 values");
    sast_checks::check(tx.len <= 4096, "an explain answer is above 4096 bytes");

    // A rule with no CWE.
    var ta: u8[>..] = [];
    sast_checks::check(sast::explain_rule("ADVISORY", false, ta), "explain ADVISORY");
    sast_checks::check(sast_checks::holds(ta[..], "CWE:") && sast_checks::holds(ta[..], "none"), "a rule with no CWE says none");
    var tj: u8[>..] = [];
    sast_checks::check(sast::explain_rule("ADVISORY", true, tj), "explain ADVISORY as JSON");
    var jdoc: json::Node[>..] = [];
    var jdec: u8[>..] = [];
    let jroot, jerr = json::parse(tj[..], jdoc, jdec);
    sast_checks::check(jroot != null, "the explain JSON parses");
    sast_checks::field_table(jroot, "|id|severity|confidence|cwe|profile|explanation|flagged|clean|fix|", "the explain JSON keys");
    if jroot {
        let cw, cwok = json::as_i64(json::member(jroot, "cwe"));
        sast_checks::check(cwok && cw == 0, "the explain JSON cwe of a rule with none is 0");
    }

    // Every rule answers in the bound.
    i = 0;
    while i < n {
        var one: u8[>..] = [];
        sast_checks::check(sast::explain_rule(sast::reg_id_s[i], false, one) && one.len <= 4096, "an explain answer is above 4096 bytes");
        var onej: u8[>..] = [];
        sast_checks::check(sast::explain_rule(sast::reg_id_s[i], true, onej) && onej.len <= 4096, "an explain JSON answer is above 4096 bytes");
        i = i + 1;
    }

    // Unknown IDs.
    var bad: u8[>..] = [];
    sast_checks::check(!sast::explain_rule("g304", false, bad), "explain a lower case ID");
    sast_checks::check(!sast::explain_rule("", false, bad), "explain an empty ID");
    sast_checks::check(!sast::explain_rule("S105", false, bad), "explain an ID that is free");
    sast_checks::check(!sast::explain_rule("G304G304G304G304G", false, bad), "explain an ID of 17 bytes");
    sast_checks::check(sast::explain_known("g304") == -1 && sast::explain_known("") == -1, "explain_known of a bad ID");
    sast_checks::check(sast::explain_known("G304") == sast::reg_find("G304"), "explain_known of a good ID");
    sast_checks::check(bad.len == 0, "a bad ID writes no answer");

    // The secret rules print no whole shape.
    var si: i64 = 0;
    while si < 4 {
        var so2: u8[>..] = [];
        sast_checks::check(sast::explain_rule(sast_checks::shape_id(si), false, so2), "explain a shape rule");
        sast_checks::check(sast_checks::shape_free(so2[..]), "the explain text of a shape rule holds a whole shape");
        si = si + 1;
    }

    // The JSON and SARIF fields.
    var cf: sast::Finding[>..] = [];
    sast::findings_reset();
    sast_checks::scan_profile("let h = md5::sum(x);\n", sast::PROFILE_ALL, cf);
    sast_checks::check(cf.len >= 1, "the contract run has a finding");
    var cj: u8[>..] = [];
    sast::format_json(cf[..], 1, 0, cj);
    var cdoc: json::Node[>..] = [];
    var cdec: u8[>..] = [];
    let croot, cerr = json::parse(cj[..], cdoc, cdec);
    sast_checks::check(croot != null, "the contract JSON parses");
    sast_checks::field_table(croot, "|findings|totals|scanned|skipped|left_out|", "the JSON run fields");
    if croot {
        sast_checks::field_table(json::member(croot, "totals"), "|low|medium|high|critical|", "the JSON totals fields");
        let fl = json::member(croot, "findings");
        if fl {
            json::each(fl) { f1 =>
                sast_checks::field_table(f1, "|rule|severity|confidence|cwe|file|line|column|message|fingerprint|", "the JSON finding fields");
            };
        }
    }
    var cs: u8[>..] = [];
    sast::format_sarif(cf[..], cs);
    var sdoc2: json::Node[>..] = [];
    var sdec2: u8[>..] = [];
    let sroot2, serr2 = json::parse(cs[..], sdoc2, sdec2);
    sast_checks::check(sroot2 != null, "the contract SARIF parses");
    sast_checks::field_table(sroot2, "|$schema|version|runs|", "the SARIF run fields");
    if sroot2 {
        let runs2 = json::member(sroot2, "runs");
        if runs2 {
            json::each(runs2) { run =>
                let tool = json::member(run, "tool");
                let driver = json::member(tool, "driver");
                sast_checks::field_table(driver, "|name|version|rules|", "the SARIF driver fields");
                let dv, dvok = json::as_string(json::member(driver, "version"));
                sast_checks::check(dvok && dv == sast::VERSION, "the SARIF driver version is the package version");
                var s101_tag = false;
                var adv_tag = false;
                var rules_seen: i64 = 0;
                let rules_n = json::member(driver, "rules");
                if !rules_n { sast_checks::check(false, "the SARIF driver holds no rules"); return; }
                json::each(rules_n) { rule =>
                    sast_checks::field_table(rule, "|id|shortDescription|fullDescription|help|properties|", "the SARIF rule fields");
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
                sast_checks::check(s101_tag, "the SARIF rule S101 holds the CWE tag");
                sast_checks::check(adv_tag, "the SARIF rule ADVISORY holds no CWE tag");
                sast_checks::check(rules_seen == sast::rule_count(), "the SARIF rules list holds every registry rule");
                let results_n = json::member(run, "results");
                if results_n { json::each(results_n) { res =>
                    sast_checks::field_table(res, "|ruleId|level|message|locations|partialFingerprints|", "the SARIF result fields");
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
        pat.push(96); sast_checks::put(pat, keys[ks..ke]); pat.push(96);
        sast_checks::check(find(rdt, pat[..]) >= 0, "the README names a field key");
        ks = ke + 1;
    }

    // The README import line names the version of the package.
    var rd: u8[>..] = [];
    read_file("README.md", rd);
    let imp = find(rd[..], "goose-sast@v");
    sast_checks::check(imp >= 0, "the README holds an import line");
    if imp >= 0 {
        let from = imp + 12;
        var to = from;
        while to < rd.len && rd[to] != 34 { to = to + 1; }
        sast_checks::check(rd[from..to] == sast::VERSION, "the README version equals the package version");
    }
}

// The tests of the group supply.
namespace supply_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import common;

fn supply_tests() {
    // The pin kind with no cache.
    common::check(sast::pin_kind("", "", "../lib") == 0, "a local path has no pin");
    common::check(sast::pin_kind("abc1234", "", "o/r") == 1, "7 hex bytes are a commit");
    common::check(sast::pin_kind("0123456789abcdef0123456789abcdef01234567", "", "o/r") == 1, "40 hex bytes are a commit");
    common::check(sast::pin_kind("abc123", "", "o/r") == 3, "6 hex bytes are no commit");
    common::check(sast::pin_kind("ABC1234", "", "o/r") == 3, "uppercase hex is no commit");
    common::check(sast::pin_kind("v1.2.3", "", "o/r") == 2, "v and a digit is a tag with no cache");
    common::check(sast::pin_kind("main", "", "o/r") == 3, "a name is a branch with no cache");
    // The source check.
    common::check(sast::source_safe("o/r"), "o/r is safe");
    common::check(sast::source_safe("github.com/o/r"), "a host source is safe");
    common::check(!sast::source_safe("../x"), "a .. segment is unsafe");
    common::check(!sast::source_safe("o/../r"), "a middle .. segment is unsafe");
    common::check(!sast::source_safe("/o/r"), "a leading slash is unsafe");
    common::check(!sast::source_safe("o\\r"), "a backslash is unsafe");
    common::check(!sast::source_safe("o//r"), "an empty segment is unsafe");
    common::check(!sast::source_safe(""), "an empty source is unsafe");
    var big: u8[>..] = [];
    common::fill(big, 97, 257);
    common::check(!sast::source_safe(big[..]), "257 bytes are unsafe");
    var nul: u8[>..] = [];
    common::put(nul, "o/r"); nul.push(0);
    common::check(!sast::source_safe(nul[..]), "a NUL byte is unsafe");
    // The URL cache name, measured with the compiler.
    var un: u8[>..] = [];
    common::check(sast::url_cache_name("file:///home/ubuntu/works/goose/pkgtest/mylib", un), "url name builds");
    common::check(un[..] == "mylib-e6dff747", "the url cache name matches the compiler");

    // A fake cache.
    let root = "../../tmp/sc-cache";
    let gh = "../../tmp/sc-cache/github.com/o";
    common::mk_file("../../tmp/sc-cache/github.com/o/tagpkg/v1/.git", "config", "[remote]\n\tfetch = +refs/tags/v1:refs/tags/v1\n");
    common::mk_file("../../tmp/sc-cache/github.com/o/brpkg/v1/.git", "config", "[remote]\n\tfetch = +refs/heads/v1:refs/remotes/origin/v1\n");
    common::mk_file("../../tmp/sc-cache/github.com/o/cpkg/v1", "x.build", "c_sources = [\"a.c\"];\n");
    common::mk_file("../../tmp/sc-cache/github.com/o/cpkg/0123456789ab", "x.build", "c_sources = [\"a.c\"];\n");
    common::mk_file("../../tmp/sc-cache/github.com/o/cmk/v1", "CMakeLists.txt", "project(x)\n");
    common::mk_file("../../tmp/sc-cache/github.com/o/pure/v1", "pure.goose", "namespace pure;\n");
    common::check(sast::pin_kind("v1", root, "o/tagpkg") == 2, "the cache tag refspec gives a tag");
    common::check(sast::pin_kind("v1", root, "o/brpkg") == 3, "the cache branch refspec gives a branch");
    common::check(sast::cpart_probe(root, "o/cpkg", "v1") == 1, "a sidecar with c_sources is a C part");
    common::check(sast::cpart_probe(root, "o/cmk", "v1") == 1, "a CMakeLists.txt is a C part");
    common::check(sast::cpart_probe(root, "o/pure", "v1") == 0, "a pure package has no C part");
    // A sidecar above the bound is unreadable, so the probe fails closed.
    var bigtxt: u8[>..] = [];
    common::fill(bigtxt, 32, 70000);
    common::put(bigtxt, "c_sources = [];");
    common::mk_file("../../tmp/sc-cache/github.com/o/big/v1", "x.build", bigtxt[..]);
    common::check(sast::cpart_probe(root, "o/big", "v1") == 2, "a sidecar above the bound cannot be checked");
    common::check(sast::cpart_probe(root, "o/none", "v1") == 2, "a missing entry cannot be checked");
    common::check(sast::cpart_probe(root, "../x", "v1") == 2, "an unsafe source cannot be checked");
    common::check(sast::cpart_probe(root, "o/pure", "../v1") == 2, "an unsafe ref cannot be checked");

    // The policy keys.
    common::supply_pol("{}", "an empty policy parses");
    common::check(!sast::pol_pin_required, "require_commit_pin defaults to false");
    common::check(!sast::pol_cpart_report, "report_c_parts defaults to false");
    sast::pol_reset();
    common::supply_pol("{\"sources\":{\"require_commit_pin\":true,\"report_c_parts\":true,\"c_parts_allow\":[\"o/cpkg\"]}}", "the supply keys parse");
    common::check(sast::pol_pin_required, "require_commit_pin reads as true");
    common::check(sast::pol_cpart_report, "report_c_parts reads as true");
    common::check(sast::pol_cpart_allowed("o/cpkg"), "the allow list holds its name");
    common::check(!sast::pol_cpart_allowed("o/cmk"), "the allow list holds no other name");
    var perr: u8[>..] = [];
    common::check(!sast::read_policy("{\"sources\":{\"require_commit_pin\":\"yes\"}}", perr), "a string for a bool key is a fault");
    common::check(perr.len > 0, "the fault has a text");
    var lots: u8[>..] = [];
    common::put(lots, "{\"sources\":{\"c_parts_allow\":[");
    var li: i64 = 0;
    while li < 1025 { if li > 0 { common::put(lots, ","); } common::put(lots, "\"n\""); li = li + 1; }
    common::put(lots, "]}}");
    var lerr: u8[>..] = [];
    common::check(!sast::read_policy(lots[..], lerr), "1025 allow names are a fault");
    var long: u8[>..] = [];
    common::put(long, "{\"sources\":{\"c_parts_allow\":[\"");
    common::fill(long, 97, 257);
    common::put(long, "\"]}}");
    var lerr2: u8[>..] = [];
    common::check(!sast::read_policy(long[..], lerr2), "a 257-byte allow name is a fault");

    // The checks over a program of four imports.
    let prog = "import a from \"o/brpkg@v1\";\nimport b from \"o/tagpkg@v1\";\nimport c from \"o/cpkg@0123456789ab\";\nimport d from \"../lib\";\nimport e from \"o/none@v1\";\n";
    common::supply_pol("{}", "empty policy for the checks");
    common::check(common::supply_count(prog, root, "PIN") == 1, "an empty policy reports the branch only");
    common::check(common::supply_count(prog, root, "CPART") == 0, "an empty policy reports no C part");
    common::supply_pol("{\"sources\":{\"require_commit_pin\":true}}", "the commit policy");
    common::check(common::supply_count(prog, root, "PIN") == 3, "the commit policy reports the branch and two tags");
    common::supply_pol("{\"sources\":{\"report_c_parts\":true}}", "the C part policy");
    common::check(common::supply_count(prog, root, "CPART") == 2, "the C part policy reports the C package and the missing one");
    common::supply_pol("{\"sources\":{\"report_c_parts\":true,\"c_parts_allow\":[\"o/cpkg\",\"o/none\"]}}", "the allow policy");
    common::check(common::supply_count(prog, root, "CPART") == 0, "the allow list silences the C part check");
    // The URL userinfo: the pin is the text after the last @.
    sast::read_manifest("import u from \"https://me@host.example/x/y.git@v2\";\n");
    common::check(sast::dep_tag(0) == "v2", "the pin of a URL with userinfo is after the last @");
    sast::pol_reset();
    // The dependency check alone adds no pin finding.
    var nd: sast::Finding[>..] = [];
    common::check(sast::check_deps(prog, nd) == 0, "check_deps gives no pin finding");
}

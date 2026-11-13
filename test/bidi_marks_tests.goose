// The tests of the group bidi_marks.
namespace bidi_marks_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import sast_checks;

// bidi_marks_tests checks that the plain marks U+200E and U+200F stay
// silent, because right-to-left text holds them, and that the overrides
// report.
fn bidi_marks_tests() {
    var b: u8[>..] = [];
    sast_checks::bidi_src(3, b);
    sast_checks::check(sast_checks::count_rule(b[..], "G116") == 0, "G116 keeps the mark U+200E");
    var c: u8[>..] = [];
    sast_checks::bidi_src(4, c);
    sast_checks::check(sast_checks::count_rule(c[..], "G116") == 0, "G116 keeps the mark U+200F");
    var d: u8[>..] = [];
    sast_checks::bidi_src(1, d);
    sast_checks::check(sast_checks::count_rule(d[..], "G116") == 1, "G116 reports the override U+202A");
}

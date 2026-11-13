// The tests of the group bidi_marks.
namespace bidi_marks_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import common;

// bidi_marks_tests checks that the plain marks U+200E and U+200F stay
// silent, because right-to-left text holds them, and that the overrides
// report.
fn bidi_marks_tests() {
    var b: u8[>..] = [];
    common::bidi_src(3, b);
    common::check(common::count_rule(b[..], "G116") == 0, "G116 keeps the mark U+200E");
    var c: u8[>..] = [];
    common::bidi_src(4, c);
    common::check(common::count_rule(c[..], "G116") == 0, "G116 keeps the mark U+200F");
    var d: u8[>..] = [];
    common::bidi_src(1, d);
    common::check(common::count_rule(d[..], "G116") == 1, "G116 reports the override U+202A");
}

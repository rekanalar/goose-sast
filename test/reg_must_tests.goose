// The tests of the group reg_must.
namespace reg_must_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import common;

// reg_must_tests checks the exact lookup over every rule of the
// registry. It gives the index of the row that carries the ID.
fn reg_must_tests() {
    let n = sast::rule_count();
    var i: i64 = 0;
    while i < n {
        common::check(sast::reg_must(sast::reg_id_s[i]) == i, "the exact lookup of a rule ID");
        i = i + 1;
    }
    // An alias resolves for the user, and the exact lookup reads no
    // alias.
    common::check(sast::reg_find("B105") == sast::reg_find("G101"), "the alias B105 resolves to G101");
}

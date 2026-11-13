// Tests of the package. Run them all with: goose run test/run.goose
// The program must start in the package directory.

import std;
import sast from "..";
import baseline_tests;
import metadata_tests;
import supply_tests;
import id_site_tests;
import bidi_marks_tests;
import reg_must_tests;
import ledger_tests;
import common;
import os;
import json;
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    baseline_tests::baseline_tests();
    metadata_tests::metadata_tests();
    supply_tests::supply_tests();
    id_site_tests::id_site_tests();
    bidi_marks_tests::bidi_marks_tests();
    reg_must_tests::reg_must_tests();
    ledger_tests::ledger_tests();
    print("all tests passed");
    return 0;
}

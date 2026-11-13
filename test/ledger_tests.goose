// The tests of the group ledger.
namespace ledger_tests;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";
import common;

// The rules that left the registry and the constant index check.
fn ledger_tests() {
    // The nine IDs that left the registry.
    var gone: const u8[:][>..] = [];
    gone.push("B405");
    gone.push("B406");
    gone.push("B407");
    gone.push("B408");
    gone.push("B409");
    gone.push("B412");
    gone.push("B413");
    gone.push("B414");
    gone.push("B415");
    var i: i64 = 0;
    while i < gone.len {
        common::check(sast::reg_find(gone[i]) == -1, "a removed rule ID is still in the registry");
        var one: u8[>..] = [];
        common::check(!sast::explain_rule(gone[i], false, one), "explain a removed rule ID");
        i = i + 1;
    }
    // A removed ID in a config file is an unknown ID and faults.
    var co = sast::default_options();
    var cpol: u8[>..] = [];
    var cadv: u8[>..] = [];
    var crules: u8[>..] = [];
    var cerr: u8[>..] = [];
    var ctext: u8[>..] = [];
    for c in "{ \"exclude\": \"B405\" }" { ctext.push(c); }
    common::check(!sast::read_config(ctext[..], 0, co, cpol, cadv, crules, cerr), "a removed ID in a config file faults");
    common::check(common::holds(cerr[..], "no rule carries the ID B405"), "the fault names the removed ID");

    // The constant index outside a fixed array.
    var lines: i64[>..] = [];
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = a[4];\n", lines);
    common::check(lines.len == 1 && lines[0] == 2, "G602 reports an index outside the array");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = a[3];\n", lines);
    common::check(lines.len == 0, "G602 keeps an index inside the array");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\na[9] = 5;\n", lines);
    common::check(lines.len == 1 && lines[0] == 2, "G602 reports a write outside the array");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = a[-1];\n", lines);
    common::check(lines.len == 1, "G602 reports a negative index");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = a[i];\n", lines);
    common::check(lines.len == 0, "G602 keeps a variable index");
    lines.resize(0, 0);
    common::g602_lines("let c: u8[>..] = [];\nlet v = c[9];\n", lines);
    common::check(lines.len == 0, "G602 keeps a growable slice");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[N] = [1];\nlet v = a[9];\n", lines);
    common::check(lines.len == 0, "G602 keeps an array of no literal length");
    lines.resize(0, 0);
    common::g602_lines("fn f(a: i64) { let v = a[9]; }\n", lines);
    common::check(lines.len == 0, "G602 keeps a parameter");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nfn f() { let a = 5; let v = a[9]; }\n", lines);
    common::check(lines.len == 0, "G602 keeps a name that an inner scope rebinds");
    lines.resize(0, 0);
    common::g602_lines("fn f() { let a: i64[4] = [1, 2, 3, 4]; let v = a[9]; }\nfn g() { let a: i64[16] = [1]; let w = a[9]; }\n", lines);
    common::check(lines.len == 1 && lines[0] == 1, "G602 reads the binding of the own scope");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet s = \"a[9]\";\n", lines);
    common::check(lines.len == 0, "G602 keeps an index in a string");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\n// a[9]\n", lines);
    common::check(lines.len == 0, "G602 keeps an index in a comment");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[9999999999999999999] = [1];\nlet v = a[9];\n", lines);
    common::check(lines.len == 0, "G602 keeps a length of more than 18 digits");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4]; let v = a[4];\n", lines);
    common::check(lines.len == 1 && lines[0] == 1, "G602 reads a declaration and a use on one line");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1];\nlet v = a[18446744073709551616];\nlet w = a[-99999999999999999999];\n", lines);
    common::check(lines.len == 2, "G602 reports a literal of more than 18 digits");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = a[-0];\n", lines);
    common::check(lines.len == 0, "G602 keeps a minus sign before zero");
    lines.resize(0, 0);
    common::g602_lines("let w: i64[0] = [];\nlet v = w[0];\n", lines);
    common::check(lines.len == 1, "G602 reports an index of an array of no length");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = a[2-1];\n", lines);
    common::check(lines.len == 0, "G602 keeps an index that is an expression");
    lines.resize(0, 0);
    common::g602_lines("let a: i64[4] = [1, 2, 3, 4];\nlet v = s.a[9];\n", lines);
    common::check(lines.len == 0, "G602 keeps an index of a field");

    // The text of G602 names the run-time abort.
    var tx: u8[>..] = [];
    common::check(sast::explain_rule("G602", false, tx), "explain G602");
    common::check(!common::holds(tx[..], "corrupt"), "the text of G602 names no memory corruption");
    common::check(common::holds(tx[..], "abort"), "the text of G602 names the run-time abort");
    // The rows B410 and B411 keep their behavior.
    common::check(common::count_rule("import m from \"a/goose-lxml@v1.0.0\";\n", "B410") == 1, "B410 import");
    common::check(common::count_rule("import m from \"a/goose-xmlrpc@v1.0.0\";\n", "B411") == 1, "B411 import");
}

// The probe of the exact lookup. It reads one rule ID from the command
// line and prints the registry index of that row. An ID that no row
// carries, and an alias such as B105, abort the run and name the ID.
import std;
import os;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    let a = args();
    if a.len < 2 {
        write_stderr("usage: abort_probe ID\n");
        return;
    }
    print(sast::reg_must(a[1]));
}

// Runs the three profiles over one tree and prints the count of each.
// The tree holds a file at the top, a file under a test directory and a
// file under an examples directory. The default and the strict
// profiles leave the two directories out, and the profile all reads
// them. The three rules of the default profile stay out of the default
// run, and the strict profile holds them.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn count_profile(path: const u8[:], profile: i64) -> i64 {
    var o = sast::default_options();
    o.profile = profile;
    var fs: sast::Finding[>..] = [];
    sast::scan_reset();
    var budget = o.max_files;
    let scanned, skipped = sast::scan_dir_budget(path, o, fs, budget);
    return scanned;
}

fn main() {
    print("default ", count_profile("examples/profiles", sast::PROFILE_DEFAULT), " file(s)\n");
    print("strict  ", count_profile("examples/profiles", sast::PROFILE_STRICT), " file(s)\n");
    print("all     ", count_profile("examples/profiles", sast::PROFILE_ALL), " file(s)\n");
}

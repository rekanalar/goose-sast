// The table of the sites that report a rule. The test fills it and
// then reads it.
//
namespace site_table;

import std;

var site_src: const u8[:][>..] = [];
var site_id: const u8[:][>..] = [];
var site_kind: i64[>..] = [];

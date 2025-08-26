use nautilus_trader_rig::scan;
use std::io::{self, Read};

fn main() {
    // No flags, no env, no clap: read whole stdin and scan.
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_ok() {
        let issues = scan(&buf);
        println!("{}", serde_json::to_string_pretty(&issues).unwrap());
    } else {
        // If nothing on stdin, do nothing (still no flags/env).
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

const LAST_V2_READ_AT_UNIX: u64 = 1_799_107_200;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(tinycloud_legacy_share_v2)");
    // This is a construction-time removal boundary, not an operator feature
    // flag. A post-cutoff build must not be able to compile the legacy module
    // by supplying an earlier timestamp in its environment.
    let build_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("build time is after Unix epoch")
        .as_secs();
    if build_time <= LAST_V2_READ_AT_UNIX {
        println!("cargo:rustc-cfg=tinycloud_legacy_share_v2");
    }
}

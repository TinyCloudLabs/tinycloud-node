//! The compose env lines `tinycloud-at-rest recipients` prints parse into
//! `at_rest` exactly as the node loads them (main.rs's provider chain).
//! One test in its own process, since it sets process environment.

use rocket::figment::{
    providers::{Env, Serialized},
    Figment,
};
use tinycloud::config::{AtRestMode, Config};

#[test]
fn compose_env_lines_configure_at_rest() {
    let recipients = "[{holder=\"sam\",recipient=\"age1yubikey1q2w7u3vpya839jxxuq8g0sedh3d740d4xvn639sqhr95ejj8vu3hyfumptt\"},\
{holder=\"hunter\",recipient=\"age1qthuv2xtsp2nrz0apnfmj49fkdwp46zygpy4vv8ellvh47203psse695k4\"},\
{holder=\"safe\",recipient=\"age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e\"}]";
    let fp = "ab".repeat(32);
    std::env::set_var("TINYCLOUD_AT_REST__MODE", "encrypt");
    std::env::set_var("TINYCLOUD_AT_REST__ESCROW__RECIPIENTS", recipients);
    std::env::set_var("TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP", &fp);

    let config: Config = Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(Config::default()))
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .extract()
        .expect("at_rest env parses");

    assert_eq!(config.at_rest.mode, AtRestMode::Encrypt);
    let holders: Vec<_> = config
        .at_rest
        .escrow
        .recipients
        .iter()
        .map(|h| h.holder.as_str())
        .collect();
    assert_eq!(holders, ["sam", "hunter", "safe"]);
    assert!(config.at_rest.escrow.recipients[0]
        .recipient
        .starts_with("age1yubikey1q2w7"));
    assert_eq!(
        config.at_rest.escrow.verified_fp.as_deref(),
        Some(fp.as_str())
    );
    assert!(!config.at_rest.escrow.allow_software);
    assert!(!config.at_rest.escrow_none);
}

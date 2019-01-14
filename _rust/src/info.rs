use clap::crate_version;
use std::env::consts;

pub static NAME: &str = "phaser";
pub static VERSION: &str = crate_version!();
pub static AUTHOR: &str = "Sylvain Kerkour";
pub static DESCRPITION: &str = "Bloom's security scanner";
pub static OS: &str = consts::OS;
pub static ARCH: &str = consts::ARCH;

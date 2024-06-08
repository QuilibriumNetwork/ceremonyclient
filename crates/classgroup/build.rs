use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").expect("cargo should have set this");
    if target == "aarch64-apple-darwin" {
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/gmp/6.3.0/lib");
    } else if target == "aarch64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu/");
    } else if target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/");
    } else {
        panic!("unsupported target {target}");
    }
}

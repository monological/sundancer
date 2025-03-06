use std::process::Command;
use std::env;
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=src/fpga_ed25519.c");
    println!("cargo:rerun-if-changed=src/fpga_ed25519_test.c");

    let lib = pkg_config::Config::new().atleast_version("1.0.18").probe("libsodium").unwrap();

    {
        let mut cmd = Command::new("clang");
        cmd.args(&["-c", "-fPIC", "-o", "fpga_ed25519.o", "src/fpga_ed25519.c"]);
        for path in &lib.include_paths {
            cmd.arg(format!("-I{}", path.display()));
        }
        cmd.status().unwrap();
    }

    {
        let lib_name = "libfpga_ed25519.a";
        let mut cmd = Command::new("ar");
        cmd.args(&["rcs", lib_name, "fpga_ed25519.o"]);
        cmd.status().unwrap();
        let out_dir = env::var("OUT_DIR").unwrap();
        fs::copy(lib_name, format!("{}/{}", out_dir, lib_name)).unwrap();
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=fpga_ed25519");
    }

    for path in &lib.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }

    for l in &lib.libs {
        println!("cargo:rustc-link-lib={}", l);
    }
}

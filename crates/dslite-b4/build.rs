use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "illumos" {
        println!("cargo:rustc-link-lib=dladm");

        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let symlink = out_dir.join("libipadm.so");
        let lib_path = if std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64" {
            "/lib/amd64/libipadm.so.1"
        } else {
            "/lib/libipadm.so.1"
        };
        let _ = std::fs::remove_file(&symlink);
        std::os::unix::fs::symlink(lib_path, &symlink).unwrap();

        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=ipadm");
    }
}

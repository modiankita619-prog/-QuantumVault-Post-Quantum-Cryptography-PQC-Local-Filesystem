// Compiles the C crypto engine (../c_demo/qv_crypto.c) and links it, plus
// liboqs and OpenSSL, into the Rust binary.
fn main() {
    cc::Build::new()
        .file("../c_demo/qv_crypto.c")
        .include("../c_demo")
        .warnings(true)
        .compile("qvcrypto");

    // liboqs is installed in /usr/local/lib, which rust-lld does not search by
    // default. Set OQS_LIB_DIR to override if liboqs lives elsewhere.
    let dir = std::env::var("OQS_LIB_DIR").unwrap_or_else(|_| "/usr/local/lib".to_string());
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rerun-if-env-changed=OQS_LIB_DIR");

    println!("cargo:rustc-link-lib=oqs");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=../c_demo/qv_crypto.c");
    println!("cargo:rerun-if-changed=../c_demo/qv_crypto.h");
}

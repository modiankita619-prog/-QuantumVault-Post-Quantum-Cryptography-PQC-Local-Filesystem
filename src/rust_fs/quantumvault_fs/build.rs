fn main() {
    cc::Build::new()
        .file("../../../src/c_crypto/quantumvault_crypto_lib.c")
        .include("../../../src/c_crypto")
        .flag_if_supported("-std=c11")
        .warnings(true)
        .compile("quantumvault_crypto");

    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=../../../src/c_crypto/quantumvault_crypto_lib.c");
    println!("cargo:rerun-if-changed=../../../src/c_crypto/quantumvault_crypto.h");
}

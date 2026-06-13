fn main() {
    println!("cargo:rerun-if-changed=LICENSE");
    println!(
        "cargo:warning=reVault key/topology server production operation requires a separate commercial license from OnePub IP Pty Ltd; see lockbox_key_server/LICENSE"
    );
}

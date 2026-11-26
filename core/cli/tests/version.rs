use std::process::Command;

#[test]
fn prints_core_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_lazymail"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.trim(), lazymail_core::core_version());
}

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct CoreInfo {
    pub name: String,
    pub version: String,
}

#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[uniffi::export]
pub fn core_info() -> CoreInfo {
    CoreInfo {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: core_version(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_package() {
        assert_eq!(core_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn info_carries_version() {
        let info = core_info();
        assert_eq!(info.name, "lazymail-core");
        assert_eq!(info.version, core_version());
    }
}

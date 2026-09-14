pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn user_agent_joins_the_crate_name_and_version() {
        assert_eq!(USER_AGENT, format!("{NAME}/{VERSION}"));
    }

    #[test]
    fn user_agent_is_a_transmittable_http_header_value() {
        let header = reqwest::header::HeaderValue::from_str(USER_AGENT)
            .expect("user agent must be a valid header value");

        assert_eq!(header.to_str().unwrap(), USER_AGENT);
        assert!(
            !USER_AGENT
                .chars()
                .any(|character| character.is_whitespace() || character.is_control()),
            "user agent must not contain whitespace or control characters: {USER_AGENT:?}"
        );
    }

    #[test]
    fn crate_name_matches_the_advertised_command_name() {
        assert_eq!(NAME, "bughunter");
    }

    #[test]
    fn version_is_a_numeric_release_triple() {
        let components: Vec<&str> = VERSION.split('.').collect();

        assert_eq!(
            components.len(),
            3,
            "version must be major.minor.patch: {VERSION}"
        );
        for component in components {
            assert!(
                component.parse::<u32>().is_ok(),
                "version component is not numeric: {component:?}"
            );
        }
    }
}

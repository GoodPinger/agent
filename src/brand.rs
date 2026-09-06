//! The ONLY place the product name is hardcoded in Rust.

pub const NAME: &str = "Goodpinger";
pub const CLI: &str = "gpr";

/// Default control-plane base URL. Overridable per install via config
/// (`base_url`) or the `GPR_BASE_URL` env var — see `config.rs`.
pub const BASE_URL: &str = "https://goodpinger.com";

/// This build's version, from Cargo. Sent in `/agent/hello` and the UA.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `User-Agent` every request carries.
pub fn user_agent() -> String {
    format!("{CLI}/{VERSION}")
}

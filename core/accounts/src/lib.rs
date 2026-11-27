mod account;
mod autoconfig;
mod guide;
mod net;
mod provider;
mod sasl;

pub use account::{Account, Identity, MailAccess};
pub use autoconfig::{discover, parse_autoconfig, Found, Network, Source, SrvRecord};
pub use guide::{app_password_guide, check_app_password, Guide, PasswordProblem};
pub use net::SystemNetwork;
pub use provider::{Endpoint, Login, Provider, Security, ServerSettings};
pub use sasl::{xoauth2, xoauth2_base64, Resource, StaticTokens, TokenError, TokenSource};

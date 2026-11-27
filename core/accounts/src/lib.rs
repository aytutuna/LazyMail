mod account;
mod autoconfig;
mod net;
mod provider;

pub use account::{Account, Identity, MailAccess};
pub use autoconfig::{discover, parse_autoconfig, Found, Network, Source, SrvRecord};
pub use net::SystemNetwork;
pub use provider::{Endpoint, Login, Provider, Security, ServerSettings};

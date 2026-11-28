use crate::provider::Provider;

macro_rules! app_name {
    () => {
        "Alazy"
    };
}

/// Where to make an app password and what to click, in English; the one place to localize.
pub struct Guide {
    pub url: &'static str,
    pub steps: &'static [&'static str],
}

pub fn app_password_guide(provider: Provider) -> Option<Guide> {
    let guide = match provider {
        Provider::Gmail => Guide {
            url: "https://myaccount.google.com/apppasswords",
            steps: &[
                "Turn on 2-Step Verification for the Google account if it is off.",
                concat!("Open the App passwords page and name the password ", app_name!(), "."),
                "Copy the 16 letters Google shows and paste them here.",
                "Workspace accounts: if the page is missing, ask the administrator to allow app passwords.",
            ],
        },
        Provider::ICloud => Guide {
            url: "https://account.apple.com/account/manage",
            steps: &[
                "Sign in and open Sign-In and Security.",
                concat!("Choose App-Specific Passwords and make one named ", app_name!(), "."),
                "Copy it and paste it here.",
            ],
        },
        Provider::Yahoo => Guide {
            url: "https://login.yahoo.com/account/security",
            steps: &[
                "Open Account security and choose Generate app password.",
                concat!("Name it ", app_name!(), " and copy the password Yahoo shows."),
            ],
        },
        Provider::Aol => Guide {
            url: "https://login.aol.com/account/security",
            steps: &[
                "Open Account security and choose Generate app password.",
                concat!("Name it ", app_name!(), " and copy the password AOL shows."),
            ],
        },
        Provider::Fastmail => Guide {
            url: "https://app.fastmail.com/settings/security/integrations",
            steps: &[
                "Open Settings, Privacy and Security, Integrations.",
                "Choose New app password, pick Mail (IMAP/POP/SMTP) and copy the password.",
            ],
        },
        Provider::ProtonBridge => Guide {
            url: "https://proton.me/mail/bridge",
            steps: &[
                "Install Proton Mail Bridge and sign in there (a paid Proton plan is needed).",
                "Open the account's mailbox details in Bridge and copy the Bridge password, not the Proton one.",
            ],
        },
        _ => return None,
    };
    Some(guide)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordProblem {
    Empty,
    /// The provider's passwords have a fixed shape and this is not it.
    WrongShape,
}

/// Cleans up a pasted app password and checks its shape; returns the text to save.
pub fn check_app_password(provider: Provider, input: &str) -> Result<String, PasswordProblem> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PasswordProblem::Empty);
    }
    match provider {
        // Google shows 16 lowercase letters in groups of four.
        Provider::Gmail => {
            let letters: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            if letters.len() == 16 && letters.bytes().all(|b| b.is_ascii_lowercase()) {
                Ok(letters)
            } else {
                Err(PasswordProblem::WrongShape)
            }
        }
        // Apple's look like xxxx-xxxx-xxxx-xxxx.
        Provider::ICloud => {
            let ok = trimmed.split('-').count() == 4
                && trimmed
                    .split('-')
                    .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_lowercase()));
            if ok {
                Ok(trimmed.to_string())
            } else {
                Err(PasswordProblem::WrongShape)
            }
        }
        _ => Ok(trimmed.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmail_password_loses_its_spaces() {
        assert_eq!(
            check_app_password(Provider::Gmail, " abcd efgh ijkl mnop "),
            Ok("abcdefghijklmnop".to_string())
        );
        assert_eq!(
            check_app_password(Provider::Gmail, "my real password"),
            Err(PasswordProblem::WrongShape)
        );
    }

    #[test]
    fn icloud_password_shape() {
        assert!(check_app_password(Provider::ICloud, "abcd-efgh-ijkl-mnop").is_ok());
        assert_eq!(
            check_app_password(Provider::ICloud, "abcdefghijklmnop"),
            Err(PasswordProblem::WrongShape)
        );
        assert_eq!(
            check_app_password(Provider::Yahoo, "  "),
            Err(PasswordProblem::Empty)
        );
    }

    #[test]
    fn guides_exist_for_app_password_providers_only() {
        for p in [
            Provider::Gmail,
            Provider::ICloud,
            Provider::Yahoo,
            Provider::Aol,
            Provider::Fastmail,
            Provider::ProtonBridge,
        ] {
            let g = app_password_guide(p).unwrap();
            assert!(g.url.starts_with("https://"));
            assert!(!g.steps.is_empty());
        }
        assert!(app_password_guide(Provider::Outlook).is_none());
        assert!(app_password_guide(Provider::Other).is_none());
    }
}

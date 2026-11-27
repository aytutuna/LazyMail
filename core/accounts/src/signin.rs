use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::account::{Account, MailAccess};
use crate::provider::Provider;
use crate::sasl::TokenError;

pub const RETRY_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthFailure {
    Rejected,
    /// Gmail refused an app password it had accepted before.
    GoogleAppPasswordRefused,
    AppPasswordRequired,
    /// The Microsoft sign-in has to be done again.
    SignInExpired,
    /// A Microsoft 365 tenant that turned IMAP or SMTP AUTH off.
    GraphNeeded,
}

impl AuthFailure {
    pub fn message(self) -> &'static str {
        match self {
            AuthFailure::Rejected => "The server did not accept the sign-in.",
            AuthFailure::GoogleAppPasswordRefused => {
                "Google turned off this app password, usually after a password change"
            }
            AuthFailure::AppPasswordRequired => "This account needs an app password.",
            AuthFailure::SignInExpired => "Sign in again to keep this account up to date.",
            AuthFailure::GraphNeeded => "This organization does not allow IMAP or SMTP sign-in.",
        }
    }

    /// A transient token failure is not a sign-in problem.
    pub fn from_token_error(e: &TokenError) -> Option<AuthFailure> {
        match e {
            TokenError::InteractionRequired => Some(AuthFailure::SignInExpired),
            TokenError::Failed(_) => None,
        }
    }
}

/// Reads the text of a failed IMAP or SMTP login. `None` means the refusal is temporary
/// (a busy or limited server), which says nothing about the credentials.
/// `worked_before` is false while a password is first being added.
pub fn classify_login_error(
    provider: Provider,
    server_text: &str,
    worked_before: bool,
) -> Option<AuthFailure> {
    let t = server_text.to_ascii_lowercase();
    if is_temporary(&t) {
        return None;
    }
    Some(match provider {
        Provider::Microsoft365
            if [
                "user is authenticated but not connected",
                "smtpclientauthentication is disabled",
                "basic authentication is disabled",
                "5.7.30",
            ]
            .iter()
            .any(|s| t.contains(s)) =>
        {
            AuthFailure::GraphNeeded
        }
        Provider::Gmail if t.contains("application-specific password required") => {
            AuthFailure::AppPasswordRequired
        }
        Provider::Gmail
            if worked_before
                && [
                    "authenticationfailed",
                    "invalid credentials",
                    "username and password not accepted",
                    "5.7.8",
                ]
                .iter()
                .any(|s| t.contains(s)) =>
        {
            AuthFailure::GoogleAppPasswordRefused
        }
        _ => AuthFailure::Rejected,
    })
}

// RFC 5530 temporary codes, Gmail's connection limit, and SMTP 4yz replies.
fn is_temporary(t: &str) -> bool {
    let smtp_4xx = {
        let b = t.trim_start().as_bytes();
        b.len() > 2 && b[0] == b'4' && b[1].is_ascii_digit() && b[2].is_ascii_digit()
    };
    smtp_4xx
        || [
            "[unavailable]",
            "[inuse]",
            "[limit]",
            "too many simultaneous connections",
        ]
        .iter()
        .any(|s| t.contains(s))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountState {
    SignedIn,
    NeedsSignIn {
        reason: AuthFailure,
        since: SystemTime,
        last_attempt: SystemTime,
    },
}

/// What the app should tell the person, once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    NeedsSignIn {
        account_id: String,
        reason: AuthFailure,
    },
    UsesGraph {
        account_id: String,
    },
}

/// Kept by the store between launches, so a restart neither notifies again nor skips the hour.
#[derive(Default, Serialize, Deserialize)]
pub struct SignIn {
    states: HashMap<String, AccountState>,
}

impl SignIn {
    pub fn state(&self, account_id: &str) -> AccountState {
        self.states
            .get(account_id)
            .copied()
            .unwrap_or(AccountState::SignedIn)
    }

    /// The Outbox and scheduled work of this account wait; other accounts are not affected.
    pub fn work_paused(&self, account_id: &str) -> bool {
        matches!(self.state(account_id), AccountState::NeedsSignIn { .. })
    }

    /// Records a failed sign-in. Only the first failure gives an event; failures of
    /// retries only move the retry clock.
    pub fn report_failure(
        &mut self,
        account: &mut Account,
        failure: AuthFailure,
        now: SystemTime,
    ) -> Option<Event> {
        if failure == AuthFailure::GraphNeeded {
            self.states.remove(&account.id);
            if account.mail == MailAccess::Graph {
                return None;
            }
            account.mail = MailAccess::Graph;
            return Some(Event::UsesGraph {
                account_id: account.id.clone(),
            });
        }
        match self.states.get_mut(&account.id) {
            Some(AccountState::NeedsSignIn {
                reason,
                last_attempt,
                ..
            }) => {
                let changed = *reason != failure;
                *reason = failure;
                *last_attempt = now;
                // Google's text and the new-password button matter more than the first reason.
                (changed && failure == AuthFailure::GoogleAppPasswordRefused).then(|| {
                    Event::NeedsSignIn {
                        account_id: account.id.clone(),
                        reason: failure,
                    }
                })
            }
            _ => {
                self.states.insert(
                    account.id.clone(),
                    AccountState::NeedsSignIn {
                        reason: failure,
                        since: now,
                        last_attempt: now,
                    },
                );
                Some(Event::NeedsSignIn {
                    account_id: account.id.clone(),
                    reason: failure,
                })
            }
        }
    }

    pub fn report_success(&mut self, account_id: &str) {
        self.states.remove(account_id);
    }

    /// True when a sign-in attempt may start now; a granted retry counts as an attempt,
    /// so an account is tried at most once an hour however many tasks ask.
    pub fn try_retry(&mut self, account_id: &str, now: SystemTime) -> bool {
        match self.states.get_mut(account_id) {
            None => true,
            Some(AccountState::SignedIn) => true,
            Some(AccountState::NeedsSignIn { last_attempt, .. }) => {
                let waited = now.duration_since(*last_attempt).unwrap_or(Duration::ZERO);
                if waited >= RETRY_INTERVAL {
                    *last_attempt = now;
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn account(id: &str, provider: Provider) -> Account {
        Account::new(id, provider, &format!("{id}@example.com"), "Test")
    }

    #[test]
    fn first_failure_notifies_once_and_pauses_only_that_account() {
        let mut s = SignIn::default();
        let mut a = account("a", Provider::Yahoo);
        let b = account("b", Provider::Fastmail);
        let ev = s.report_failure(&mut a, AuthFailure::Rejected, at(0));
        assert_eq!(
            ev,
            Some(Event::NeedsSignIn {
                account_id: "a".into(),
                reason: AuthFailure::Rejected
            })
        );
        assert!(s.work_paused("a"));
        assert!(!s.work_paused(&b.id));
        assert_eq!(
            s.report_failure(&mut a, AuthFailure::Rejected, at(10)),
            None
        );
    }

    #[test]
    fn retries_at_most_hourly() {
        let mut s = SignIn::default();
        let mut a = account("a", Provider::Yahoo);
        s.report_failure(&mut a, AuthFailure::Rejected, at(0));
        assert!(!s.try_retry("a", at(3599)));
        assert!(s.try_retry("a", at(3600)));
        // The granted retry restarts the hour, even before its result is known.
        assert!(!s.try_retry("a", at(3601)));
        s.report_failure(&mut a, AuthFailure::Rejected, at(3700));
        assert!(!s.try_retry("a", at(3700 + 3599)));
        assert!(s.try_retry("a", at(3700 + 3600)));
    }

    #[test]
    fn success_clears_the_state() {
        let mut s = SignIn::default();
        let mut a = account("a", Provider::Yahoo);
        s.report_failure(&mut a, AuthFailure::Rejected, at(0));
        s.report_success("a");
        assert_eq!(s.state("a"), AccountState::SignedIn);
        assert!(!s.work_paused("a"));
        assert!(s
            .report_failure(&mut a, AuthFailure::Rejected, at(5))
            .is_some());
    }

    #[test]
    fn clock_going_back_does_not_allow_a_retry() {
        let mut s = SignIn::default();
        let mut a = account("a", Provider::Yahoo);
        s.report_failure(&mut a, AuthFailure::Rejected, at(10_000));
        assert!(!s.try_retry("a", at(5)));
    }

    #[test]
    fn microsoft_imap_disabled_switches_to_graph_not_sign_in() {
        let mut s = SignIn::default();
        let mut a = account("w", Provider::Microsoft365);
        let f = classify_login_error(
            Provider::Microsoft365,
            "NO LOGIN failed. BAD User is authenticated but not connected.",
            true,
        )
        .unwrap();
        assert_eq!(f, AuthFailure::GraphNeeded);
        assert_eq!(
            s.report_failure(&mut a, f, at(0)),
            Some(Event::UsesGraph {
                account_id: "w".into()
            })
        );
        assert_eq!(a.mail, MailAccess::Graph);
        assert!(!s.work_paused("w"));
        assert_eq!(s.report_failure(&mut a, f, at(1)), None);
    }

    #[test]
    fn smtp_auth_disabled_text_is_recognised() {
        let text = "535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant.";
        assert_eq!(
            classify_login_error(Provider::Microsoft365, text, true),
            Some(AuthFailure::GraphNeeded)
        );
        assert_eq!(
            classify_login_error(Provider::Outlook, text, true),
            Some(AuthFailure::Rejected)
        );
    }

    #[test]
    fn google_refusal_has_the_planned_text() {
        let f = classify_login_error(
            Provider::Gmail,
            "NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)",
            true,
        )
        .unwrap();
        assert_eq!(f, AuthFailure::GoogleAppPasswordRefused);
        assert_eq!(
            f.message(),
            "Google turned off this app password, usually after a password change"
        );
        assert_eq!(
            classify_login_error(
                Provider::Gmail,
                "NO [ALERT] Application-specific password required: https://support.google.com/accounts/answer/185833",
                true
            ),
            Some(AuthFailure::AppPasswordRequired)
        );
    }

    #[test]
    fn gmail_smtp_refusal_is_the_google_one() {
        let text = "535-5.7.8 Username and Password not accepted. For more information, go to";
        assert_eq!(
            classify_login_error(Provider::Gmail, text, true),
            Some(AuthFailure::GoogleAppPasswordRefused)
        );
    }

    #[test]
    fn a_new_gmail_password_that_fails_is_just_rejected() {
        assert_eq!(
            classify_login_error(
                Provider::Gmail,
                "NO [AUTHENTICATIONFAILED] Invalid credentials",
                false
            ),
            Some(AuthFailure::Rejected)
        );
    }

    #[test]
    fn temporary_refusals_are_not_sign_in_problems() {
        for (p, text) in [
            (Provider::Yahoo, "NO [UNAVAILABLE] LOGIN error"),
            (
                Provider::Gmail,
                "NO [ALERT] Too many simultaneous connections. (Failure)",
            ),
            (
                Provider::Gmail,
                "454 4.7.0 Too many login attempts, please try again later.",
            ),
            (Provider::Fastmail, "NO [INUSE] mailbox busy"),
        ] {
            assert_eq!(classify_login_error(p, text, true), None, "{text}");
        }
    }

    #[test]
    fn google_reason_arriving_later_notifies_again() {
        let mut s = SignIn::default();
        let mut a = account("g", Provider::Gmail);
        s.report_failure(&mut a, AuthFailure::Rejected, at(0));
        let ev = s.report_failure(&mut a, AuthFailure::GoogleAppPasswordRefused, at(5));
        assert_eq!(
            ev,
            Some(Event::NeedsSignIn {
                account_id: "g".into(),
                reason: AuthFailure::GoogleAppPasswordRefused
            })
        );
        assert_eq!(
            s.report_failure(&mut a, AuthFailure::GoogleAppPasswordRefused, at(9)),
            None
        );
    }

    #[test]
    fn state_survives_a_restart_and_still_waits_the_hour() {
        let mut s = SignIn::default();
        let mut a = account("a", Provider::Yahoo);
        s.report_failure(&mut a, AuthFailure::Rejected, at(100));
        let saved = serde_json::to_string(&s).unwrap();
        let mut back: SignIn = serde_json::from_str(&saved).unwrap();
        assert!(back.work_paused("a"));
        assert!(!back.try_retry("a", at(100 + 3599)));
        assert!(back.try_retry("a", at(100 + 3600)));
    }

    #[test]
    fn only_interaction_required_tokens_need_sign_in() {
        assert_eq!(
            AuthFailure::from_token_error(&TokenError::InteractionRequired),
            Some(AuthFailure::SignInExpired)
        );
        assert_eq!(
            AuthFailure::from_token_error(&TokenError::Failed("net".into())),
            None
        );
    }
}

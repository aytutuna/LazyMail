use std::sync::Mutex;

use lazymail_store::{Folder, Store};

use crate::conn::{Connection, RemoteFolder};
use crate::error::Result;

const NAMES: &[(&str, &[&str])] = &[
    (
        "sent",
        &[
            "sent",
            "sent items",
            "sent mail",
            "sent messages",
            "gönderilmiş öğeler",
            "gönderilen öğeler",
            "gönderilenler",
            "gesendet",
            "gesendete elemente",
            "gesendete objekte",
            "éléments envoyés",
            "envoyés",
            "messages envoyés",
            "enviados",
            "elementos enviados",
            "correo enviado",
        ],
    ),
    (
        "drafts",
        &[
            "drafts",
            "draft",
            "taslaklar",
            "entwürfe",
            "entwurf",
            "brouillons",
            "borradores",
        ],
    ),
    (
        "trash",
        &[
            "trash",
            "deleted items",
            "deleted messages",
            "bin",
            "silinmiş öğeler",
            "silinen öğeler",
            "çöp kutusu",
            "çöp",
            "papierkorb",
            "gelöschte elemente",
            "gelöschte objekte",
            "corbeille",
            "éléments supprimés",
            "papelera",
            "elementos eliminados",
        ],
    ),
    (
        "junk",
        &[
            "junk",
            "junk email",
            "junk e-mail",
            "spam",
            "bulk mail",
            "gereksiz",
            "gereksiz e-posta",
            "istenmeyen e-posta",
            "junk-e-mail",
            "courrier indésirable",
            "indésirables",
            "correo no deseado",
            "correo basura",
            "no deseado",
        ],
    ),
    (
        "archive",
        &[
            "archive",
            "archives",
            "arşiv",
            "archiv",
            "archivo",
            "archivados",
        ],
    ),
];

const FLAGS: &[(&str, &str)] = &[
    ("\\sent", "sent"),
    ("\\drafts", "drafts"),
    ("\\trash", "trash"),
    ("\\junk", "junk"),
    ("\\archive", "archive"),
    ("\\all", "all"),
];

/// The role of a folder: its SPECIAL-USE flag when it has one, else its name in English,
/// Turkish, German, French or Spanish.
pub fn role_of(f: &RemoteFolder) -> Option<&'static str> {
    if f.name.eq_ignore_ascii_case("inbox") {
        return Some("inbox");
    }
    for (flag, role) in FLAGS {
        if f.has(flag) {
            return Some(role);
        }
    }
    let last = match &f.delimiter {
        Some(d) if !d.is_empty() => f.name.rsplit(d.as_str()).next().unwrap_or(&f.name),
        _ => &f.name,
    };
    let last = last.trim().to_lowercase();
    NAMES
        .iter()
        .find(|(_, names)| names.contains(&last.as_str()))
        .map(|(role, _)| *role)
}

/// Gmail syncs only these, as All Mail holds every message and the labels say where it sits.
fn gmail_wants(role: Option<&str>) -> bool {
    matches!(role, Some("all" | "junk" | "trash"))
}

fn rank(role: Option<&str>) -> u8 {
    match role {
        Some("inbox") => 0,
        Some("all") => 1,
        Some("sent") => 2,
        Some("drafts") => 3,
        Some("archive") => 4,
        None => 5,
        Some("junk") => 6,
        _ => 7,
    }
}

/// Brings the store's folder list in line with the server's and returns the folders to sync,
/// the Inbox first. Folders that are gone from the server leave the store with their mail.
pub(crate) async fn refresh(conn: &mut Connection, store: &Mutex<Store>) -> Result<Vec<Folder>> {
    let remote = conn.list_folders().await?;
    let gmail = conn.is_gmail();
    let mut wanted: Vec<(RemoteFolder, Option<&'static str>)> = remote
        .into_iter()
        .filter(|f| !f.has("\\noselect") && !f.has("\\nonexistent"))
        .map(|f| {
            let role = role_of(&f);
            (f, role)
        })
        .filter(|(_, role)| !gmail || gmail_wants(*role))
        .collect();
    wanted.sort_by(|a, b| (rank(a.1), &a.0.name).cmp(&(rank(b.1), &b.0.name)));

    let store = store.lock().unwrap();
    let mut out = Vec::new();
    for (f, role) in &wanted {
        out.push(store.upsert_folder(&f.name, *role)?);
    }
    for old in store.folders()? {
        if old.remote_id.is_none() && !out.iter().any(|f| f.id == old.id) {
            store.remove_folder(old.id)?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, attrs: &[&str]) -> RemoteFolder {
        RemoteFolder {
            name: name.into(),
            delimiter: Some("/".into()),
            attributes: attrs.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn flags_win_over_names() {
        assert_eq!(role_of(&folder("Gesendet", &["\\trash"])), Some("trash"));
        assert_eq!(
            role_of(&folder("[Gmail]/All Mail", &["\\all"])),
            Some("all")
        );
        assert_eq!(role_of(&folder("inbox", &[])), Some("inbox"));
    }

    #[test]
    fn names_are_read_in_five_languages() {
        for (name, role) in [
            ("Sent Items", "sent"),
            ("Gönderilmiş Öğeler", "sent"),
            ("INBOX/Gesendete Elemente", "sent"),
            ("Éléments envoyés", "sent"),
            ("Elementos enviados", "sent"),
            ("Taslaklar", "drafts"),
            ("Entwürfe", "drafts"),
            ("Brouillons", "drafts"),
            ("Borradores", "drafts"),
            ("Silinmiş Öğeler", "trash"),
            ("Papierkorb", "trash"),
            ("Corbeille", "trash"),
            ("Papelera", "trash"),
            ("Gereksiz E-posta", "junk"),
            ("Junk-E-Mail", "junk"),
            ("Courrier indésirable", "junk"),
            ("Correo no deseado", "junk"),
            ("Arşiv", "archive"),
            ("Archiv", "archive"),
            ("Archivo", "archive"),
        ] {
            assert_eq!(role_of(&folder(name, &[])), Some(role), "{name}");
        }
        assert_eq!(role_of(&folder("Receipts", &[])), None);
    }

    #[test]
    fn gmail_keeps_three_folders() {
        assert!(gmail_wants(Some("all")));
        assert!(gmail_wants(Some("junk")));
        assert!(gmail_wants(Some("trash")));
        assert!(!gmail_wants(Some("sent")));
        assert!(!gmail_wants(Some("inbox")));
        assert!(!gmail_wants(None));
    }
}

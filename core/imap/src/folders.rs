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
            "posta inviata",
            "inviati",
            "elementi inviati",
            "itens enviados",
            "mensagens enviadas",
            "verzonden",
            "verzonden items",
            "отправленные",
            "отправленные элементы",
            "送信済み",
            "送信済みアイテム",
            "已发送",
            "已发送邮件",
            "已发送项",
            "寄件備份",
            "已傳送郵件",
            "보낸편지함",
            "보낸 편지함",
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
            "bozze",
            "rascunhos",
            "concepten",
            "черновики",
            "下書き",
            "草稿",
            "草稿箱",
            "임시보관함",
            "임시 보관함",
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
            "cestino",
            "posta eliminata",
            "elementi eliminati",
            "lixeira",
            "itens excluídos",
            "itens eliminados",
            "prullenbak",
            "verwijderde items",
            "корзина",
            "удалённые",
            "удаленные",
            "удалённые элементы",
            "удаленные элементы",
            "ゴミ箱",
            "削除済みアイテム",
            "已删除邮件",
            "已删除项目",
            "刪除的郵件",
            "已刪除郵件",
            "휴지통",
            "지운편지함",
            "지운 편지함",
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
            "posta indesiderata",
            "lixo",
            "lixo eletrônico",
            "lixo eletrónico",
            "ongewenste e-mail",
            "ongewenst",
            "спам",
            "нежелательная почта",
            "нежелательные",
            "迷惑メール",
            "垃圾邮件",
            "垃圾箱",
            "垃圾郵件",
            "스팸",
            "스팸 메일함",
            "정크 메일",
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
            "archivio",
            "arquivo",
            "archief",
            "архив",
            "アーカイブ",
            "归档",
            "存档",
            "封存",
            "보관함",
            "보관 처리됨",
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

/// The role of a folder: its SPECIAL-USE flag when it has one, else its name in English or one
/// of the 12 languages of the first wave.
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
    fn names_are_read_in_the_first_wave_of_languages() {
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
            ("Posta inviata", "sent"),
            ("Bozze", "drafts"),
            ("Cestino", "trash"),
            ("Posta indesiderata", "junk"),
            ("Archivio", "archive"),
            ("Itens enviados", "sent"),
            ("Rascunhos", "drafts"),
            ("Lixeira", "trash"),
            ("Lixo eletrônico", "junk"),
            ("Arquivo", "archive"),
            ("Verzonden items", "sent"),
            ("Concepten", "drafts"),
            ("Prullenbak", "trash"),
            ("Ongewenste e-mail", "junk"),
            ("Archief", "archive"),
            ("Отправленные", "sent"),
            ("Черновики", "drafts"),
            ("Корзина", "trash"),
            ("Спам", "junk"),
            ("Архив", "archive"),
            ("送信済みアイテム", "sent"),
            ("下書き", "drafts"),
            ("ゴミ箱", "trash"),
            ("迷惑メール", "junk"),
            ("アーカイブ", "archive"),
            ("已发送邮件", "sent"),
            ("草稿", "drafts"),
            ("已删除邮件", "trash"),
            ("垃圾邮件", "junk"),
            ("归档", "archive"),
            ("寄件備份", "sent"),
            ("刪除的郵件", "trash"),
            ("垃圾郵件", "junk"),
            ("封存", "archive"),
            ("보낸편지함", "sent"),
            ("임시보관함", "drafts"),
            ("휴지통", "trash"),
            ("스팸", "junk"),
            ("보관함", "archive"),
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

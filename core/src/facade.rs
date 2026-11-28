use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use lazymail_sync::{system_clock, Clock};

use crate::accounts;
use crate::callbacks::{EventListener, TokenProvider, Tokens, Wrap, WrappingKey};
use crate::error::{CoreError, Result};
use crate::shared::Shared;
use crate::types::{
    AccountInfo, AccountSetup, AddedAccount, AppPasswordHelp, DeviceInfo, Discovered, FlagSet,
    FolderInfo, JoinOffer, JoinRequest, MessageDetail, MessageSummary, OutboxEntry, OutboxReport,
    OutgoingMessage, ProviderKind, PullResult, SearchRequest, SettingEntry, SettingsSetup,
    SettingsState, SyncSummary,
};

/// The mail core of one device: its accounts, their stores and the settings sync. Every call
/// blocks until it is done, so the apps call it from a background thread.
#[derive(uniffi::Object)]
pub struct Core {
    rt: tokio::runtime::Runtime,
    shared: Arc<Shared>,
}

impl Core {
    /// Like `new`, with the clock the settings sync and the lease read, for tests that move time.
    #[doc(hidden)]
    pub fn with_clock(
        data_dir: &Path,
        device_name: &str,
        wrapping_key: Box<dyn WrappingKey>,
        tokens: Box<dyn TokenProvider>,
        clock: Clock,
    ) -> Result<Core> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("lazymail")
            .enable_all()
            .build()?;
        let shared = Shared::open(
            data_dir,
            device_name,
            Wrap(wrapping_key),
            Tokens(Arc::from(tokens)),
            clock,
            rt.handle().clone(),
        )?;
        let accounts = shared.accounts.lock().unwrap().clone();
        for acc in &accounts {
            shared.recover_outbox(acc)?;
        }
        Ok(Core { rt, shared })
    }

    fn run<T>(&self, work: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        self.rt.block_on(work)
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

#[uniffi::export]
impl Core {
    /// Opens the core on a folder of its own. The wrapping key protects every secret kept in it;
    /// the token provider hands out Microsoft access tokens.
    #[uniffi::constructor]
    pub fn new(
        data_dir: String,
        device_name: String,
        wrapping_key: Box<dyn WrappingKey>,
        tokens: Box<dyn TokenProvider>,
    ) -> Result<Arc<Core>, CoreError> {
        Core::with_clock(
            Path::new(&data_dir),
            &device_name,
            wrapping_key,
            tokens,
            system_clock(),
        )
        .map(Arc::new)
    }

    pub fn set_listener(&self, listener: Option<Box<dyn EventListener>>) {
        self.shared.events.set(listener.map(Arc::from));
    }

    // Accounts

    /// Finds the server settings for an address: the built-in table, then the provider's
    /// autoconfig and DNS. `None` means the person types them.
    pub fn discover(&self, address: String) -> Option<Discovered> {
        self.rt.block_on(accounts::discover_settings(&address))
    }

    /// The steps and link for making an app password, for the providers that need one.
    pub fn app_password_help(&self, provider: ProviderKind) -> Option<AppPasswordHelp> {
        accounts::password_help(provider)
    }

    /// Cleans up a pasted app password and checks its shape; returns the text to use.
    pub fn check_app_password(
        &self,
        provider: ProviderKind,
        input: String,
    ) -> Result<String, CoreError> {
        accounts::check_password(provider, &input)
    }

    /// Signs in once and saves the account only if that works. The first account with a
    /// mailbox becomes the sync account and starts the settings sync.
    pub fn add_account(&self, setup: AccountSetup) -> Result<AddedAccount, CoreError> {
        let added = self.run(self.shared.add_account(setup))?;
        if self.shared.is_running() {
            self.shared
                .start_account(&self.shared.account(&added.account.id)?);
        }
        Ok(added)
    }

    /// Deletes the account's mail, index and secrets on this device. It never revokes the
    /// provider's grant.
    pub fn remove_account(&self, account_id: String) -> Result<(), CoreError> {
        self.run(self.shared.remove_account(&account_id))
    }

    pub fn accounts(&self) -> Vec<AccountInfo> {
        self.shared.account_infos()
    }

    /// Replaces the app password of an account that needs a new sign-in, and signs in with it.
    pub fn set_app_password(&self, account_id: String, password: String) -> Result<(), CoreError> {
        self.run(self.shared.set_password(&account_id, &password))
    }

    // Syncing

    /// Starts keeping every account up to date in the background; progress and changes come
    /// through the listener.
    pub fn start_sync(&self) {
        self.shared.start();
    }

    pub fn stop_sync(&self) {
        self.shared.stop();
        if self.shared.lease_held.load(Ordering::Relaxed) {
            let _ = self.rt.block_on(self.shared.drop_lease());
        }
    }

    /// One pass over the account: its mail, then its Outbox.
    pub fn sync_now(&self, account_id: String) -> Result<SyncSummary, CoreError> {
        self.run(self.shared.sync_account(&account_id))
    }

    // Reading

    pub fn folders(&self, account_id: String) -> Result<Vec<FolderInfo>, CoreError> {
        self.shared.folders(&account_id)
    }

    /// A folder's messages, newest first.
    pub fn messages(
        &self,
        account_id: String,
        folder_id: i64,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<MessageSummary>, CoreError> {
        self.shared.messages(&account_id, folder_id, offset, limit)
    }

    pub fn message(&self, account_id: String, message_id: i64) -> Result<MessageDetail, CoreError> {
        self.shared.message(&account_id, message_id)
    }

    /// Downloads an attachment if this device does not have it yet.
    pub fn attachment(
        &self,
        account_id: String,
        message_id: i64,
        attachment_id: i64,
    ) -> Result<Vec<u8>, CoreError> {
        self.run(
            self.shared
                .attachment(&account_id, message_id, attachment_id),
        )
    }

    /// Keyword search in one account, newest first.
    pub fn search(
        &self,
        account_id: String,
        request: SearchRequest,
    ) -> Result<Vec<MessageSummary>, CoreError> {
        self.shared.search(&account_id, &request)
    }

    // Changing mail

    pub fn set_flags(
        &self,
        account_id: String,
        message_id: i64,
        flags: FlagSet,
    ) -> Result<(), CoreError> {
        self.run(self.shared.set_flags(&account_id, message_id, flags))
    }

    pub fn move_message(
        &self,
        account_id: String,
        message_id: i64,
        folder_id: i64,
    ) -> Result<(), CoreError> {
        self.run(self.shared.move_message(&account_id, message_id, folder_id))
    }

    /// Deletes for good over IMAP; over Graph the message goes to Deleted Items first.
    pub fn delete_message(&self, account_id: String, message_id: i64) -> Result<(), CoreError> {
        self.run(self.shared.delete_message(&account_id, message_id))
    }

    // Sending

    /// Puts a message in the account's Outbox. It goes out on the next run of the Outbox, at
    /// once when syncing is started.
    pub fn send(
        &self,
        account_id: String,
        message: OutgoingMessage,
    ) -> Result<OutboxEntry, CoreError> {
        self.shared.queue(&account_id, message)
    }

    pub fn outbox(&self, account_id: String) -> Result<Vec<OutboxEntry>, CoreError> {
        self.shared.outbox(&account_id)
    }

    /// Sends what is due and files the Sent copies.
    pub fn run_outbox(&self, account_id: String) -> Result<OutboxReport, CoreError> {
        let acc = self.shared.account(&account_id)?;
        self.run(self.shared.run_outbox(&acc))
    }

    /// Queues a failed message again, to go out now.
    pub fn retry_outbox_item(&self, account_id: String, id: i64) -> Result<(), CoreError> {
        self.shared.outbox_retry(&account_id, id)
    }

    pub fn remove_outbox_item(&self, account_id: String, id: i64) -> Result<(), CoreError> {
        self.shared.outbox_remove(&account_id, id)
    }

    // Settings

    pub fn settings_state(&self) -> SettingsState {
        self.shared.settings_state()
    }

    /// Tries again to start the settings sync on the sync account.
    pub fn setup_settings(&self) -> SettingsSetup {
        self.rt.block_on(self.shared.setup_settings())
    }

    pub fn pull_settings(&self) -> Result<PullResult, CoreError> {
        self.run(self.shared.pull_settings())
    }

    pub fn settings(&self) -> Result<Vec<SettingEntry>, CoreError> {
        self.run(self.shared.settings())
    }

    pub fn setting(&self, key: String) -> Result<Option<String>, CoreError> {
        self.run(self.shared.setting(&key))
    }

    pub fn set_setting(&self, key: String, value: String) -> Result<(), CoreError> {
        self.run(self.shared.set_setting(&key, Some(&value)))
    }

    pub fn remove_setting(&self, key: String) -> Result<(), CoreError> {
        self.run(self.shared.set_setting(&key, None))
    }

    // Devices

    pub fn devices(&self) -> Result<Vec<DeviceInfo>, CoreError> {
        self.run(self.shared.devices())
    }

    /// New device: asks the person's other devices to let it in.
    pub fn request_join(&self) -> Result<(), CoreError> {
        self.run(self.shared.request_join())
    }

    /// New device: the devices that answered, each with the code to type on that device.
    pub fn join_offers(&self) -> Result<Vec<JoinOffer>, CoreError> {
        self.run(self.shared.join_offers())
    }

    /// New device: takes the key from the device whose own screen showed `shown`.
    pub fn finish_join(&self, device_id: String, shown: String) -> Result<(), CoreError> {
        self.run(self.shared.finish_join(&device_id, &shown))
    }

    /// Device with the key: requests waiting for an answer.
    pub fn join_requests(&self) -> Result<Vec<JoinRequest>, CoreError> {
        self.run(self.shared.join_requests())
    }

    /// Device with the key: lets the new device see this one and its code.
    pub fn offer_join(&self, nonce: String) -> Result<(), CoreError> {
        self.run(self.shared.offer_join(&nonce))
    }

    /// Device with the key: the code to read out and type on the new device.
    pub fn join_code(&self, nonce: String) -> Result<String, CoreError> {
        self.run(self.shared.join_code(&nonce))
    }

    /// Device with the key: `typed` is the code the new device shows.
    pub fn approve_join(&self, nonce: String, typed: String) -> Result<(), CoreError> {
        self.run(self.shared.approve_join(&nonce, &typed))
    }

    pub fn deny_join(&self, nonce: String) -> Result<(), CoreError> {
        self.run(self.shared.deny_join(&nonce))
    }

    /// Gets the settings key from the printed recovery code, with no other device.
    pub fn recover(&self, recovery_code: String) -> Result<(), CoreError> {
        self.run(self.shared.recover(&recovery_code))
    }

    /// Makes a new recovery code, for when the printed one is lost.
    pub fn reissue_recovery(&self) -> Result<String, CoreError> {
        self.run(self.shared.reissue_recovery())
    }

    /// Ends a device and gives the others a new key; returns the new recovery code. `keep` is
    /// every device id the person saw and agreed should stay.
    pub fn remove_device(&self, device_id: String, keep: Vec<String>) -> Result<String, CoreError> {
        self.run(self.shared.remove_device(&device_id, &keep))
    }

    /// Starts a new key for exactly these devices; returns the new recovery code.
    pub fn keep_only(&self, keep: Vec<String>) -> Result<String, CoreError> {
        self.run(self.shared.keep_only(&keep))
    }

    // Scheduled work

    /// Chooses the computer that does scheduled work, or none.
    pub fn set_main_computer(&self, device_id: Option<String>) -> Result<(), CoreError> {
        self.run(self.shared.set_main_computer(device_id.as_deref()))
    }

    pub fn main_computer(&self) -> Result<Option<String>, CoreError> {
        self.run(self.shared.main_computer())
    }

    /// Claims or renews the lease; true when this device may do scheduled work now. Another
    /// device takes over only after the main computer has been silent for 10 minutes.
    pub fn hold_lease(&self) -> Result<bool, CoreError> {
        self.run(self.shared.hold_lease())
    }

    pub fn drop_lease(&self) -> Result<(), CoreError> {
        self.run(self.shared.drop_lease())
    }

    pub fn lease_holder(&self) -> Result<Option<String>, CoreError> {
        self.run(self.shared.lease_holder())
    }
}

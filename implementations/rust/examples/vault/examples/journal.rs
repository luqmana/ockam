/// Example: A Digital Journal
///
/// Use Case:
/// With the Ockam Vault, I can manage and use secrets to secure my data.
/// I can encrypt my data with a block cipher using a secret key stored in the Vault.
/// I can sign and verify my data with a public and private keypair stored in the Vault.
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};

use ockam_vault::ockam_vault_core::{
    Hasher, KeyId, KeyIdVault, PublicKey, Secret, SecretAttributes, SecretPersistence, SecretType,
    SecretVault, Signer, SymmetricVault, Verifier, AES256_SECRET_LENGTH, CURVE25519_SECRET_LENGTH,
};
use ockam_vault::SoftwareVault;

type Bytes = Vec<u8>;

/// A Journal Entry. All fields are optional. An unencrypted journal has a message and no payload.
/// An encrypted journal has a payload and no message. Decryption and Encryption swap these fields.
/// * `message` - plain text message
/// * `payload` - encrypted message
/// * `signature` - signature of payload if present OR message, if not.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
struct Entry {
    message: Option<Bytes>,
    payload: Option<Bytes>,
    signature: Option<Bytes>,
}

impl Entry {
    fn new(s: &str) -> Self {
        Entry {
            message: Some(s.as_bytes().to_vec()),
            payload: None,
            signature: None,
        }
    }

    fn is_encrypted(&self) -> bool {
        self.payload.is_some()
    }

    fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

impl Display for Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;

        if self.is_encrypted() {
            write!(f, "<ENCRYPTED>")?;
        } else {
            write!(
                f,
                "{}",
                String::from_utf8(self.clone().message.unwrap_or_default()).unwrap_or_default()
            )?;
        }

        if self.is_signed() {
            write!(f, "\t<SIGNED>")?;
        }
        write!(f, "]")
    }
}

/// A Journal is a set of Entries, plus Ockam Vault.
struct Journal {
    entries: BTreeSet<Entry>,
    vault: SoftwareVault,
    message_secret: Secret,
    key_id: KeyId,
}

impl Default for Journal {
    /// Create a Vault, encryption key for messages, and public/private keypair for signing.
    fn default() -> Self {
        let mut vault = SoftwareVault::default();

        let aes_attributes = SecretAttributes::new(
            SecretType::Aes,
            SecretPersistence::Ephemeral,
            AES256_SECRET_LENGTH,
        );

        let message_secret = match vault.secret_generate(aes_attributes) {
            Ok(secret) => secret,
            Err(e) => panic!("{}", e),
        };

        let signing_attributes = SecretAttributes::new(
            SecretType::Curve25519,
            SecretPersistence::Persistent,
            CURVE25519_SECRET_LENGTH,
        );

        let signing_secret = vault.secret_generate(signing_attributes).unwrap();

        let public_key = vault.secret_public_key_get(&signing_secret).unwrap();

        let key_id = vault.compute_key_id_for_public_key(&public_key).unwrap();

        Journal {
            entries: BTreeSet::new(),
            vault,
            message_secret,
            key_id,
        }
    }
}

// For demo purposes only, this is not secure use of these parameters.
const NONCE: &[u8; 12] = b"journal_0123";
const AAD: &[u8; 12] = b"journal_0000";

/// A Journal implementation using Ockam Vault.
impl Journal {
    /// Encrypt a journal entry. Encryption is AES in GCM mode, with AEAD.
    fn encrypt(&mut self, mut entry: Entry) -> Entry {
        let message = entry.message.unwrap();

        if let Ok(encrypted) =
            self.vault
                .aead_aes_gcm_encrypt(&self.message_secret, &message, NONCE, AAD)
        {
            entry.message = None;
            entry.payload = Some(encrypted);
        } else {
            panic!("Encryption failed!")
        }

        entry
    }

    /// Sign content with the Journal's secret key.
    fn sign(&mut self, mut entry: Entry, bytes: &[u8]) -> Entry {
        let secret = self.get_signing_secret();

        if let Ok(signature) = self.vault.sign(&secret, bytes) {
            entry.signature = Some(signature.into());
        } else {
            panic!("Signing failed!")
        }
        entry
    }

    /// Sign the journal encrypted payload.
    fn sign_payload(&mut self, entry: Entry) -> Entry {
        let payload = entry.clone().payload.unwrap();
        self.sign(entry, &payload)
    }

    /// Sign the journal unencrypted message.
    fn sign_message(&mut self, entry: Entry) -> Entry {
        let message = entry.clone().message.unwrap();
        self.sign(entry, &message)
    }

    /// Add a new encrypted, signed entry to the Journal.
    fn add_secret_entry(&mut self, entry: Entry) {
        let entry = self.encrypt(entry);
        self.add_entry(entry);
    }

    /// Add a new plaintext, signed entry to the Journal.
    fn add_public_entry(&mut self, entry: Entry) {
        self.add_entry(entry);
    }

    /// Sign and add an entry to the journal.
    fn add_entry(&mut self, entry: Entry) {
        let entry = if entry.is_encrypted() {
            self.sign_payload(entry)
        } else {
            self.sign_message(entry)
        };

        self.entries.insert(entry);
    }

    /// Retrieve the signing secret from the Vault using the Key ID
    fn get_signing_secret(&mut self) -> Secret {
        self.vault
            .get_secret_by_key_id(self.key_id.as_str())
            .unwrap()
    }

    /// Retrieve the public key from the Vault.
    fn get_verifying_key(&mut self) -> PublicKey {
        let secret = self.get_signing_secret();
        self.vault.secret_public_key_get(&secret).unwrap()
    }

    /// Verify the signature of an entry.
    fn verify(&mut self, entry: &Entry) -> bool {
        let signature = entry.signature.as_ref().unwrap();

        let input = if entry.is_encrypted() {
            entry.payload.as_ref().unwrap()
        } else {
            entry.message.as_ref().unwrap()
        };

        let public_key = self.get_verifying_key();

        let sig64 = <&[u8; 64]>::try_from(signature.as_slice()).unwrap();

        matches!(
            self.vault
                .verify(sig64, public_key.as_ref(), input.as_slice()),
            Ok(_)
        )
    }

    /// Decrypt a journal entry.
    fn decrypt(&mut self, entry: &Entry) -> Option<String> {
        let cipher = entry.payload.as_ref().unwrap();
        if let Ok(plain) =
            self.vault
                .aead_aes_gcm_decrypt(&self.message_secret, cipher.as_slice(), NONCE, AAD)
        {
            Some(String::from_utf8(plain.to_vec()).unwrap())
        } else {
            None
        }
    }

    /// Verify and gather unencrypted Journal entries, hash the contents, sign the hash.
    fn digest(&mut self) -> Option<String> {
        let mut content = String::new();

        for entry in &self.entries {
            // Journal Digests contain unencrypted, signed entries.
            if entry.is_encrypted() || !entry.is_signed() {
                continue;
            }

            // Print each message on a new line.
            if let Some(message) = &entry.message {
                let v = message.to_vec();
                let s = String::from_utf8(v).unwrap_or_default();
                content += &*format!("{}\n", s.as_str());
            }
        }

        if content.is_empty() {
            None
        } else if let Ok(hash) = self.vault.sha256(content.as_bytes()) {
            let secret = self.get_signing_secret();

            let signed_hash = self.vault.sign(&secret, &hash).unwrap();
            let encoded_hash = base64::encode(signed_hash);

            content += &*format!("\n\nKeyID: {}\n", self.key_id.as_str());
            content += &*format!("Signed Hash: {}\n", encoded_hash.as_str());
            Some(content)
        } else {
            None
        }
    }

    /// Print out all Journal entries, verifying and decrypting each one.
    fn read(&mut self) {
        let entries = self.entries.clone();
        for entry in &entries {
            println!("Reading entry: {}", entry);
            if entry.is_signed() {
                if self.verify(entry) {
                    println!("✅\tVerified!");
                } else {
                    println!("❌\tVerification failed.")
                }
            }

            if entry.is_encrypted() {
                if let Some(message) = self.decrypt(entry) {
                    println!("✅\tDecrypted! Message: {}", message);
                } else {
                    println!("❌\tDecryption failed.")
                }
            }
        }
    }
}

/// A toy journal. Contains encrypted, signed entries.
fn main() {
    let mut journal = Journal::default();

    journal.add_secret_entry(Entry::new("my secret"));
    journal.add_public_entry(Entry::new("Happy New Year!"));
    journal.add_secret_entry(Entry::new("another secret"));
    journal.add_public_entry(Entry::new("Happy Friday!"));
    journal.read();

    if let Some(digest) = journal.digest() {
        println!("\nDigest\n------\n{}", digest);
    }
}

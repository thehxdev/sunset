use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::Rng;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 32;
pub const VERIFY_MSG_LEN: usize = 32;
pub const VERIFY_MAGIC: &[u8; VERIFY_MSG_LEN] = b"SUNSET_V1_AUTH_OK_STREAMCIPHER!\0";

pub const ARGON2_M_COST: u32 = 65536; // 64 MB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Authentication failed: invalid key or corrupted data")]
    AuthFailed,
    #[error("Encryption failed: {0}")]
    EncryptFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptFailed(String),
    #[error("Key derivation failed: {0}")]
    KdfFailed(String),
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; KEY_SIZE]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

pub fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_SIZE],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<MasterKey, CryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_SIZE))
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;

    Ok(MasterKey(key_bytes))
}

pub fn encrypt_block(
    key: &MasterKey,
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from(*nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(&xnonce, payload)
        .map_err(|e| CryptoError::EncryptFailed(e.to_string()))
}

pub fn decrypt_block(
    key: &MasterKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let xnonce = XNonce::from(*nonce);
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };
    cipher
        .decrypt(&xnonce, payload)
        .map_err(|_| CryptoError::AuthFailed)
}

#[allow(clippy::type_complexity)]
pub fn create_verification_token(
    key: &MasterKey,
) -> Result<([u8; NONCE_SIZE], [u8; VERIFY_MSG_LEN], [u8; TAG_SIZE]), CryptoError> {
    let nonce = generate_nonce();
    let ciphertext = encrypt_block(key, &nonce, VERIFY_MAGIC, b"SUNSET_VERIFY_AAD")?;
    if ciphertext.len() != VERIFY_MSG_LEN + TAG_SIZE {
        return Err(CryptoError::EncryptFailed(
            "Unexpected token length".to_string(),
        ));
    }
    let mut ct = [0u8; VERIFY_MSG_LEN];
    let mut tag = [0u8; TAG_SIZE];
    ct.copy_from_slice(&ciphertext[..VERIFY_MSG_LEN]);
    tag.copy_from_slice(&ciphertext[VERIFY_MSG_LEN..]);
    Ok((nonce, ct, tag))
}

pub fn verify_key(
    key: &MasterKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8; VERIFY_MSG_LEN],
    tag: &[u8; TAG_SIZE],
) -> Result<(), CryptoError> {
    let mut full = [0u8; VERIFY_MSG_LEN + TAG_SIZE];
    full[..VERIFY_MSG_LEN].copy_from_slice(ciphertext);
    full[VERIFY_MSG_LEN..].copy_from_slice(tag);
    let decrypted = decrypt_block(key, nonce, &full, b"SUNSET_VERIFY_AAD")?;
    if decrypted.as_slice() == VERIFY_MAGIC {
        Ok(())
    } else {
        Err(CryptoError::AuthFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_and_verification() {
        let salt = generate_salt();
        let key = derive_key("super_secret_password", &salt, 1024, 1, 1).unwrap();
        let (nonce, ct, tag) = create_verification_token(&key).unwrap();

        // Correct key verifies
        assert!(verify_key(&key, &nonce, &ct, &tag).is_ok());

        // Wrong key fails
        let wrong_key = derive_key("wrong_password", &salt, 1024, 1, 1).unwrap();
        assert!(verify_key(&wrong_key, &nonce, &ct, &tag).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_block() {
        let key = MasterKey([42u8; KEY_SIZE]);
        let nonce = generate_nonce();
        let plaintext = b"Hello, stream cipher authenticated world!";
        let aad = 12345u64.to_le_bytes();

        let ciphertext = encrypt_block(&key, &nonce, plaintext, &aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_block(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(decrypt_block(&key, &nonce, &tampered, &aad).is_err());

        // Wrong AAD (e.g. block swapped)
        let wrong_aad = 99999u64.to_le_bytes();
        assert!(decrypt_block(&key, &nonce, &ciphertext, &wrong_aad).is_err());
    }
}

/// AES-128-CBC decryption wrapper (no padding).
///
/// Apple HLS sample encryption uses AES-128-CBC but does NOT use PKCS#7 padding;
/// only complete 16-byte blocks are encrypted, and trailing bytes are left in the clear.

use aes::Aes128;
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit};

type Aes128CbcDec = Decryptor<Aes128>;

/// Decrypt `data` in-place using AES-128-CBC with no padding.
/// `data.len()` must be a multiple of 16.
///
/// Returns `Err` if the data length is not block-aligned.
pub fn decrypt_aes128_cbc(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<(), String> {
    if data.len() % 16 != 0 {
        return Err(format!(
            "Data length {} is not a multiple of 16",
            data.len()
        ));
    }
    if data.is_empty() {
        return Ok(());
    }

    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(data)
        .map_err(|e| format!("AES-CBC decryption failed: {}", e))?;

    Ok(())
}

/// Decrypt only the complete 16-byte blocks in `data`, leaving any trailing bytes untouched.
pub fn decrypt_aes128_cbc_partial(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let block_len = (data.len() / 16) * 16;
    if block_len > 0 {
        // unwrap is safe because we ensured block alignment
        decrypt_aes128_cbc(key, iv, &mut data[..block_len]).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use cbc::Encryptor;
    use cipher::{BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = Encryptor<Aes128>;

    fn encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
        let encryptor = Aes128CbcEnc::new(key.into(), iv.into());
        encryptor
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(data, data.len())
            .unwrap();
    }

    #[test]
    fn round_trip() {
        let key = [0x01u8; 16];
        let iv = [0x00u8; 16];
        let original = [0xAA; 32];
        let mut data = original;
        encrypt(&key, &iv, &mut data);
        assert_ne!(data, original);
        decrypt_aes128_cbc(&key, &iv, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn partial_decrypt_leaves_trailing() {
        let key = [0x02u8; 16];
        let iv = [0x00u8; 16];
        let mut data = [0xBB; 20]; // 16 encrypted + 4 trailing
        let original_trailing = [0xBB; 4];
        encrypt(&key, &iv, &mut data[..16]);
        decrypt_aes128_cbc_partial(&key, &iv, &mut data);
        assert_eq!(data[..16], [0xBB; 16]);
        assert_eq!(data[16..], original_trailing);
    }

    #[test]
    fn empty_data() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let mut data = [];
        assert!(decrypt_aes128_cbc(&key, &iv, &mut data).is_ok());
    }

    #[test]
    fn non_aligned_fails() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let mut data = [0u8; 10];
        assert!(decrypt_aes128_cbc(&key, &iv, &mut data).is_err());
    }
}

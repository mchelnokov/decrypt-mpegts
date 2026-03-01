/// AAC ADTS frame decryption for HLS sample encryption.
///
/// Per Apple's spec:
/// - Each ADTS frame is decrypted independently.
/// - Skip the ADTS header (7 or 9 bytes depending on protection_absent).
/// - Skip 16 bytes of leader after the header.
/// - Decrypt all complete 16-byte blocks; trailing bytes are unencrypted.
/// - IV resets to the provided IV for each frame.

use crate::crypto::aes_cbc;

/// Returns the ADTS frame header size: 7 if protection_absent=1, 9 if protection_absent=0.
fn adts_header_size(frame: &[u8]) -> usize {
    if frame.len() < 4 {
        return 7; // fallback
    }
    if frame[1] & 0x01 == 0 {
        9 // CRC present
    } else {
        7
    }
}

/// Returns the ADTS frame size as encoded in the header.
fn adts_frame_size(frame: &[u8]) -> usize {
    if frame.len() < 6 {
        return 0;
    }
    let size = ((frame[3] as usize & 0x03) << 11)
        | ((frame[4] as usize) << 3)
        | ((frame[5] as usize) >> 5);
    size
}

/// Check if the buffer starts with an ADTS sync word (0xFFF).
fn is_adts_sync(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xF0) == 0xF0
}

/// Decrypt AAC elementary stream data (sequence of ADTS frames) in-place.
pub fn decrypt_aac(key: &[u8; 16], iv: &[u8; 16], data: &mut Vec<u8>) {
    let mut offset = 0;

    while offset < data.len() {
        if !is_adts_sync(&data[offset..]) {
            break;
        }

        let header_size = adts_header_size(&data[offset..]);
        let frame_size = adts_frame_size(&data[offset..]);
        if frame_size == 0 || offset + frame_size > data.len() {
            break;
        }

        let leader = 16;
        let skip = header_size + leader;

        if skip < frame_size {
            let enc_start = offset + skip;
            let enc_end = offset + frame_size;
            if enc_start < enc_end {
                aes_cbc::decrypt_aes128_cbc_partial(key, iv, &mut data[enc_start..enc_end]);
            }
        }

        offset += frame_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adts_header_size_protection_absent() {
        // protection_absent = 1 → 7 bytes
        let frame = [0xFF, 0xF1, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(adts_header_size(&frame), 7);
    }

    #[test]
    fn adts_header_size_with_crc() {
        // protection_absent = 0 → 9 bytes
        let frame = [0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(adts_header_size(&frame), 9);
    }

    #[test]
    fn adts_frame_size_parsing() {
        // Frame size = 100 (0x64)
        // Byte 3 bits [1:0] = 0, Byte 4 = 0x0C, Byte 5 bits [7:5] = 4
        // 0x0C << 3 = 96, | 4 = 100
        let frame = [0xFF, 0xF1, 0x00, 0x00, 0x0C, 0x80, 0x00];
        assert_eq!(adts_frame_size(&frame), 100);
    }

    #[test]
    fn is_adts_sync_valid() {
        assert!(is_adts_sync(&[0xFF, 0xF1]));
        assert!(is_adts_sync(&[0xFF, 0xF0]));
    }

    #[test]
    fn is_adts_sync_invalid() {
        assert!(!is_adts_sync(&[0xFF, 0xE0]));
        assert!(!is_adts_sync(&[0x00, 0xF0]));
    }

    #[test]
    fn decrypt_aac_no_frames() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut data = vec![0x00; 10];
        decrypt_aac(&key, &iv, &mut data);
        // Should not panic, data unchanged since no ADTS sync
    }
}

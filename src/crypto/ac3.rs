/// AC-3 / E-AC-3 syncframe decryption for HLS sample encryption.
///
/// Per Apple's spec:
/// - Each syncframe is decrypted independently.
/// - Skip 16 bytes of leader.
/// - Decrypt all complete 16-byte blocks; trailing bytes are unencrypted.
/// - IV resets to the provided IV for each frame.

use crate::crypto::aes_cbc;

/// AC-3 sync word: 0x0B77
fn is_ac3_sync(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x0B && data[1] == 0x77
}

/// Get AC-3 frame size from the header.
/// For standard AC-3, frame size is determined by frmsizecod and sample rate.
/// This is a simplified version using the frmsizecod table for 48kHz.
fn ac3_frame_size(frame: &[u8]) -> Option<usize> {
    if frame.len() < 7 {
        return None;
    }

    // Check for E-AC-3 (bsid >= 11)
    let bsid = (frame[5] >> 3) & 0x1F;
    if bsid > 10 {
        // E-AC-3: frame size is in bytes 2-3
        let frmsiz = ((frame[2] as usize & 0x07) << 8) | frame[3] as usize;
        return Some((frmsiz + 1) * 2);
    }

    // Standard AC-3
    let fscod = (frame[4] >> 6) & 0x03;
    let frmsizecod = (frame[4] & 0x3F) as usize;

    // Frame size table (words) for each sample rate code.
    // Index by frmsizecod (0..37).
    static FRAME_SIZE_48K: [usize; 38] = [
        64, 64, 80, 80, 96, 96, 112, 112, 128, 128, 160, 160, 192, 192, 224, 224, 256, 256, 320,
        320, 384, 384, 448, 448, 512, 512, 640, 640, 768, 768, 896, 896, 1024, 1024, 1152, 1152,
        1280, 1280,
    ];
    static FRAME_SIZE_44K: [usize; 38] = [
        69, 70, 87, 88, 104, 105, 121, 122, 139, 140, 174, 175, 208, 209, 243, 244, 278, 279,
        348, 349, 417, 418, 487, 488, 557, 558, 696, 697, 835, 836, 975, 976, 1114, 1115, 1253,
        1254, 1393, 1394,
    ];
    static FRAME_SIZE_32K: [usize; 38] = [
        96, 96, 120, 120, 144, 144, 168, 168, 192, 192, 240, 240, 288, 288, 336, 336, 384, 384,
        480, 480, 576, 576, 672, 672, 768, 768, 960, 960, 1152, 1152, 1344, 1344, 1536, 1536,
        1728, 1728, 1920, 1920,
    ];

    if frmsizecod >= 38 {
        return None;
    }

    let words = match fscod {
        0 => FRAME_SIZE_48K[frmsizecod],
        1 => FRAME_SIZE_44K[frmsizecod],
        2 => FRAME_SIZE_32K[frmsizecod],
        _ => return None, // fscod=3 is reserved
    };

    Some(words * 2) // words → bytes
}

/// Decrypt AC-3/E-AC-3 elementary stream data (sequence of syncframes) in-place.
pub fn decrypt_ac3(key: &[u8; 16], iv: &[u8; 16], data: &mut Vec<u8>) {
    let mut offset = 0;

    while offset < data.len() {
        if !is_ac3_sync(&data[offset..]) {
            break;
        }

        let frame_size = match ac3_frame_size(&data[offset..]) {
            Some(s) if s > 0 && offset + s <= data.len() => s,
            _ => break,
        };

        let leader = 16;
        if leader < frame_size {
            let enc_start = offset + leader;
            let enc_end = offset + frame_size;
            aes_cbc::decrypt_aes128_cbc_partial(key, iv, &mut data[enc_start..enc_end]);
        }

        offset += frame_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ac3_sync_detection() {
        assert!(is_ac3_sync(&[0x0B, 0x77, 0x00]));
        assert!(!is_ac3_sync(&[0x0B, 0x78, 0x00]));
        assert!(!is_ac3_sync(&[0x00, 0x77, 0x00]));
    }

    #[test]
    fn ac3_frame_size_48k() {
        // fscod=0 (48kHz), frmsizecod=4 → 96 words = 192 bytes
        let mut frame = [0u8; 7];
        frame[0] = 0x0B;
        frame[1] = 0x77;
        frame[4] = 0x04; // fscod=0, frmsizecod=4
        frame[5] = 0x40; // bsid=8
        assert_eq!(ac3_frame_size(&frame), Some(192));
    }

    #[test]
    fn decrypt_ac3_no_frames() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut data = vec![0x00; 10];
        decrypt_ac3(&key, &iv, &mut data);
    }
}

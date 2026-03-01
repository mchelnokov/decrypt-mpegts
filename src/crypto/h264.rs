/// H.264 NAL unit decryption for HLS sample encryption.
///
/// Per Apple's spec:
/// - Only NAL types 1 (coded slice) and 5 (IDR slice) are encrypted; others pass through.
/// - Remove emulation prevention bytes (EPB: 0x00 0x00 0x03) before decryption.
/// - Skip first 32 bytes (1 NAL type byte + 31 leader bytes).
/// - Apply 1:9 pattern: decrypt 16 bytes, then skip min(144, remaining) bytes, repeat.
///   An encrypted block is only produced when bytes_remaining > 16 (strictly greater).
/// - IV resets per NAL unit; CBC chains continuously within a NAL.
/// - Re-insert EPBs after decryption.

use crate::crypto::aes_cbc;

/// Remove emulation prevention bytes: 0x00 0x00 0x03 XX (where XX is 0x00..=0x03)
/// becomes 0x00 0x00 XX. Returns the cleaned RBSP data.
fn remove_epb(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        if i + 3 < data.len()
            && data[i] == 0x00
            && data[i + 1] == 0x00
            && data[i + 2] == 0x03
            && data[i + 3] <= 0x03
        {
            out.push(0x00);
            out.push(0x00);
            // Skip the 0x03 EPB byte, the next byte (0x00-0x03) will be pushed normally.
            i += 3;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }

    out
}

/// Insert emulation prevention bytes by scanning for 0x00 0x00 XX (XX=0x00..=0x03)
/// and inserting a 0x03 byte before XX. This produces a valid Annex B NAL unit.
#[cfg(test)]
fn insert_epb(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 128);
    let mut zeros = 0u32;

    for &b in data {
        if zeros >= 2 && b <= 0x03 {
            out.push(0x03);
            zeros = 0;
        }

        if b == 0x00 {
            zeros += 1;
        } else {
            zeros = 0;
        }

        out.push(b);
    }

    out
}

/// A NAL unit boundary: start code position, NAL data start, NAL data end.
struct NalBoundary {
    /// Byte offset where the start code begins (0x00 0x00 0x01 or 0x00 0x00 0x00 0x01).
    sc_offset: usize,
    /// Byte offset of the first NAL byte (right after start code).
    data_start: usize,
    /// Byte offset one past the last NAL byte (exclusive).
    data_end: usize,
}

/// Find NAL unit boundaries using Annex B start codes.
fn find_nal_boundaries(data: &[u8]) -> Vec<NalBoundary> {
    let mut nals = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let sc_offset;
        let start;
        if i + 4 <= data.len()
            && data[i] == 0x00
            && data[i + 1] == 0x00
            && data[i + 2] == 0x00
            && data[i + 3] == 0x01
        {
            sc_offset = i;
            start = i + 4;
        } else if i + 3 <= data.len()
            && data[i] == 0x00
            && data[i + 1] == 0x00
            && data[i + 2] == 0x01
        {
            sc_offset = i;
            start = i + 3;
        } else {
            i += 1;
            continue;
        }

        // Find the end (next start code or end of data)
        let mut end = start;
        while end < data.len() {
            if end + 3 <= data.len()
                && data[end] == 0x00
                && data[end + 1] == 0x00
                && (data[end + 2] == 0x01
                    || (data[end + 2] == 0x00 && end + 3 < data.len() && data[end + 3] == 0x01))
            {
                break;
            }
            end += 1;
        }

        if start < end {
            nals.push(NalBoundary {
                sc_offset,
                data_start: start,
                data_end: end,
            });
        }
        i = end;
    }

    nals
}

/// Decrypt a single NAL unit's RBSP data using the 1:9 pattern.
///
/// `rbsp` is the NAL data with EPBs already removed.
/// Modifies `rbsp` in-place.
fn decrypt_nal_rbsp(key: &[u8; 16], iv: &[u8; 16], rbsp: &mut [u8]) {
    let nal_len = rbsp.len();
    let skip = 32;
    // Per spec: NAL units <= 48 bytes are completely unencrypted.
    if nal_len <= 48 {
        return;
    }

    // Apply 1:9 pattern with CBC chaining within this NAL.
    let mut current_iv = *iv;
    let mut offset = skip;
    loop {
        let remaining = nal_len - offset;
        // Per spec: only encrypt when bytes_remaining > 16 (strictly greater).
        if remaining <= 16 {
            break;
        }

        // Save ciphertext for CBC chaining before decryption.
        let mut next_iv = [0u8; 16];
        next_iv.copy_from_slice(&rbsp[offset..offset + 16]);

        aes_cbc::decrypt_aes128_cbc(key, &current_iv, &mut rbsp[offset..offset + 16]).unwrap();

        current_iv = next_iv;
        offset += 16;
        let remaining = nal_len - offset;
        offset += remaining.min(144);
    }
}

/// Decrypt H.264 elementary stream data.
///
/// The data should contain Annex B NAL units (start code delimited).
/// NAL types 1 and 5 are decrypted using the 1:9 pattern.
///
/// Per the Apple SAMPLE-AES spec:
/// 1. Find NAL boundaries via Annex B start codes.
/// 2. For encrypted NAL types (1, 5): remove EPBs, decrypt RBSP.
/// 3. Reconstruct the ES data with start codes and (possibly resized) NAL data.
pub fn decrypt_h264(key: &[u8; 16], iv: &[u8; 16], data: &mut Vec<u8>) {
    let boundaries = find_nal_boundaries(data);
    if boundaries.is_empty() {
        return;
    }

    let mut output = Vec::with_capacity(data.len());

    // Copy any bytes before the first NAL start code.
    if boundaries[0].sc_offset > 0 {
        output.extend_from_slice(&data[..boundaries[0].sc_offset]);
    }

    for (idx, nal) in boundaries.iter().enumerate() {
        // Copy the start code.
        output.extend_from_slice(&data[nal.sc_offset..nal.data_start]);

        let nal_data = &data[nal.data_start..nal.data_end];
        let nal_type = nal_data[0] & 0x1F;

        if (nal_type == 1 || nal_type == 5) && nal_data.len() > 48 {
            let mut rbsp = remove_epb(nal_data);
            decrypt_nal_rbsp(key, iv, &mut rbsp);
            output.extend_from_slice(&rbsp);
        } else {
            output.extend_from_slice(nal_data);
        }

        // Copy any bytes between this NAL's end and the next NAL's start code.
        let gap_end = if idx + 1 < boundaries.len() {
            boundaries[idx + 1].sc_offset
        } else {
            data.len()
        };
        if nal.data_end < gap_end {
            output.extend_from_slice(&data[nal.data_end..gap_end]);
        }
    }

    *data = output;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epb_removal() {
        // 00 00 03 01 → 00 00 01 (valid EPB, XX=0x01)
        let data = vec![0x00, 0x00, 0x03, 0x01, 0xAA];
        let clean = remove_epb(&data);
        assert_eq!(clean, vec![0x00, 0x00, 0x01, 0xAA]);
    }

    #[test]
    fn epb_removal_only_valid_epb() {
        // 00 00 03 04 → NOT an EPB (XX=0x04), should stay as-is
        let data = vec![0x00, 0x00, 0x03, 0x04];
        let clean = remove_epb(&data);
        assert_eq!(clean, data);
    }

    #[test]
    fn epb_insertion_scan() {
        // 00 00 01 should become 00 00 03 01
        let data = vec![0x00, 0x00, 0x01, 0xAA];
        let with_epb = insert_epb(&data);
        assert_eq!(with_epb, vec![0x00, 0x00, 0x03, 0x01, 0xAA]);
    }

    #[test]
    fn epb_insertion_multiple_zeros() {
        // 00 00 00 00 → 00 00 03 00 00 (insert EPB after first pair)
        let data = vec![0x00, 0x00, 0x00, 0x00];
        let with_epb = insert_epb(&data);
        // After 00 00, next is 00 (<=03), insert 03 → 00 00 03 00
        // Now zeros resets. Then 00 → zeros=1. Then data ends.
        assert_eq!(with_epb, vec![0x00, 0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn epb_round_trip() {
        // Insert then remove should give back original
        let original = vec![0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x01];
        let with_epb = insert_epb(&original);
        let clean = remove_epb(&with_epb);
        assert_eq!(clean, original);
    }

    #[test]
    fn epb_no_sequences() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let clean = remove_epb(&data);
        assert_eq!(clean, data);
        let with_epb = insert_epb(&data);
        assert_eq!(with_epb, data);
    }

    #[test]
    fn find_nals_annex_b() {
        // Two NAL units: 00 00 01 <nal1> 00 00 00 01 <nal2>
        let data = vec![
            0x00, 0x00, 0x01, 0x67, 0x42, 0x00, // NAL1 (SPS, type 7)
            0x00, 0x00, 0x00, 0x01, 0x65, 0xAA, 0xBB, // NAL2 (IDR, type 5)
        ];
        let boundaries = find_nal_boundaries(&data);
        assert_eq!(boundaries.len(), 2);
        assert_eq!(data[boundaries[0].data_start] & 0x1F, 7); // SPS
        assert_eq!(data[boundaries[1].data_start] & 0x1F, 5); // IDR
    }

    #[test]
    fn decrypt_short_nal_noop() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        // NAL unit shorter than 48 bytes → no decryption
        let mut data = vec![0x00, 0x00, 0x01, 0x65]; // IDR NAL, but very short
        data.extend_from_slice(&[0xAA; 20]);
        let original = data.clone();
        decrypt_h264(&key, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn non_encrypted_nal_types_unchanged() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        // SPS (type 7) should not be decrypted
        let mut data = vec![0x00, 0x00, 0x01, 0x67];
        data.extend_from_slice(&[0xBB; 100]);
        let original = data.clone();
        decrypt_h264(&key, &iv, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn decrypt_with_epb_in_nal() {
        // Build a NAL with an EPB in the clear leader area.
        // Start code + NAL type 5 (IDR)
        let mut data = vec![0x00, 0x00, 0x01, 0x65];
        // 31 leader bytes, put an EPB sequence at positions 10-12 within leader
        let mut leader = vec![0xAA; 31];
        leader[9] = 0x00;
        leader[10] = 0x00;
        leader[11] = 0x03; // EPB byte
        leader[12] = 0x01; // protected byte
        data.extend_from_slice(&leader);
        // Add enough data for encryption (need > 48 bytes total NAL data)
        data.extend_from_slice(&[0xCC; 100]);
        // Total NAL data = 1 + 31 + 100 = 132 bytes, well above 48

        // This should not panic and should process the EPBs correctly
        let key = [0u8; 16];
        let iv = [0u8; 16];
        decrypt_h264(&key, &iv, &mut data);

        // Verify start code is preserved
        assert_eq!(&data[..3], &[0x00, 0x00, 0x01]);
        // Verify NAL type is preserved
        assert_eq!(data[3] & 0x1F, 5);
    }
}

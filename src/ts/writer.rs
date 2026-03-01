/// Re-packetize decrypted PES data back into 188-byte TS packets.

use crate::ts::packet::{SYNC_BYTE, TS_PACKET_SIZE};

/// Re-packetize a complete PES packet into TS packets for a given PID.
///
/// - `pid`: The PID for the output packets.
/// - `cc_start`: Starting continuity counter (will be incremented per packet).
/// - `pes_data`: The full PES packet (including PES header).
///
/// Returns the generated TS packets and the next continuity counter value.
pub fn packetize(pid: u16, cc_start: u8, pes_data: &[u8]) -> (Vec<u8>, u8) {
    let mut output = Vec::new();
    let mut offset = 0usize;
    let mut cc = cc_start;
    let mut first = true;

    while offset < pes_data.len() {
        let mut pkt = [0xFFu8; TS_PACKET_SIZE];
        pkt[0] = SYNC_BYTE;

        let pid_hi = ((pid >> 8) & 0x1F) as u8;
        let pid_lo = (pid & 0xFF) as u8;
        pkt[1] = pid_hi | if first { 0x40 } else { 0 }; // PUSI on first packet
        pkt[2] = pid_lo;
        pkt[3] = 0x10 | (cc & 0x0F); // payload only, continuity counter

        let max_payload = TS_PACKET_SIZE - 4;
        let remaining = pes_data.len() - offset;
        let payload_len = remaining.min(max_payload);

        if payload_len < max_payload {
            // Need stuffing via adaptation field.
            let stuff_bytes = max_payload - payload_len;
            if stuff_bytes == 1 {
                // adaptation_field_length = 0 (just the length byte itself)
                pkt[3] = 0x30 | (cc & 0x0F); // adaptation + payload
                pkt[4] = 0x00; // adaptation field length = 0
                pkt[5..5 + payload_len].copy_from_slice(&pes_data[offset..offset + payload_len]);
            } else {
                // adaptation field with stuffing
                pkt[3] = 0x30 | (cc & 0x0F); // adaptation + payload
                let af_len = stuff_bytes - 1; // -1 for the length byte itself
                pkt[4] = af_len as u8;
                if af_len > 0 {
                    pkt[5] = 0x00; // flags byte
                    // Fill remaining adaptation field with 0xFF stuffing
                    for b in pkt.iter_mut().take(5 + af_len).skip(6) {
                        *b = 0xFF;
                    }
                }
                let payload_start = 5 + af_len;
                pkt[payload_start..payload_start + payload_len]
                    .copy_from_slice(&pes_data[offset..offset + payload_len]);
            }
        } else {
            pkt[4..4 + payload_len].copy_from_slice(&pes_data[offset..offset + payload_len]);
        }

        output.extend_from_slice(&pkt);
        offset += payload_len;
        cc = cc.wrapping_add(1) & 0x0F;
        first = false;
    }

    (output, cc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packetize_small_payload() {
        let pes = vec![0xAA; 100];
        let (output, next_cc) = packetize(0x100, 0, &pes);
        assert_eq!(output.len(), TS_PACKET_SIZE);
        assert_eq!(output[0], SYNC_BYTE);
        assert!(output[1] & 0x40 != 0); // PUSI
        assert_eq!(next_cc, 1);
    }

    #[test]
    fn packetize_exact_one_packet() {
        let pes = vec![0xBB; 184];
        let (output, next_cc) = packetize(0x100, 5, &pes);
        assert_eq!(output.len(), TS_PACKET_SIZE);
        // payload only, no adaptation field needed
        assert_eq!(output[3] & 0x30, 0x10);
        assert_eq!(next_cc, 6);
    }

    #[test]
    fn packetize_multi_packet() {
        let pes = vec![0xCC; 300];
        let (output, _) = packetize(0x200, 0, &pes);
        // 300 bytes needs 2 packets: 184 + 116
        assert_eq!(output.len(), TS_PACKET_SIZE * 2);
        // First packet: PUSI set
        assert!(output[1] & 0x40 != 0);
        // Second packet: PUSI not set
        assert!(output[TS_PACKET_SIZE + 1] & 0x40 == 0);
    }

    #[test]
    fn continuity_counter_wraps() {
        let pes = vec![0xDD; 184 * 3];
        let (_, next_cc) = packetize(0x100, 14, &pes);
        // 14, 15, 0 → next is 1
        assert_eq!(next_cc, 1);
    }
}

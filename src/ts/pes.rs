/// PES (Packetized Elementary Stream) header parser and multi-packet accumulator.

/// Parse a PES header and return the offset where the ES data begins.
///
/// PES header structure:
///   - 3 bytes: start code prefix (0x00 0x00 0x01)
///   - 1 byte:  stream id
///   - 2 bytes: PES packet length
///   - 2 bytes: flags (optional header data)
///   - 1 byte:  PES header data length
///   - N bytes: optional fields (PTS/DTS, etc.)
///   - payload
pub fn pes_payload_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 6 {
        return None;
    }
    // Verify start code prefix
    if data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x01 {
        return None;
    }

    let stream_id = data[3];

    // Stream IDs that don't have the extended header (padding, private_stream_2, etc.)
    // For these, payload starts at byte 6.
    if stream_id == 0xBE  // padding_stream
        || stream_id == 0xBF // private_stream_2
        || stream_id == 0xF0 // ECM
        || stream_id == 0xF1 // EMM
        || stream_id == 0xF2 // DSMCC
        || stream_id == 0xF8
    // H.222.1 type E
    {
        return Some(6);
    }

    // Standard PES with optional header needs at least 9 bytes.
    if data.len() < 9 {
        return None;
    }

    let pes_header_data_length = data[8] as usize;
    let offset = 9 + pes_header_data_length;

    if offset > data.len() {
        return None;
    }

    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pes_offset_standard() {
        // Minimal PES: start code + stream_id(0xE0=video) + length(0) + flags + header_data_length(5)
        let mut data = vec![0x00, 0x00, 0x01, 0xE0, 0x00, 0x00, 0x80, 0x80, 5];
        data.extend_from_slice(&[0u8; 5]); // PTS bytes
        data.push(0xAA); // first ES byte
        assert_eq!(pes_payload_offset(&data), Some(14));
    }

    #[test]
    fn pes_offset_no_optional_header() {
        // header_data_length = 0
        let data = vec![0x00, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x80, 0x00, 0];
        assert_eq!(pes_payload_offset(&data), Some(9));
    }

    #[test]
    fn pes_offset_padding_stream() {
        let data = vec![0x00, 0x00, 0x01, 0xBE, 0x00, 0x10];
        assert_eq!(pes_payload_offset(&data), Some(6));
    }

    #[test]
    fn pes_bad_start_code() {
        let data = vec![0x00, 0x00, 0x02, 0xE0, 0x00, 0x00, 0x80, 0x80, 0];
        assert_eq!(pes_payload_offset(&data), None);
    }
}

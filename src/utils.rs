use crate::types::Pmtu;

#[inline]
fn get_first_packet_length(va: u64, pmtu: u32) -> u32 {
    let offset = va % pmtu as u64;
    if offset == 0 {
        pmtu
    } else {
        pmtu - offset as u32
    }
}

pub(crate) fn calculate_packet_cnt(pmtu: Pmtu, raddr: u64, total_len: u32) -> u32 {
    let first_pkt_max_len = get_first_packet_length(raddr, u32::from(&pmtu));
    let first_pkt_len = total_len.min(first_pkt_max_len);

    1 + (total_len - first_pkt_len).div_ceil(u64::from(&pmtu) as u32)
}

pub(crate) fn u8_slice_to_u64(slice: &[u8]) -> u64 {
    slice.iter().fold(0, |a, b| (a << 8) + *b as u64)
}

#[cfg(test)]
mod tests {
    use crate::types::Pmtu;

    #[test]
    fn test_calculate_packet_cnt() {
        let raddr = 0;
        let total_len = 4096;
        let packet_cnt = super::calculate_packet_cnt(Pmtu::Mtu1024, raddr, total_len);
        assert_eq!(packet_cnt, 4);

        for raddr in 1..1023 {
            let packet_cnt = super::calculate_packet_cnt(Pmtu::Mtu1024, raddr, total_len);
            assert_eq!(packet_cnt, 5);
        }
    }
}

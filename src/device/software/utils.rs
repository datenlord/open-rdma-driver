use crate::device::Pmtu;

/// Convert Pmtu enumeration to u32
#[inline]
pub fn get_pmtu(pmtu: &Pmtu) -> u32 {
    match pmtu {
        Pmtu::Mtu256 => 256,
        Pmtu::Mtu512 => 512,
        Pmtu::Mtu1024 => 1024,
        Pmtu::Mtu2048 => 2048,
        Pmtu::Mtu4096 => 4096,
    }
}

/// Get the length of the first packet.
///
/// A buffer will be divided into multiple packets if any slice is crossed the boundary of pmtu
/// For example, if pmtu = 256 and va = 254, then the first packet can be at most 2 bytes.
/// If pmtu = 256 and va = 256, then the first packet can be at most 256 bytes.
#[inline]
pub fn get_first_packet_length(va: u64, pmtu: u32) -> u32 {
    let offset = va % pmtu as u64;
    if offset == 0 {
        pmtu
    } else {
        pmtu - offset as u32
    }
}

#[cfg(test)]
mod test{
    use crate::device::software::utils::get_first_packet_length;

    #[test]
    fn test_helper_function_first_length() {
        assert_eq!(get_first_packet_length(254, 256), 2);
        assert_eq!(get_first_packet_length(256, 256), 256);
        assert_eq!(get_first_packet_length(257, 256), 255);

        assert_eq!(get_first_packet_length(1023, 1024), 1);
        assert_eq!(get_first_packet_length(1024, 1024), 1024);
        assert_eq!(get_first_packet_length(1025, 1024), 1023);
    }
}
enum CsrIndex {
    CsrIdxRbBaseAddrLow = 0x0,
    CsrIdxRbBaseAddrHigh = 0x1,
    CsrIdxRbHead = 0x2,
    CsrIdxRbTail = 0x3,
}

const fn generate_csr_addr(is_h2c: bool, queue_index: usize, reg_index: CsrIndex) -> usize {
    let mut a = if is_h2c { 1 } else { 0 };
    a <<= 3;
    a |= queue_index & 0b111;
    a <<= 10;
    a |= reg_index as usize & 0x3FF;
    a <<= 2;
    a
}

pub(crate) const CSR_ADDR_CMD_REQ_QUEUE_ADDR_LOW: usize =
    generate_csr_addr(true, 0, CsrIndex::CsrIdxRbBaseAddrLow);
pub(crate) const CSR_ADDR_CMD_REQ_QUEUE_ADDR_HIGH: usize =
    generate_csr_addr(true, 0, CsrIndex::CsrIdxRbBaseAddrHigh);
pub(crate) const CSR_ADDR_CMD_REQ_QUEUE_HEAD: usize =
    generate_csr_addr(true, 0, CsrIndex::CsrIdxRbHead);
pub(crate) const CSR_ADDR_CMD_REQ_QUEUE_TAIL: usize =
    generate_csr_addr(true, 0, CsrIndex::CsrIdxRbTail);

pub(crate) const CSR_ADDR_CMD_RESP_QUEUE_HEAD: usize =
    generate_csr_addr(false, 0, CsrIndex::CsrIdxRbHead);
pub(crate) const CSR_ADDR_CMD_RESP_QUEUE_TAIL: usize =
    generate_csr_addr(false, 0, CsrIndex::CsrIdxRbTail);
pub(crate) const CSR_ADDR_CMD_RESP_QUEUE_ADDR_LOW: usize =
    generate_csr_addr(false, 0, CsrIndex::CsrIdxRbBaseAddrLow);
pub(crate) const CSR_ADDR_CMD_RESP_QUEUE_ADDR_HIGH: usize =
    generate_csr_addr(false, 0, CsrIndex::CsrIdxRbBaseAddrHigh);

pub(crate) const CSR_ADDR_SEND_QUEUE_HEAD: usize =
    generate_csr_addr(true, 1, CsrIndex::CsrIdxRbHead);
pub(crate) const CSR_ADDR_SEND_QUEUE_TAIL: usize =
    generate_csr_addr(true, 1, CsrIndex::CsrIdxRbTail);
pub(crate) const CSR_ADDR_SEND_QUEUE_ADDR_LOW: usize =
    generate_csr_addr(true, 1, CsrIndex::CsrIdxRbBaseAddrLow);
pub(crate) const CSR_ADDR_SEND_QUEUE_ADDR_HIGH: usize =
    generate_csr_addr(true, 1, CsrIndex::CsrIdxRbBaseAddrHigh);

pub(crate) const CSR_ADDR_META_REPORT_QUEUE_HEAD: usize =
    generate_csr_addr(false, 1, CsrIndex::CsrIdxRbHead);
pub(crate) const CSR_ADDR_META_REPORT_QUEUE_TAIL: usize =
    generate_csr_addr(false, 1, CsrIndex::CsrIdxRbTail);
pub(crate) const CSR_ADDR_META_REPORT_QUEUE_ADDR_LOW: usize =
    generate_csr_addr(false, 1, CsrIndex::CsrIdxRbBaseAddrLow);
pub(crate) const CSR_ADDR_META_REPORT_QUEUE_ADDR_HIGH: usize =
    generate_csr_addr(false, 1, CsrIndex::CsrIdxRbBaseAddrHigh);

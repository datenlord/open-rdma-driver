pub(crate) const RINGBUF_PAGE_SIZE: usize = 4096;
pub(crate) const RINGBUF_DEPTH: usize = 128;
pub(crate) const RINGBUF_ELEMENT_SIZE: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct RingbufPointer<const D: usize> {
    idx_with_guard: usize,
}

const fn is_power_of_2(v: usize) -> bool {
    (v & (v - 1)) == 0
}

impl<const D: usize> RingbufPointer<D> {
    const GUARD_MASK: usize = D;
    const IDX_MASK: usize = D - 1;

    fn new(init_value: usize) -> Self {
        if !is_power_of_2(D) {
            panic!("invalid ringbuf depth.");
        }
        Self {
            idx_with_guard: init_value,
        }
    }

    fn get_idx(&self) -> usize {
        self.idx_with_guard & Self::IDX_MASK
    }
    fn get_guard(&self) -> usize {
        self.idx_with_guard & Self::GUARD_MASK
    }
    pub fn get_index_with_guard(&self) -> usize {
        self.idx_with_guard
    }

    fn incr_pointer(&mut self, v: usize) {
        // Note: should check v not greater than ringbuf depth here, but it will take extra cpu effort.
        self.idx_with_guard += v;
    }
}

pub(crate) struct Ringbuf<const D: usize, const E: usize> {
    buffer: Vec<u8>,
    start_pa: usize,
    align_offset: usize,

    head: RingbufPointer<D>,
    tail: RingbufPointer<D>,
}

impl<const D: usize, const E: usize> Ringbuf<D, E> {
    pub(crate) fn new() -> Self {
        let ringbuf_size_in_byte = D * E;
        if ringbuf_size_in_byte < RINGBUF_PAGE_SIZE {
            panic!("invalid ringbuf size.");
        }

        if !is_power_of_2(E) {
            panic!("invalid element size.");
        }

        let buffer = Vec::with_capacity(ringbuf_size_in_byte + RINGBUF_PAGE_SIZE);
        let buf_addr = buffer.as_ptr() as usize;
        let aligned_buf_addr = (buf_addr + RINGBUF_PAGE_SIZE) & (!(RINGBUF_PAGE_SIZE - 1));
        let align_offset = buf_addr & (RINGBUF_PAGE_SIZE - 1);
        Self {
            buffer,
            start_pa: aligned_buf_addr,
            align_offset,
            head: RingbufPointer::new(0),
            tail: RingbufPointer::new(0),
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        (self.head.get_idx() == self.tail.get_idx()
            && self.head.get_guard() != self.tail.get_guard())
    }

    pub(crate) fn is_empty(&self) -> bool {
        (self.head.get_idx() == self.tail.get_idx()
            && self.head.get_guard() == self.tail.get_guard())
    }
    pub(crate) fn push(&mut self, item: &[u8; E]) {
        let start_offset = self.align_offset + self.head.get_idx() * E;
        for (idx, ele) in self.buffer[start_offset..start_offset + E]
            .iter_mut()
            .enumerate()
        {
            *ele = item[idx];
        }
        self.head.incr_pointer(1);
    }

    pub(crate) fn pop(&mut self, item: &mut [u8; E]) {
        let start_offset = self.align_offset + self.tail.get_idx() * E;
        for (idx, ele) in self.buffer[start_offset..start_offset + E]
            .iter_mut()
            .enumerate()
        {
            item[idx] = *ele;
        }
        self.tail.incr_pointer(1);
    }

    pub(crate) fn set_head(&mut self, p: RingbufPointer<D>) {
        self.head = p;
    }

    pub(crate) fn set_tail(&mut self, p: RingbufPointer<D>) {
        self.tail = p;
    }

    pub(crate) fn get_head(&self) -> RingbufPointer<D> {
        self.head
    }

    pub(crate) fn get_tail(&self) -> RingbufPointer<D> {
        self.tail
    }
}

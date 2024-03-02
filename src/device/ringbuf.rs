use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex, MutexGuard,
};

pub(super) struct Ringbuf<const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> {
    buf: Mutex<Box<[u8]>>,
    aligned_ringbuf_addr: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
}

pub(super) struct RingbufWriter<
    'a,
    const DEPTH: usize,
    const ELEM_SIZE: usize,
    const PAGE_SIZE: usize,
> {
    buf: MutexGuard<'a, Box<[u8]>>,
    aligned_ringbuf_addr: usize,
    head: &'a AtomicUsize,
    total_cnt: usize,
    written_cnt: usize,
}

pub(super) struct RingbufReader<
    'a,
    const DEPTH: usize,
    const ELEM_SIZE: usize,
    const PAGE_SIZE: usize,
> {
    buf: MutexGuard<'a, Box<[u8]>>,
    aligned_ringbuf_addr: usize,
    head: usize,
    tail: &'a AtomicUsize,
    read_cnt: usize,
}

const fn _is_power_of_2(v: usize) -> bool {
    (v & (v - 1)) == 0
}

impl<const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize>
    Ringbuf<DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    const _PTR_GUARD_MASK: usize = DEPTH;
    const PTR_IDX_MASK: usize = DEPTH - 1;

    const _IS_DEPTH_POWER_OF_2: () = assert!(_is_power_of_2(DEPTH), "invalid ringbuf depth");
    const _IS_ELEM_SIZE_POWER_OF_2: () = assert!(_is_power_of_2(ELEM_SIZE), "invalid element size");
    const _IS_RINGBUF_SIZE_VALID: () =
        assert!(DEPTH * ELEM_SIZE >= PAGE_SIZE, "invalid ringbuf size");

    pub(super) fn new() -> Self {
        let buf = Mutex::new(vec![0; DEPTH * ELEM_SIZE + PAGE_SIZE].into_boxed_slice());
        let buf_addr = buf.lock().unwrap().as_ref().as_ptr() as usize;
        let aligned_ringbuf_addr = (buf_addr + PAGE_SIZE) & (!(PAGE_SIZE - 1));

        Self {
            buf,
            aligned_ringbuf_addr,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Get space for writing `desc_cnt` descriptors to the ring buffer.
    pub(super) fn write(
        &self,
        desc_cnt: usize,
    ) -> Option<RingbufWriter<'_, DEPTH, ELEM_SIZE, PAGE_SIZE>> {
        // TODO: check if there is enough space in the ring buffer

        Some(RingbufWriter {
            buf: self.buf.lock().unwrap(),
            aligned_ringbuf_addr: self.aligned_ringbuf_addr,
            head: &self.head,
            total_cnt: desc_cnt,
            written_cnt: 0,
        })
    }

    /// Prepare to read some descriptors from the ring buffer.
    pub(super) fn read(&self) -> RingbufReader<'_, DEPTH, ELEM_SIZE, PAGE_SIZE> {
        RingbufReader {
            buf: self.buf.lock().unwrap(),
            aligned_ringbuf_addr: self.aligned_ringbuf_addr,
            head: self.head.load(Ordering::Acquire),
            tail: &self.tail,
            read_cnt: 0,
        }
    }

    pub(super) fn head(&self) -> usize {
        self.head.load(Ordering::Acquire)
    }

    pub(super) fn tail(&self) -> usize {
        self.tail.load(Ordering::Acquire)
    }

    pub(super) fn set_head(&self, value: usize) {
        // TODO: Check is Ordering::Release enough ?
        self.head.store(value, Ordering::Release);
    }

    pub(super) fn set_tail(&self, value: usize) {
        self.tail.store(value, Ordering::Release);
    }

    pub(super) fn get_ringbuf_addr(&self) -> usize {
        self.aligned_ringbuf_addr
    }
}

impl<'a, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> Iterator
    for RingbufWriter<'a, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    type Item = &'a mut [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.written_cnt == self.total_cnt {
            return None;
        }

        let idx = (self.head.load(Ordering::Acquire) + self.written_cnt)
            & Ringbuf::<DEPTH, ELEM_SIZE, PAGE_SIZE>::PTR_IDX_MASK;
        let offset = idx * ELEM_SIZE;
        let ptr = unsafe { (self.aligned_ringbuf_addr as *mut u8).add(offset) };

        self.written_cnt += 1;

        Some(unsafe { std::slice::from_raw_parts_mut(ptr, ELEM_SIZE) })
    }
}

/// Drop the writer to update the head pointer.
impl<'a, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> Drop
    for RingbufWriter<'a, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn drop(&mut self) {
        self.head.fetch_add(self.written_cnt, Ordering::Release);
    }
}

impl<'a, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> Iterator
    for RingbufReader<'a, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.tail.load(Ordering::Acquire) + self.read_cnt == self.head {
            return None;
        }

        let idx = (self.tail.load(Ordering::Acquire) + self.read_cnt)
            & Ringbuf::<DEPTH, ELEM_SIZE, PAGE_SIZE>::PTR_IDX_MASK;
        let offset = idx * ELEM_SIZE;
        let ptr = unsafe { (self.aligned_ringbuf_addr as *const u8).add(offset) };

        self.read_cnt += 1;

        Some(unsafe { std::slice::from_raw_parts(ptr, ELEM_SIZE) })
    }
}

/// Drop the reader to update the tail pointer.
impl<'a, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> Drop
    for RingbufReader<'a, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn drop(&mut self) {
        self.tail.fetch_add(self.read_cnt, Ordering::Release);
    }
}

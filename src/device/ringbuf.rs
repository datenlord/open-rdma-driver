use std::{
    slice,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, MutexGuard,
    },
};

pub(super) struct Ringbuf<const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> {
    buf: Mutex<&'static mut [u8]>,
    buf_padding: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
}

pub(super) struct RingbufWriter<
    'a,
    const DEPTH: usize,
    const ELEM_SIZE: usize,
    const PAGE_SIZE: usize,
> {
    buf: MutexGuard<'a, &'static mut [u8]>,
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
    buf: MutexGuard<'a, &'static mut [u8]>,
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

    /// Return (ringbuf, ringbuf virtual memory address)
    pub(super) fn new() -> (Self, usize) {
        let raw_buf = Box::leak(vec![0; DEPTH * ELEM_SIZE + PAGE_SIZE].into_boxed_slice());
        let buf_padding = raw_buf.as_ptr() as usize & (PAGE_SIZE - 1);
        let buf_addr = raw_buf[buf_padding..].as_ptr() as usize;
        let buf = Mutex::new(&mut raw_buf[buf_padding..]);

        (
            Self {
                buf,
                buf_padding,
                head: AtomicUsize::new(0),
                tail: AtomicUsize::new(0),
            },
            buf_addr,
        )
    }

    /// Get space for writing `desc_cnt` descriptors to the ring buffer.
    pub(super) fn write(
        &self,
        desc_cnt: usize,
    ) -> Option<RingbufWriter<'_, DEPTH, ELEM_SIZE, PAGE_SIZE>> {
        // TODO: check if there is enough space in the ring buffer

        Some(RingbufWriter {
            buf: self.buf.lock().unwrap(),
            head: &self.head,
            total_cnt: desc_cnt,
            written_cnt: 0,
        })
    }

    /// Prepare to read some descriptors from the ring buffer.
    pub(super) fn read(&self) -> RingbufReader<'_, DEPTH, ELEM_SIZE, PAGE_SIZE> {
        RingbufReader {
            buf: self.buf.lock().unwrap(),
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

    pub(super) fn set_head(&self, head: usize) {
        self.head.store(head, Ordering::Release);
    }

    pub(super) fn set_tail(&self, tail: usize) {
        self.tail.store(tail, Ordering::Release);
    }
}

impl<const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> Drop
    for Ringbuf<DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn drop(&mut self) {
        let buf = self.buf.get_mut().unwrap().as_mut_ptr();
        let raw_buf = unsafe {
            slice::from_raw_parts_mut(buf.sub(self.buf_padding), DEPTH * ELEM_SIZE + PAGE_SIZE)
        };

        drop(unsafe { Box::from_raw(raw_buf) });
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
        let ptr = unsafe { self.buf.as_mut_ptr().add(offset) };

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
        let ptr = unsafe { self.buf.as_ptr().add(offset) };

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

use std::{
    slice,
    sync::{Mutex, MutexGuard},
};

pub(super) trait CsrWriterProxy {
    fn write_head(&self, data: u32);
    fn read_tail(&self) -> u32;
}

pub(super) trait CsrReaderProxy {
    fn write_tail(&self, data: u32);
    fn read_head(&self) -> u32;
}


/// The Ringbuf is a circular buffer used comunicate between the host and the card.
pub(super) struct Ringbuf<
    T,
    const DEPTH: usize,
    const ELEM_SIZE: usize,
    const PAGE_SIZE: usize,
> {
    buf: Mutex<&'static mut [u8]>,
    buf_padding: usize,
    head: usize,
    tail: usize,
    proxy: T,
}

pub(super) struct RingbufWriter<
    'a,
    'proxy,
    T: CsrWriterProxy,
    const DEPTH: usize,
    const ELEM_SIZE: usize,
    const PAGE_SIZE: usize,
> {
    buf: MutexGuard<'a, &'static mut [u8]>,
    head: &'a mut usize,
    tail: &'a mut usize,
    written_cnt: usize,
    proxy: &'proxy T,
}

pub(super) struct RingbufReader<
    'a,
    'proxy,
    T: CsrReaderProxy,
    const DEPTH: usize,
    const ELEM_SIZE: usize,
    const PAGE_SIZE: usize,
> {
    buf: MutexGuard<'a, &'static mut [u8]>,
    head: &'a mut usize,
    tail: &'a mut usize,
    read_cnt: usize,
    proxy: &'proxy T,
}

const fn _is_power_of_2(v: usize) -> bool {
    (v & (v - 1)) == 0
}

impl<T, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize>
    Ringbuf<T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    const _PTR_GUARD_MASK: usize = DEPTH;
    const PTR_IDX_MASK: usize = DEPTH - 1;

    const _IS_DEPTH_POWER_OF_2: () = assert!(_is_power_of_2(DEPTH), "invalid ringbuf depth");
    const _IS_ELEM_SIZE_POWER_OF_2: () = assert!(_is_power_of_2(ELEM_SIZE), "invalid element size");
    const _IS_RINGBUF_SIZE_VALID: () =
        assert!(DEPTH * ELEM_SIZE >= PAGE_SIZE, "invalid ringbuf size");

    /// Return (ringbuf, ringbuf virtual memory address)
    pub(super) fn new(proxy: T) -> (Self, usize) {
        let raw_buf = Box::leak(vec![0; DEPTH * ELEM_SIZE + PAGE_SIZE].into_boxed_slice());
        let buf_padding = raw_buf.as_ptr() as usize & (PAGE_SIZE - 1);
        let buf_addr = raw_buf[buf_padding..].as_ptr() as usize;
        let buf = Mutex::new(&mut raw_buf[buf_padding..]);

        (
            Self {
                buf,
                buf_padding,
                head: 0,
                tail: 0,
                proxy,
            },
            buf_addr,
        )
    }

    pub fn is_full(head: usize, tail: usize) -> bool {
        let diff = if head >= tail {
            head - tail
        } else {
            DEPTH + head - tail
        };
        diff & Self::PTR_IDX_MASK == Self::PTR_IDX_MASK
    }

    pub fn is_empty(head: usize, tail: usize) -> bool {
        head == tail
    }

    pub fn wrapping_add(cur: usize, cnt: usize) -> usize {
        (cur + cnt) & Self::PTR_IDX_MASK
    }
}

impl<T: CsrWriterProxy, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize>
    Ringbuf<T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    /// Get space for writing `desc_cnt` descriptors to the ring buffer.
    pub(super) fn write(&mut self) -> RingbufWriter<'_, '_, T, DEPTH, ELEM_SIZE, PAGE_SIZE> {
        RingbufWriter {
            buf: self.buf.lock().unwrap(),
            head: &mut self.head,
            tail: &mut self.tail,
            written_cnt: 0,
            proxy: &self.proxy,
        }
    }
}

impl<T: CsrReaderProxy, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize>
    Ringbuf<T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    /// Prepare to read some descriptors from the ring buffer.
    pub(super) fn read(&mut self) -> RingbufReader<'_, '_, T, DEPTH, ELEM_SIZE, PAGE_SIZE> {
        RingbufReader {
            buf: self.buf.lock().unwrap(),
            head: &mut self.head,
            tail: &mut self.tail,
            read_cnt: 0,
            proxy: &self.proxy,
        }
    }
}

impl<T, const DEPTH: usize, const ELEM_SIZE: usize, const PAGE_SIZE: usize> Drop
    for Ringbuf<T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn drop(&mut self) {
        let buf = self.buf.get_mut().unwrap().as_mut_ptr();
        let raw_buf = unsafe {
            slice::from_raw_parts_mut(buf.sub(self.buf_padding), DEPTH * ELEM_SIZE + PAGE_SIZE)
        };

        drop(unsafe { Box::from_raw(raw_buf) });
    }
}

impl<
        'a,
        'proxy,
        T: CsrWriterProxy,
        const DEPTH: usize,
        const ELEM_SIZE: usize,
        const PAGE_SIZE: usize,
    > RingbufWriter<'a, 'proxy, T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn advance(&mut self) {
        let head = *self.head;
        let new_head =
            Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::wrapping_add(head, self.written_cnt);
        *self.head = new_head;
        self.proxy.write_head(new_head as u32);
        self.written_cnt = 0;
    }
}

impl<
        'a,
        'proxy,
        T: CsrWriterProxy,
        const DEPTH: usize,
        const ELEM_SIZE: usize,
        const PAGE_SIZE: usize,
    > Iterator for RingbufWriter<'a, 'proxy, T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    type Item = &'a mut [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let idx = (*self.head + self.written_cnt)
            & Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::PTR_IDX_MASK;

        // currently, we not allow the writer to overflow
        // Instead, we wait and polling.
        // FIXME: we may return an overflow here later?
        if Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::is_full(idx, *self.tail) {
            // write back first
            self.advance();
            loop {
                let new_tail = self.proxy.read_tail();
                if !Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::is_full(idx, new_tail as usize) {
                    *self.tail = new_tail as usize;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        let offset = idx * ELEM_SIZE;
        let ptr = unsafe { self.buf.as_mut_ptr().add(offset) };

        self.written_cnt += 1;

        Some(unsafe { std::slice::from_raw_parts_mut(ptr, ELEM_SIZE) })
    }
}

/// Drop the writer to update the head pointer.
impl<
        'a,
        'proxy,
        T: CsrWriterProxy,
        const DEPTH: usize,
        const ELEM_SIZE: usize,
        const PAGE_SIZE: usize,
    > Drop for RingbufWriter<'a, 'proxy, T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn drop(&mut self) {
        self.advance();
    }
}

impl<
        'a,
        'proxy,
        T: CsrReaderProxy,
        const DEPTH: usize,
        const ELEM_SIZE: usize,
        const PAGE_SIZE: usize,
    > Iterator for RingbufReader<'a, 'proxy, T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let idx =
            (*self.tail + self.read_cnt) & Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::PTR_IDX_MASK;
        if Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::is_empty(*self.head, idx) {
            loop {
                let new_head = self.proxy.read_head();
                if !Ringbuf::<T, DEPTH, ELEM_SIZE, PAGE_SIZE>::is_empty(new_head as usize, idx) {
                    *self.head = new_head as usize;
                    break;
                }
            }
        }
        let offset = idx * ELEM_SIZE;
        let ptr = unsafe { self.buf.as_ptr().add(offset) };

        self.read_cnt += 1;

        Some(unsafe { std::slice::from_raw_parts(ptr, ELEM_SIZE) })
    }
}

/// Drop the reader to update the tail pointer.
impl<
        'a,
        'proxy,
        T: CsrReaderProxy,
        const DEPTH: usize,
        const ELEM_SIZE: usize,
        const PAGE_SIZE: usize,
    > Drop for RingbufReader<'a, 'proxy, T, DEPTH, ELEM_SIZE, PAGE_SIZE>
{
    fn drop(&mut self) {
        *self.tail += self.read_cnt;
        self.proxy.write_tail(self.read_cnt as u32);
    }
}

#[cfg(test)]
mod test {
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicU32, Ordering},
            Arc,
        },
        thread::{sleep, spawn},
    };

    use super::Ringbuf;

    #[derive(Debug, Clone)]
    struct Proxy(Arc<ProxyInner>);

    #[derive(Debug)]
    struct ProxyInner {
        head: AtomicU32,
        tail: AtomicU32,
    }
    impl Proxy {
        pub fn consume(&self) {
            // move the tail to the head
            let head = self.0.head.load(Ordering::Acquire);
            self.0.tail.store(head, Ordering::Release);
        }

        pub fn produce<const DEPTH: usize>(&self, cnt: usize) {
            // move the head to the tail
            let head = self.0.head.load(Ordering::Acquire);
            let new_head = (head + cnt as u32) % DEPTH as u32;
            self.0.head.store(new_head, Ordering::Release);
        }
    }
    impl super::CsrWriterProxy for Proxy {
        fn write_head(&self, data: u32){
            self.0.head.store(data, Ordering::Release);
        }
        fn read_tail(&self) -> u32 {
            self.0.tail.load(Ordering::Acquire)
        }
    }
    impl super::CsrReaderProxy for Proxy {
        fn write_tail(&self, data: u32){
            self.0.tail.store(data, Ordering::Release);
        }
        fn read_head(&self) -> u32 {
            self.0.head.load(Ordering::Acquire)
        }
    }
    #[test]
    fn test_ringbuf_writer() {
        let proxy = Proxy(Arc::new(ProxyInner {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
        }));
        let thread_proxy = proxy.clone();
        let _ = spawn(move || loop {
            sleep(std::time::Duration::from_millis(10));
            thread_proxy.consume();
        });
        let (mut ringbuf, _) = Ringbuf::<Proxy, 128, 32, 4096>::new(proxy.clone());
        let mut writer = ringbuf.write();

        for i in 0..127 {
            let desc = writer.next().unwrap();
            desc.fill(i as u8);
        }
        drop(writer);
        assert!(proxy.0.head.load(Ordering::Relaxed) == 127);
        assert!(proxy.0.tail.load(Ordering::Relaxed) == 0);
        sleep(std::time::Duration::from_millis(20));
        assert!(proxy.0.head.load(Ordering::Relaxed) == 127);
        assert!(proxy.0.tail.load(Ordering::Relaxed) == 127);
        // test if blocking?

        let mut writer = ringbuf.write();
        for i in 0..256 {
            let desc = writer.next().unwrap();
            desc.fill(i as u8);
        }
        drop(writer);
    }

    #[test]
    fn test_ringbuf_reader() {
        let proxy = Proxy(Arc::new(ProxyInner {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
        }));
        let thread_proxy = proxy.clone();
        let _ = spawn(move || loop {
            thread_proxy.produce::<128>(50);
            sleep(std::time::Duration::from_millis(10));
        });
        let (mut ringbuf, _) = Ringbuf::<Proxy, 128, 32, 4096>::new(proxy.clone());
        let mut reader = ringbuf.read();

        for _i in 0..50 {
            let _desc = reader.next().unwrap();
        }
        drop(reader);
        assert!(proxy.0.head.load(Ordering::Relaxed) == 50);
        assert!(proxy.0.tail.load(Ordering::Relaxed) == 50);

        let mut reader = ringbuf.read();

        let finish_flag = Arc::new(AtomicBool::new(false));
        let finish_flag_clone = finish_flag.clone();
        let checker = spawn(move || {
            sleep(std::time::Duration::from_millis(60));
            if finish_flag_clone.load(Ordering::Relaxed) {
                panic!("should not block at here");
            }
        });
        for _i in 0..256 {
            let _desc = reader.next().unwrap();
        }
        drop(reader);
        finish_flag.store(true, Ordering::Relaxed);
        checker.join().unwrap();
    }
}

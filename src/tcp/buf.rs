use std::fmt::Debug;

pub(super) struct TcpBuffer {
    buffer: Box<[u8]>,
    tail: usize, // A ptr to the last existing byte (if len > 0)
    head: usize, // A ptr to the next free byte

    pub(super) tail_seq_no: u32, // The relative seq_no of the tail element
}

impl TcpBuffer {
    pub fn state(&self) {
        inet_trace!(
            "TcpBuffer [{} ... {} ... {}]",
            self.tail_seq_no,
            self.head_seq_no(),
            self.tail_seq_no + self.cap() as u32
        )
    }

    pub fn len(&self) -> usize {
        let result = if self.tail <= self.head {
            self.head - self.tail
        } else {
            self.head + (self.buffer.len() - self.tail)
        };

        assert!(
            result <= self.cap(),
            "Buffer {{ head: {}, tail: {}, len: {}, cap + 1: {} }}",
            self.head,
            self.tail,
            result,
            self.buffer.len()
        );
        result
    }

    pub fn cap(&self) -> usize {
        self.buffer.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn rem(&self) -> usize {
        self.buffer.len() - self.len() - 1
    }

    pub fn head_seq_no(&self) -> u32 {
        self.tail_seq_no + self.len() as u32
    }

    pub fn rem_for(&self, seq_no: u32) -> usize {
        if seq_no > self.head_seq_no() {
            todo!()
        }
        let additional_bytes = self.head_seq_no() - seq_no;
        self.rem() + additional_bytes as usize
    }

    pub fn head_for(&self, seq_no: u32) -> usize {
        assert!(seq_no >= self.tail_seq_no);
        let offset = seq_no - self.tail_seq_no;
        (self.tail + offset as usize) % self.buffer.len()
    }

    pub fn new(size: usize, initial_seq_no: u32) -> Self {
        Self {
            buffer: vec![0u8; size + 1].into_boxed_slice(),
            head: 0,
            tail: 0,
            tail_seq_no: initial_seq_no,
        }
    }

    pub fn fwd_to_seq_no(&mut self, seq_no: u32) {
        assert!(self.is_empty());
        self.head = 0;
        self.tail = 0;
        self.tail_seq_no = seq_no;
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        let k = self.rem().min(buf.len());
        for i in 0..k {
            self.buffer[(self.head + i) % self.buffer.len()] = buf[i];
        }
        self.head = (self.head + k) % self.buffer.len();
        k
    }

    pub fn write_to(&mut self, buf: &[u8], seq_no: u32) -> usize {
        let k = self.rem_for(seq_no).min(buf.len());
        let seq_no_head = self.head_for(seq_no);
        for i in 0..k {
            self.buffer[(seq_no_head + i) % self.buffer.len()] = buf[i];
        }
        // Check whether head need updates.
        // sh ... h ... sh+k
        // or
        // sh ... sh+k ... h;
        let seq_no_tail = (seq_no_head + k) % self.buffer.len();
        let h = if self.head < seq_no_head {
            self.head + self.buffer.len()
        } else {
            self.head
        };
        let shk = if seq_no_tail < seq_no_head {
            seq_no_tail + self.buffer.len()
        } else {
            seq_no_tail
        };

        if h < shk {
            self.head = shk % self.buffer.len();
        } else {
            // NOP
        }

        k
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let k = self.len().min(buf.len());
        for i in 0..k {
            buf[i] = self.buffer[(self.tail + i) % self.buffer.len()];
        }
        self.tail = (self.tail + k) % self.buffer.len();
        self.tail_seq_no = self.tail_seq_no.wrapping_add(k as u32);
        k
    }

    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let k = self.len().min(buf.len());
        for i in 0..k {
            buf[i] = self.buffer[(self.tail + i) % self.buffer.len()];
        }
        k
    }

    pub fn peek_at(&self, buf: &mut [u8], seq_no: u32) -> usize {
        assert!(self.tail_seq_no <= seq_no && self.head_seq_no() > seq_no);
        let k = ((self.head_seq_no() - seq_no) as usize).min(buf.len()); // TODO overflow

        let tail = self.head_for(seq_no);
        for i in 0..k {
            buf[i] = self.buffer[(tail + i) % self.buffer.len()];
        }
        k
    }

    pub fn free(&mut self, n: usize) {
        assert!(n <= self.len());
        self.tail = (self.tail + n) % self.buffer.len();
        self.tail_seq_no = self.tail_seq_no.wrapping_add(n as u32);
    }
}

impl Debug for TcpBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TcpBuffer [{} ... {} ... {}]",
            self.tail_seq_no,
            self.head_seq_no(),
            self.tail_seq_no + self.cap() as u32
        )
    }
}

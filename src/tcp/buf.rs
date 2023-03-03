use std::fmt::Debug;

pub(super) struct TcpBuffer {
    buffer: Box<[u8]>,
    tail: usize, // A ptr to the last existing byte (if len > 0)
    head: usize, // A ptr to the next free byte

    pub(super) state: TcpBufferState,

    pub(super) tail_seq_no: u32, // The relative seq_no of the tail element
}

impl TcpBuffer {
    pub fn state(&self) {
        log::trace!(
            target: "inet/tcp",
            "TcpBuffer({}) [{:<4} ..(data).. {:<4} ..(zero).. {:<4}]",
            self.cap(),
            self.tail_seq_no,
            self.tail_seq_no + self.state.valid_slice_len(),
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
            if seq_no < self.tail_seq_no + self.cap() as u32 {
                let ret = self.tail_seq_no + self.cap() as u32 - seq_no;
                ret as usize
            } else {
                unimplemented!()
            }
        } else {
            let additional_bytes = self.head_seq_no() - seq_no;
            self.rem() + additional_bytes as usize
        }
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
            state: TcpBufferState::new(),
            tail_seq_no: initial_seq_no,
        }
    }

    pub fn fwd_to_seq_no(&mut self, seq_no: u32) {
        assert!(self.is_empty());
        self.head = 0;
        self.tail = 0;
        self.tail_seq_no = seq_no;
        self.state = TcpBufferState::new();
        self.state.add_slice(seq_no, 0);
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        let k = self.rem().min(buf.len());
        for i in 0..k {
            self.buffer[(self.head + i) % self.buffer.len()] = buf[i];
        }
        self.state.add_slice(self.head_seq_no(), k as u32);
        self.head = (self.head + k) % self.buffer.len();
        k
    }

    pub fn write_to(&mut self, buf: &[u8], seq_no: u32) -> usize {
        let k = self.rem_for(seq_no).min(buf.len());
        self.state.add_slice(seq_no, k as u32);

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
        let k = self
            .len()
            .min(buf.len()) // TODO: may be redundant
            .min(self.state.valid_slice_len() as usize);
        for i in 0..k {
            buf[i] = self.buffer[(self.tail + i) % self.buffer.len()];
        }
        self.tail = (self.tail + k) % self.buffer.len();
        self.tail_seq_no = self.tail_seq_no.wrapping_add(k as u32);
        self.state.free_slice(k as u32);
        k
    }

    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let k = self
            .len()
            .min(buf.len()) // TODO: may be redundant
            .min(self.state.valid_slice_len() as usize);
        for i in 0..k {
            buf[i] = self.buffer[(self.tail + i) % self.buffer.len()];
        }
        k
    }

    pub fn peek_at(&self, buf: &mut [u8], seq_no: u32) -> usize {
        assert!(self.tail_seq_no <= seq_no && self.head_seq_no() > seq_no);
        let k = ((self.head_seq_no() - seq_no) as usize)
            .min(buf.len())
            .min(self.state.valid_slice_len() as usize); // TODO overflow

        let tail = self.head_for(seq_no);
        for i in 0..k {
            buf[i] = self.buffer[(tail + i) % self.buffer.len()];
        }
        k
    }

    pub fn free(&mut self, n: usize) {
        self.state.free_slice(n as u32);

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

// # Buffer state

/// The state of a TCP receive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TcpBufferState {
    slices: Vec<(u32, u32)>, // all valid slices
}

impl TcpBufferState {
    /// Creates a new buffer state
    pub(super) fn new() -> Self {
        Self { slices: Vec::new() }
    }

    /// Adds a received slice to the valid slices.
    ///
    /// Returns `true` if the slice was added and `false`
    /// if the slice was not valid to be added (data with seq_no
    /// smaller than current receiving window).
    pub(super) fn add_slice(&mut self, seq_no: u32, len: u32) -> bool {
        if !self.slices.is_empty() {
            // TODO: Overflow
            if seq_no < self.slices[0].0 {
                return true;
            }
        }

        match self.slices.binary_search_by(|e| e.0.cmp(&seq_no)) {
            Ok(i) => {
                // ensure that our slice is place at a appropiate place
                // only two versions are avialable
                if self.slices[i].1 > len {
                    self.slices.insert(i, (seq_no, len))
                } else {
                    self.slices.insert(i + 1, (seq_no, len))
                }
            }
            Err(i) => self.slices.insert(i, (seq_no, len)),
        };

        // # Cleanup internal state

        // Consider each element to have those invariants:
        // 1) The previous slice end with a non-zero offset to the begin of
        //    the current slice, thus cant be merged.
        // 2) The next slice starts at a non-zero offset to the end of the current
        //    slice, thus cannot be merged

        // * The first slice may be of len = 0

        let mut i = 0;
        while i < self.slices.len() {
            let mut slice_end = self.slices[i].0.wrapping_add(self.slices[i].1);
            let k = i + 1;
            while k < self.slices.len() && self.slices[k].0 <= slice_end {
                // println!("{:?} {:?}", self.slices[i], self.slices[k]);
                // Merge next slice into the current one
                let unique_len = self.slices[k].1 - (slice_end - self.slices[k].0);

                self.slices[i].1 += unique_len;
                slice_end += unique_len;

                self.slices.remove(k);
            }

            i += 1;
        }

        true
    }

    /// Frees n bytes of valid slices.
    ///
    ///
    /// # Panics
    ///
    /// This function panics if no slice was added so far.
    /// This function panics if the valid slice does not contain at least n bytes.
    ///
    pub(super) fn free_slice(&mut self, n: u32) {
        let Some(first) = self.slices.first_mut() else {
        panic!()
    };
        if first.1 < n {
            panic!()
        }

        first.0 += n;
        first.1 -= n;
    }

    /// Returns the size of the readable valid slice.
    pub(super) fn valid_slice_len(&self) -> u32 {
        self.slices.first().map(|(_, len)| *len).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_state_add_slice() {
        let mut buf = TcpBufferState::new();
        buf.add_slice(100, 100); // [100..200]
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 100);

        buf.add_slice(300, 100); // [300..400]
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 100);

        buf.add_slice(100, 100); // [100..200]
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 100);

        buf.add_slice(200, 100); // [200..300]
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 300);

        buf.add_slice(300, 200);
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 400);
    }

    #[test]
    fn buffer_state_free_slice() {
        let mut buf = TcpBufferState::new();
        buf.add_slice(100, 400);
        buf.add_slice(600, 400);

        // [100..500] [600..1000]

        buf.free_slice(100);
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 300);

        buf.free_slice(300);
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 0);

        buf.add_slice(500, 200);
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 500);

        buf.free_slice(200);
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 300);

        buf.free_slice(300);
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 0);
    }

    #[test]
    fn buffer_insert_at_null_head() {
        let mut buf = TcpBufferState::new();
        buf.add_slice(100, 100);
        buf.free_slice(100);

        // Now inactive at seq_no = 200;
    }
}

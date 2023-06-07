use core::slice;

///
/// A Tcp slice_buffer
///
/// ...allready read...#############...to be written...
///                      ^read_head  ^write_head
///                        
#[derive(Debug)]
pub(crate) struct TcpBuffer {
    bytes: Box<[u8]>,
    read_head: u32,
    write_head: u32,
    slices: TcpBufferSlices,
}

#[derive(Debug)]
struct TcpBufferSlices {
    slices: Vec<(u32, u32)>,
}

impl TcpBuffer {
    pub fn len(&self) -> usize {
        self.write_head.wrapping_sub(self.read_head) as usize
    }

    pub fn len_continous(&self) -> usize {
        // TODO
        self.len().min(self.slices.valid_slice_len() as usize)
    }

    pub fn cap(&self) -> usize {
        self.bytes.len()
    }

    pub fn rem(&self) -> usize {
        self.cap() - self.len()
    }

    pub fn read_head(&self) -> u32 {
        self.read_head
    }

    pub fn new(cap: usize, seq_no: u32) -> TcpBuffer {
        TcpBuffer {
            bytes: vec![0; cap].into_boxed_slice(),
            read_head: seq_no,
            write_head: seq_no,
            slices: TcpBufferSlices::new(seq_no),
        }
    }

    pub fn bump(&mut self, seq_no: u32) {
        assert_eq!(self.len(), 0);
        self.read_head = seq_no;
        self.write_head = seq_no;
        self.slices.slices = vec![(seq_no, 0)]
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        self.write(buf, self.write_head)
    }

    pub fn write(&mut self, buf: &[u8], seq_no: u32) -> usize {
        assert!(seq_no >= self.read_head);
        let end_seq_no = seq_no.wrapping_add(buf.len() as u32);
        let max_seq_no = self.write_head.wrapping_add(self.rem() as u32);

        // TODO: not wrapping safe
        let end_seq_no = end_seq_no.min(max_seq_no);
        let k = end_seq_no - seq_no;

        self.slices.add(seq_no, k);
        for i in 0..k {
            self.bytes[(seq_no.wrapping_add(i) % self.cap() as u32) as usize] = buf[i as usize];
        }

        self.write_head = self.write_head.max(end_seq_no);
        k as usize
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let k = self.peek(buf);
        self.free(k);
        k
    }

    pub fn free(&mut self, k: usize) {
        self.read_head = self.read_head.wrapping_add(k as u32);
    }

    pub fn peek(&mut self, buf: &mut [u8]) -> usize {
        self.peek_at(buf, self.read_head)
    }

    pub fn peek_at(&mut self, buf: &mut [u8], seq_no: u32) -> usize {
        let max_seq_no = self.read_head + self.len_continous() as u32;
        let k = ((max_seq_no - seq_no) as usize).min(buf.len());
        let cap = self.cap();
        for i in 0..k {
            buf[i] = self.bytes[((seq_no as usize).wrapping_add(i) % cap) as usize]
        }
        k
    }
}

impl TcpBufferSlices {
    fn new(seq_no: u32) -> Self {
        Self {
            slices: vec![(seq_no, 0)],
        }
    }

    fn add(&mut self, seq_no: u32, len: u32) {
        if !self.slices.is_empty() {
            if seq_no < self.slices[0].0 {
                return;
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

        let mut i = 0;
        while i < self.slices.len() {
            let mut slice_end = self.slices[i].0.wrapping_add(self.slices[i].1);
            let k = i + 1;
            while k < self.slices.len() && self.slices[k].0 <= slice_end {
                // println!("{:?} {:?}", self.slices[i], self.slices[k]);
                // Merge next slice into the current one
                let c_end = self.slices[k].0 + self.slices[k].1;
                if c_end > slice_end {
                    let unique_len = self.slices[k].1 - (slice_end - self.slices[k].0);

                    self.slices[i].1 += unique_len;
                    slice_end += unique_len;
                }

                self.slices.remove(k);
            }

            i += 1;
        }
    }

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

    pub(super) fn valid_slice_len(&self) -> u32 {
        self.slices.first().map(|(_, len)| *len).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_buffer_simple_inout() {
        let mut tcp = TcpBuffer::new(128, 1000);
        let w = tcp.write(&[1; 64], 1000);
        assert_eq!(w, 64);

        let mut buf = [0; 100];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 64);
        assert_eq!(&buf[..r], [1; 64]);

        let mut buf = [0; 32];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 0);
    }

    #[test]
    fn full_buffer_staggered_write() {
        let mut tcp = TcpBuffer::new(128, 1000);
        let w = tcp.write(&[1; 32], 1000);
        assert_eq!(w, 32);
        let w = tcp.write(&[2; 32], 1032);
        assert_eq!(w, 32);
        let w = tcp.write(&[3; 32], 1064);
        assert_eq!(w, 32);

        let mut buf = [0; 100];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 96);
        assert_eq!(&buf[..32], [1; 32]);
        assert_eq!(&buf[32..64], [2; 32]);
        assert_eq!(&buf[64..r], [3; 32]);

        let mut buf = [0; 32];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 0);
    }

    #[test]
    fn full_buffer_staggered_read() {
        let mut tcp = TcpBuffer::new(128, 1000);
        let w = tcp.write(&[1; 64], 1000);
        assert_eq!(w, 64);

        let mut buf = [0; 32];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 32);
        assert_eq!(&buf[..r], [1; 32]);

        let mut buf = [0; 32];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 32);
        assert_eq!(&buf[..r], [1; 32]);

        let mut buf = [0; 32];
        let r = tcp.read(&mut buf);
        assert_eq!(r, 0);
    }

    #[test]
    fn full_buffer_out_of_order_nonoverlapping() {
        let mut tcp = TcpBuffer::new(128, 1000);
        assert_eq!(tcp.write(&[1; 32], 1000), 32);
        assert_eq!(tcp.write(&[3; 32], 1064), 32);

        assert_eq!(tcp.len_continous(), 32);
        assert_eq!(tcp.len(), 96);

        let mut buf = [0; 128];
        assert_eq!(tcp.peek(&mut buf), 32);
        assert_eq!(buf[..32], [1; 32]);

        assert_eq!(tcp.len_continous(), 32);
        assert_eq!(tcp.len(), 96);

        assert_eq!(tcp.write(&[2; 32], 1032), 32);

        assert_eq!(tcp.len_continous(), 96);
        assert_eq!(tcp.len(), 96);

        let mut buf = [0; 128];
        assert_eq!(tcp.read(&mut buf), 96);
        assert_eq!(&buf[..32], [1; 32]);
        assert_eq!(&buf[32..64], [2; 32]);
        assert_eq!(&buf[64..96], [3; 32]);
    }

    #[test]
    fn full_buffer_out_of_order_dup() {
        let mut tcp = TcpBuffer::new(128, 1000);
        assert_eq!(tcp.write(&[1; 32], 1000), 32);
        assert_eq!(tcp.write(&[2; 32], 1032), 32);
        assert_eq!(tcp.write(&[3; 32], 1064), 32);

        assert_eq!(tcp.len(), tcp.len_continous());

        assert_eq!(tcp.write(&[2; 32], 1032), 32);

        assert_eq!(tcp.len(), tcp.len_continous());

        let mut buf = [0; 96];
        assert_eq!(tcp.read(&mut buf), 96);
    }

    #[test]
    fn full_buffer_out_of_order_at_init() {
        let mut tcp = TcpBuffer::new(128, 1000);
        // assert_eq!(tcp.write(&[1; 32], 1000), 32);
        assert_eq!(tcp.write(&[2; 32], 1032), 32);
        assert_eq!(tcp.write(&[3; 32], 1064), 32);

        assert_eq!(tcp.len(), 96);
        assert_eq!(tcp.len_continous(), 0);

        assert_eq!(tcp.write(&[1; 32], 1000), 32);

        assert_eq!(tcp.len(), 96);
        assert_eq!(tcp.len_continous(), 96);
    }

    #[test]
    #[should_panic]
    fn full_buffer_too_small_seq_no() {
        let mut tcp = TcpBuffer::new(128, 1000);
        assert_eq!(tcp.write(&[1; 32], 900), 32);
    }

    #[test]
    fn slice_buffer_state_add() {
        let mut buf = TcpBufferSlices::new(100);
        buf.add(100, 100); // [100..200]
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 100);

        buf.add(300, 100); // [300..400]
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 100);

        buf.add(100, 100); // [100..200]
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 100);

        buf.add(200, 100); // [200..300]
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 300);

        buf.add(300, 200);
        assert_eq!(buf.slices.len(), 1);
        assert_eq!(buf.valid_slice_len(), 400);
    }

    #[test]
    fn slice_buffer_state_free_slice() {
        let mut buf = TcpBufferSlices::new(100);
        buf.add(100, 400);
        buf.add(600, 400);

        // [100..500] [600..1000]

        buf.free_slice(100);
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 300);

        buf.free_slice(300);
        assert_eq!(buf.slices.len(), 2);
        assert_eq!(buf.valid_slice_len(), 0);

        buf.add(500, 200);
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
    fn slice_buffer_insert_at_null_head() {
        let mut buf = TcpBufferSlices::new(100);
        buf.add(100, 100);
        buf.free_slice(100);

        // Now inactive at seq_no = 200;
    }
}

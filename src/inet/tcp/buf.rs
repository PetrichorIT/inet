use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpBuffer {
    inner: Vec<u8>,
    head: usize, // ptr to the next slot
    tail: usize, // ptr to the last contained value
    len: usize,
}

impl TcpBuffer {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn remaining_cap(&self) -> usize {
        self.inner.len() - self.len
    }

    pub fn cap(&self) -> usize {
        self.inner.len()
    }

    pub fn new(size: usize) -> Self {
        Self {
            inner: vec![0; size],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub fn fwd_to_seq_no(&mut self, seq_no: usize) {
        assert!(self.is_empty());
        self.head = seq_no;
        self.tail = seq_no;
    }

    pub fn write_to_head(&mut self, buf: &[u8]) -> usize {
        self.write_to(buf, self.head)
    }

    pub fn write_to(&mut self, buf: &[u8], pos: usize) -> usize {
        assert!(pos > 0);

        if pos >= self.head {
            // log::error!(
            //     "Writing {} bytes to head {} (buffer is {}..{})",
            //     buf.len(),
            //     pos,
            //     self.tail,
            //     self.head
            // );

            // forward to pos
            if pos != self.head {
                let diff = pos - self.head;
                if diff > self.remaining_cap() {
                    return 0;
                } else {
                    self.head += diff;
                    self.len += diff;
                }
            }

            let n = buf.len().min(self.remaining_cap());
            for offset in 0..n {
                let idx = (self.head + offset) % self.inner.len();
                self.inner[idx] = buf[offset];
            }
            self.len += n;
            self.head += n;
            n
        } else {
            // log::error!(
            //     "Writing {} bytes into buffer at {} (buffer is {}..{})",
            //     buf.len(),
            //     pos,
            //     self.tail,
            //     self.head
            // );
            assert!(
                pos + buf.len() <= self.head,
                "pos + buf := {} + {} '<' self.head := {}",
                pos,
                buf.len(),
                self.head
            );
            for i in 0..buf.len() {
                let idx = (self.head + i) % self.inner.len();
                self.inner[idx] = buf[i];
            }
            buf.len()
        }
    }

    pub fn free(&mut self, n: usize) {
        self.tail += n;
        self.len -= n;
        assert!(self.tail <= self.head);
    }

    pub fn peek_relative(&mut self, buf: &mut [u8], offset: usize) -> usize {
        self.peek(buf, self.tail + offset)
    }

    pub fn peek(&mut self, buf: &mut [u8], pos: usize) -> usize {
        assert!(self.tail <= pos);
        assert!(pos < self.head);

        let n = (self.head - pos).min(buf.len());
        for offset in 0..n {
            let idx = (pos + offset) % self.inner.len();
            buf[offset] = self.inner[idx];
        }
        n
    }
}

// impl Debug for TcpBuffer {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("TcpBuffer")
//             .field("buffer", &format!("[{}..{}]", self.tail, self.head))
//             .field("len", &self.len)
//             .finish()
//     }
// }

#[cfg(test)]
mod tests {
    use super::TcpBuffer;

    #[test]
    fn tcp_buffer_write() {
        let mut buf = TcpBuffer::new(128);
        assert_eq!(100, buf.write_to_head(&vec![42; 100]));
        assert_eq!(28, buf.write_to_head(&vec![69; 100]));

        assert_eq!(buf.len(), 128);
        assert_eq!(buf.remaining_cap(), 0);

        buf.free(50);

        assert_eq!(buf.len(), 78);
        assert_eq!(buf.remaining_cap(), 50);

        assert_eq!(50, buf.write_to_head(&vec![22; 100]));

        assert_eq!(buf.len(), 128);
        assert_eq!(buf.remaining_cap(), 0);

        buf.free(127);

        assert_eq!(buf.len(), 1);
        assert_eq!(buf.remaining_cap(), 127);

        buf.free(buf.len());

        assert!(buf.is_empty());
    }

    #[test]
    fn tcp_buffer_read() {
        let mut buf = TcpBuffer::new(128);
        assert_eq!(50, buf.write_to_head(&vec![42; 50]));
        assert_eq!(50, buf.write_to_head(&vec![50; 50]));
        assert_eq!(28, buf.write_to_head(&vec![69; 28]));

        assert_eq!(buf.remaining_cap(), 0);

        // Real test case
        let mut b40 = vec![0; 40];
        assert_eq!(buf.peek(&mut b40, 0), 40);
        assert_eq!(b40, vec![42; 40]);

        let mut b20 = vec![0; 20];
        assert_eq!(buf.peek(&mut b20, 40), 20);
        assert_eq!(
            b20,
            vec![42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50]
        );

        buf.free(60);

        assert_eq!(buf.len(), 68);
        assert_eq!(buf.remaining_cap(), 60);

        assert_eq!(68, buf.peek(&mut vec![0; 100], 60));

        // write to ring
        assert_eq!(60, buf.write_to_head(&vec![89; 100]));

        let mut b40 = vec![0; 40];
        assert_eq!(40, buf.peek_relative(&mut b40, 0));
        assert_eq!(b40, vec![50; 40]);

        buf.free(40);
        buf.free(28);

        assert_eq!(40, buf.peek_relative(&mut b40, 0));
        assert_eq!(b40, vec![89; 40]);
    }
}

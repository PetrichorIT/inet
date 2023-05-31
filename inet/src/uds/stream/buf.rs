#[derive(Debug)]
pub(super) struct Buffer {
    buf: Vec<u8>,
    head: usize,
    len: usize,
}

// head ptr to next read

impl Buffer {
    pub(super) fn cap(&self) -> usize {
        self.buf.len()
    }

    pub(super) fn new(cap: usize) -> Buffer {
        Self {
            buf: vec![0; cap],
            head: 0,
            len: 0,
        }
    }

    pub(super) fn write(&mut self, buf: &[u8]) -> usize {
        let mut i = 0;
        let cap = self.cap();
        while self.len < self.cap() && i < buf.len() {
            self.buf[(self.head + self.len) % cap] = buf[i];
            self.len += 1;
            i += 1;
        }
        i
    }

    pub(super) fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut i = 0;
        while self.len > 0 && i < buf.len() {
            buf[i] = self.buf[self.head];
            self.head = (self.head + 1) % self.cap();
            self.len -= 1;
            i += 1;
        }
        i
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::Buffer;
    use std::iter::repeat_with;

    #[test]
    fn buf_to_limits() {
        let mut rng = StdRng::seed_from_u64(rand::random());

        let input = repeat_with(|| rng.gen::<u8>())
            .take(4096)
            .collect::<Vec<_>>();
        let mut i = 0;

        let mut output = vec![0; 4096];
        let mut o = 0;

        let mut buf = Buffer::new(1024);
        while i < 4096 || o < 4096 {
            assert_eq!(buf.len, i - o);

            let w: usize = rng.gen::<usize>() % 1024 + 400;
            let n = buf.write(&input[i..(i + w).min(4096)]);
            i += n;

            assert_eq!(buf.len, i - o);

            let r = rng.gen::<usize>() % 1024 + 100;
            let n = buf.read(&mut output[o..(o + r).min(4096)]);
            o += n;

            assert_eq!(buf.len, i - o);
        }

        for i in 0..4096 {
            assert_eq!(
                input[i],
                output[i],
                "failed at {}-th byte input: {:?} output: {:?}",
                i,
                &input[(i - 2)..=(i + 2)],
                &output[(i - 2)..=(i + 2)]
            );
        }
    }
}

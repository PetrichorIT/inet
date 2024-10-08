use std::{collections::VecDeque, mem};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedBuffer<T> {
    inner: VecDeque<T>,
    cap: usize,
}

impl<T> FixedBuffer<T> {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn enqueue(&mut self, value: T) {
        if self.inner.len() < self.cap {
            self.inner.push_back(value);
        } else {
            self.inner.pop_front();
            self.inner.push_back(value);
        }
    }

    pub fn extract(&mut self) -> VecDeque<T> {
        let mut vdq = VecDeque::with_capacity(self.cap);
        mem::swap(&mut vdq, &mut self.inner);
        vdq
    }
}

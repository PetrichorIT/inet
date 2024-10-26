use std::io::Error;
use std::task::{Context, Waker};

use crate::io;

#[derive(Debug, Default)]
pub struct UserInterface {
    pub tx: Vec<Waker>,
    pub rx: Vec<Waker>,
    pub so_error: Option<Error>,
    pub error: Option<Error>,
}

impl UserInterface {
    pub fn error(&self) -> Option<Error> {
        self.error
            .as_ref()
            .map(|v| Error::new(v.kind(), v.to_string()))
    }

    pub fn set_error(&mut self, error: Error) {
        if let Some(replaced) = self.error.replace(error) {
            tracing::warn!("override error: {replaced}")
        }
    }

    pub fn register(&mut self, interest: io::Interest, cx: &mut Context<'_>) {
        if interest.is_readable() {
            self.rx.push(cx.waker().clone());
        }
        if interest.is_writable() {
            self.tx.push(cx.waker().clone());
        }
    }

    pub fn wake(&mut self, interest: io::Interest) {
        if interest.is_readable() {
            self.rx.drain(..).for_each(|w| w.wake());
        }
        if interest.is_writable() {
            self.tx.drain(..).for_each(|w| w.wake());
        }
    }
}

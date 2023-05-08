use crate::IOContext;
use des::runtime::rng;
use rand::{distributions::Alphanumeric, Rng};
use std::{
    io::Result,
    path::{Path, PathBuf},
};

/// A temporary directory owned by this struct.
///
/// Since des/inet do not simulate the fs, this directory does not really exist, but instead is
/// just a shorthand for binding unix domain sockets to randomly generated addrs.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> Result<TempDir> {
        IOContext::with_current(|ctx| ctx.tempdir_create())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn into_path(self) -> PathBuf {
        self.path
    }

    pub fn close(self) -> Result<()> {
        drop(self);
        Ok(())
    }
}

pub fn tempdir() -> Result<TempDir> {
    TempDir::new()
}

impl IOContext {
    fn tempdir_create(&self) -> Result<TempDir> {
        'outer: loop {
            let name = "tmp/".to_string()
                + &rng()
                    .sample_iter(&Alphanumeric)
                    .take(16)
                    .map(char::from)
                    .collect::<String>();

            for uds in self.uds.dgrams.values() {
                let Some(path) = uds.addr.as_pathname() else { continue;};
                if path.starts_with(&name) {
                    continue 'outer;
                }
            }

            return Ok(TempDir {
                path: PathBuf::from(name),
            });
        }
    }
}

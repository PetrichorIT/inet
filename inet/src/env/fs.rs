//! Minimal filesystem abstractions.

use crate::{IOContext, ioctx};
use des::runtime::rng;
use fxhash::FxHashMap;
use rand::{Rng, distr::Alphanumeric};
use std::{
    io::{Error, ErrorKind, Result},
    path::{Component, Path, PathBuf},
};

#[derive(Debug)]
pub(crate) struct Fs {
    nodes: FxHashMap<PathBuf, FsNode>,
}

#[derive(Debug)]
enum FsNode {
    Dir(Dir),
    File(),
}

#[derive(Debug)]
struct Dir {
    contents: Vec<PathBuf>,
}

impl Fs {
    fn create_file(&mut self, path: PathBuf) -> Result<()> {
        let mut cur = PathBuf::from("/");
        let comps = path.components().collect::<Vec<_>>();
        for comp in &comps[..comps.len() - 1] {
            match comp {
                Component::CurDir => todo!(),
                Component::Normal(name) => {
                    let Some(node) = self.nodes.get_mut(&cur) else {
                        return Err(Error::new(ErrorKind::NotFound, "not found"));
                    };

                    let FsNode::Dir(dir) = node else {
                        return Err(Error::new(ErrorKind::InvalidData, "not a directory"));
                    };

                    cur.push(name);
                    if !dir.contents.contains(&cur) {
                        dir.contents.push(cur.clone());
                        self.nodes.insert(
                            cur.clone(),
                            FsNode::Dir(Dir {
                                contents: Vec::new(),
                            }),
                        );
                    }
                }
                Component::ParentDir => {
                    let _ = cur.pop();
                }
                Component::Prefix(_) => todo!(),
                Component::RootDir => cur = PathBuf::from("/"),
            }
        }

        let Some(node) = self.nodes.get_mut(&cur) else {
            return Err(Error::new(ErrorKind::NotFound, "not found"));
        };

        let FsNode::Dir(dir) = node else {
            return Err(Error::new(ErrorKind::InvalidData, "not a directory"));
        };

        cur.push(comps[comps.len() - 1]);
        let path = cur;

        if dir.contents.contains(&path) {
            return Err(Error::new(ErrorKind::AlreadyExists, "allready exists"));
        }

        dir.contents.push(path.clone());
        self.nodes.insert(path, FsNode::File());

        Ok(())
    }
}

impl Default for Fs {
    fn default() -> Self {
        let mut nodes = FxHashMap::default();
        nodes.insert(
            PathBuf::from("/"),
            FsNode::Dir(Dir {
                contents: Vec::new(),
            }),
        );
        Self { nodes }
    }
}

/// A temporary directory owned by this struct.
///
/// Since des/inet do not simulate the fs, this directory does not really exist, but instead is
/// just a shorthand for binding unix domain sockets to randomly generated addrs.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> Result<TempDir> {
        ioctx().do_failable(|ctx| ctx.tempdir_create())
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

/// Create a new temporary directory for usage in unix domain sockets
pub fn tempdir() -> Result<TempDir> {
    TempDir::new()
}

impl IOContext {
    fn tempdir_create(&mut self) -> Result<TempDir> {
        loop {
            let name = "tmp/".to_string()
                + &rng()
                    .sample_iter(&Alphanumeric)
                    .take(16)
                    .map(char::from)
                    .collect::<String>();

            if let Err(_e) = self.fs.create_file(PathBuf::from(&name)) {
                continue;
            };

            return Ok(TempDir {
                path: PathBuf::from(name),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_setup() -> Result<()> {
        let mut fs = Fs::default();

        fs.create_file(PathBuf::from("/tmp/myfilexyz"))?;
        fs.create_file(PathBuf::from("/tmp/a"))?;
        fs.create_file(PathBuf::from("/tmp/../myfilexyz"))?;

        fs.create_file(PathBuf::from("/tmp/myfilexyz")).unwrap_err();
        Ok(())
    }
}

use std::{
    env::args,
    fs::File,
    io::{BufReader, Error},
};

use pcapng::BlockReader;

fn main() -> Result<(), Error> {
    for arg in args().skip(1) {
        let file = BufReader::new(File::open(arg)?);
        let reader = BlockReader::new(file);
        for (i, block) in reader.enumerate() {
            assert!(block.is_ok());
            if i % 10_000 == 0 {
                println!("{i}")
            }
        }
    }
    Ok(())
}

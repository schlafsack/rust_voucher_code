use rust_aes;
use num_bigint::ToBigUint;
use std::io::{BufWriter, Write};

const KEY: &str = "0123456789abcdef0123456789abcdef";
const TWEEK: &str = "REPL47";

fn main() {

    let space = 10.to_biguint().unwrap().pow(12);
    let count = 10.to_biguint().unwrap().pow(7);

    let file = std::fs::File::create("data.txt").unwrap();
    let mut file = BufWriter::new(file);

    rust_aes::generate_to(KEY, TWEEK, space, count, | x, code | {
        let _ = writeln!(writer_lock.write().unwrap(), "{}", code);
    });

    let _ = file.flush();

}

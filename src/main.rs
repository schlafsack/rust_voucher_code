use rust_aes;
use num_bigint::ToBigUint;
use std::io::{BufWriter, Write};
use std::sync::{Arc, RwLock};

const KEY: &str = "0123456789abcdef0123456789abcdef";
const TWEEK: &str = "MYPROMO";

fn main() {

    // Select a sequence of 10^7 integers from a 10^12 space.
    let space = 10.to_biguint().unwrap().pow(12);
    let count = 10.to_biguint().unwrap().pow(7);

    // Buffered file for output
    let file = std::fs::File::create("data.txt").unwrap();
    let file = BufWriter::new(file);

    // generate_to is multi-threaded so we need to guard access to the file.
    let f_lock = Arc::new(RwLock::new(file));

    // Write out the codes
    rust_aes::generate_to(KEY, TWEEK, space, count, false, | x, code | {
        let _ = writeln!(f_lock.write().unwrap(), "{},{}", x, code);
    });

    // Flush and finish up.
    let _ = f_lock.write().unwrap().flush();

}

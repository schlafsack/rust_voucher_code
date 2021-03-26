use aesni::Aes256;
use base32::Alphabet;
use cipher::{BlockCipher, NewBlockCipher};
use fpe::ff1::{BinaryNumeralString, FF1};
use num_bigint::{BigUint, RandBigInt};
use rayon::prelude::*;
use std::io::Write;
use std::sync::{Arc, RwLock};
use std::ops::{Sub, Add};

pub fn generate_to<WRIT>(key: &str, tweek: &str, space: BigUint, count: BigUint, f: WRIT)
    where WRIT: Fn(BigUint, String) {

    let key_bytes = key.as_bytes();

    // Manage concurency around the output function, we will be calling it in parallel
    // and we can't make any assumptions about it's thread safety.
    let f_lock = Arc::new(RwLock::new(f));

    // Calculate a random range of the correct size in the specified space.
    let mut rng = rand::thread_rng();
    let size = space.bits() / 8;
    let from = rng.gen_biguint_below(&space.sub(&count));
    let to = from.clone().add(&count);

    // Init the encryptor using AES and our key
    let ff1 = FF1::<Aes256>::new(&key_bytes, 2).unwrap();

    // Create an iterator over our range, using a rayon bridge to process the range in parallel.
    let iter = num_iter::range(from, to).par_bridge();
    iter.for_each( |x| {

        // Encode the int using the specified tweek.
        let code = encode(&ff1, &x, tweek, size as usize);

        // Decrypt for validation
        let validate = decode(&ff1, &code, tweek);
        assert_eq!(code, validate);

        // Write out the source integer and the encoded value.
        f_lock.write().unwrap().f(x, code);
    });
}

pub fn encode<CIPH>(ff1: &FF1<CIPH>, data: &BigUint, tweek: &str, pad: usize) -> String
    where CIPH: NewBlockCipher + BlockCipher + Clone {

    // Get the plain text as bytes.
    let mut pt_vec = data.to_bytes_le();

    // Resize the plain text vector to be the same size as the max possible value
    // for the plain text.  The ff1 will return exactly as many bytes as input, so
    // we need to make sure that the input vector has as many bytes as the max possible
    // input integer, even for smaller integers.
    if pt_vec.len() < pad {
        pt_vec.resize_with(pad, Default::default)
    }

    // Encrypt with the FPE
    let pt_bns = BinaryNumeralString::from_bytes_le(&pt_vec);
    let ct = ff1.encrypt(&tweek.as_bytes(), &pt_bns).unwrap();

    // Encode to base32 and return
    let code = base32::encode(Alphabet::Crockford, &ct.to_bytes_le());
    code
}

pub fn decode<CIPH:>(ff1: &FF1<CIPH>, code: &str, tweek: &str) -> BigUint
    where CIPH: NewBlockCipher + BlockCipher + Clone {

    // Decode the cypher text from base32
    let ct_bytes = base32::decode(Alphabet::Crockford, code).unwrap();

    // Decrypt using the FPE
    let ct_bns = BinaryNumeralString::from_bytes_le(&ct_bytes);
    let pt = ff1.decrypt(&tweek.as_bytes(), &ct_bns).unwrap();

    // Convert back to a biguint
    BigUint::from_bytes_le(&pt.to_bytes_le())
}

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
    let f_lock = Arc::new(RwLock::new(f));

    let mut rng = rand::thread_rng();
    let size = space.bits() / 8;
    let from = rng.gen_biguint_below(&space.sub(&count));
    let to = from.clone().add(&count);

    let ff1 = FF1::<Aes256>::new(&key_bytes, 2).unwrap();

    let iter = num_iter::range(from, to).par_bridge();
    iter.for_each( |x| {
        let code = encode(&ff1, &x, tweek, size as usize);
        let validate = decode(&ff1, &code, tweek);
        assert_eq!(code, validate);
        f_lock.write().unwrap().f(x, code);
    });
}

pub fn encode<CIPH>(ff1: &FF1<CIPH>, data: &BigUint, tweek: &str, pad: usize) -> String
    where CIPH: NewBlockCipher + BlockCipher + Clone {
    let mut pt_vec = data.to_bytes_le();
    if pt_vec.len() < pad {
        pt_vec.resize_with(pad, Default::default)
    }
    let pt_bns = BinaryNumeralString::from_bytes_le(&pt_vec);
    let ct = ff1.encrypt(&tweek.as_bytes(), &pt_bns).unwrap();
    let code = base32::encode(Alphabet::Crockford, &ct.to_bytes_le());
    code
}

pub fn decode<CIPH:>(ff1: &FF1<CIPH>, code: &str, tweek: &str) -> BigUint
    where CIPH: NewBlockCipher + BlockCipher + Clone {
    let ct_bytes = base32::decode(Alphabet::Crockford, code).unwrap();
    let ct_bns = BinaryNumeralString::from_bytes_le(&ct_bytes);
    let pt = ff1.decrypt(&tweek.as_bytes(), &ct_bns).unwrap();
    BigUint::from_bytes_le(&pt.to_bytes_le())
}

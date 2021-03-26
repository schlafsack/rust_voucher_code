use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fpe::ff1::FF1;
use aesni::Aes128 as Aes128ni;
use aes_soft::Aes128 as Aes128Soft;
use aesni::Aes256 as Aes256ni;
use aes_soft::Aes256 as Aes256Soft;
use rust_aes;
use num_bigint::BigUint;

const TWEEK: &str = "tweek";

pub fn criterion_benchmark_aes_soft_128(c: &mut Criterion) {
    let key = "0123456789abcdef".as_bytes();
    let ff1 = FF1::<Aes128Soft>::new(&key, 2).unwrap();
    let from = BigUint::from(13689245537u64);
    c.bench_function("encode with Aes128Soft", |b| b.iter(|| rust_aes::encode(&ff1,black_box(&from), TWEEK, 5)));
}

pub fn criterion_benchmark_aesni_128(c: &mut Criterion) {
    let key = "0123456789abcdef".as_bytes();
    let ff1 = FF1::<Aes128ni>::new(&key, 2).unwrap();
    let from = BigUint::from(13689245537u64);
    c.bench_function("encode with Aes128ni", |b| b.iter(|| rust_aes::encode(&ff1,black_box(&from), TWEEK, 5)));
}


pub fn criterion_benchmark_aes_soft_256(c: &mut Criterion) {
    let key = "0123456789abcdef0123456789abcdef".as_bytes();
    let ff1 = FF1::<Aes256Soft>::new(&key, 2).unwrap();
    let from = BigUint::from(13689245537u64);
    c.bench_function("encode with Aes256Soft", |b| b.iter(|| rust_aes::encode(&ff1,black_box(&from), TWEEK, 5)));
}

pub fn criterion_benchmark_aesni_256(c: &mut Criterion) {
    let key = "0123456789abcdef0123456789abcdef".as_bytes();
    let ff1 = FF1::<Aes256ni>::new(&key, 2).unwrap();
    let from = BigUint::from(13689245537u64);
    c.bench_function("encode with Aes256ni", |b| b.iter(|| rust_aes::encode(&ff1,black_box(&from), TWEEK, 5)));
}

criterion_group!(benches128, criterion_benchmark_aes_soft_128, criterion_benchmark_aesni_128);
criterion_group!(benches256, criterion_benchmark_aes_soft_256, criterion_benchmark_aesni_256);
criterion_main!(benches128, benches256);

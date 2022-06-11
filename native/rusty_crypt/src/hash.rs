use crate::types::IoList;
use ::sha1::Sha1;
use rustler::{Binary, Env, NewBinary};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::io::Write;

#[rustler::nif]
fn sha1<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha1>(env, data)
}

#[rustler::nif]
fn sha224<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha224>(env, data)
}

#[rustler::nif]
fn sha256<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha256>(env, data)
}

#[rustler::nif]
fn sha384<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha384>(env, data)
}

#[rustler::nif]
fn sha512<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha512>(env, data)
}

#[rustler::nif]
fn sha3_224<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha3_224>(env, data)
}

#[rustler::nif]
fn sha3_256<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha3_256>(env, data)
}

#[rustler::nif]
fn sha3_384<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha3_384>(env, data)
}

#[rustler::nif]
fn sha3_512<'a>(env: Env<'a>, data: IoList) -> Binary<'a> {
    inner_hash::<Sha3_512>(env, data)
}

fn inner_hash<'a, T: Digest>(env: Env<'a>, data: IoList) -> Binary<'a> {
    let mut binary = NewBinary::new(env, <T as Digest>::output_size());
    binary
        .as_mut_slice()
        .write_all(&T::digest(data.as_slice()))
        .unwrap();
    binary.into()
}

use crate::types::{BigInt, IoList};
use num_bigint::Sign;
use rustler::{Binary, Env, Error, NifResult};

#[rustler::nif]
fn bytes_to_integer<'a>(binary: Binary) -> NifResult<BigInt> {
    Ok(num_bigint::BigInt::from_bytes_be(Sign::Plus, binary.as_slice()).into())
}

#[rustler::nif]
fn exor<'a>(env: Env<'a>, bin1: IoList<'a>, bin2: IoList<'a>) -> NifResult<Binary<'a>> {
    if bin1.len() == bin2.len() {
        let mut bin = bin1
            .to_owned()
            .ok_or(Error::RaiseAtom("allocation_failed"))?;

        xor(bin.as_mut_slice(), bin2.as_slice());

        Ok(bin.release(env))
    } else {
        Err(Error::BadArg)
    }
}

#[inline(always)]
fn xor(buf: &mut [u8], data: &[u8]) {
    for i in 0..data.len() {
        buf[i] ^= data[i];
    }
}

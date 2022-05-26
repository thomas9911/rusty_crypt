use crate::types::{BigInt, BinaryInteger, IoList};
use num_bigint::Sign;
use rustler::{Binary, Env, Error, NewBinary, NifResult};

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

#[rustler::nif]
fn iolist_to_binary<'a>(env: Env<'a>, iolist: IoList<'a>) -> NifResult<Binary<'a>> {
    if iolist.is_list() {
        let mut new_binary = NewBinary::new(env, iolist.len());
        new_binary.as_mut_slice().copy_from_slice(iolist.as_slice());
        Ok(new_binary.into())
    } else {
        Ok(iolist.0)
    }
}

#[rustler::nif]
fn mod_pow<'a>(n: BinaryInteger, p: BinaryInteger, m: BinaryInteger) -> NifResult<BinaryInteger> {
    if m.0.sign() == num_bigint::Sign::NoSign {
        return Err(Error::BadArg)
    }
    
    Ok(BinaryInteger(n.0.modpow(&p.0, &m.0)))
}

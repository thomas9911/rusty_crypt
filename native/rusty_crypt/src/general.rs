use rustler::types::atom::error;
use rustler::{Binary, Env, Error, NifResult, Term};

use num_bigint::Sign;

struct BigInt(num_bigint::BigInt);

impl std::ops::Deref for BigInt {
    type Target = num_bigint::BigInt;

    fn deref(&self) -> &num_bigint::BigInt {
        &self.0
    }
}

impl std::ops::DerefMut for BigInt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Into<BigInt> for num_bigint::BigInt {
    fn into(self) -> BigInt {
        BigInt(self)
    }
}

fn decode_big_integer(input: &[u8]) -> NifResult<BigInt> {
    if input[0] != 131 {
        return Err(Error::BadArg);
    };

    let big_int = match input[1] {
        97 => {
            // small integer / byte
            num_bigint::BigInt::from(input[2])
        }

        98 => {
            // integer
            num_bigint::BigInt::from_signed_bytes_be(&input[2..6])
        }

        110 => {
            // small big integer
            let n = input[2] as usize;
            let sign = if input[3] == 0 {
                Sign::Plus
            } else {
                Sign::Minus
            };

            num_bigint::BigInt::from_bytes_le(sign, &input[4..n + 4])
        }

        111 => {
            // large big integer
            let n = u32::from_be_bytes([input[2], input[3], input[4], input[5]]) as usize;
            let sign = if input[6] == 0 {
                Sign::Plus
            } else {
                Sign::Minus
            };

            num_bigint::BigInt::from_bytes_le(sign, &input[7..n + 7])
        }

        _ => return Err(Error::BadArg),
    };

    Ok(big_int.into())
}

fn encode_big_integer(big_int: &BigInt) -> Vec<u8> {
    let (sign, data) = big_int.to_bytes_le();
    let sign = if sign == Sign::Minus { 1 } else { 0 };

    let mut out = vec![131];
    if data.len() < 256 {
        // small big integer
        let n = data.len() as u8;
        out.push(110);
        out.push(n);
    } else {
        // large big integer
        let n = (data.len() as u32).to_be_bytes();
        out.push(111);
        out.extend(n);
    };
    out.push(sign);
    out.extend(data);

    out
}

impl<'a> rustler::Decoder<'a> for BigInt {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        decode_big_integer(term.to_binary().as_slice())
    }
}

impl rustler::Encoder for BigInt {
    fn encode<'c>(&self, env: Env<'c>) -> Term<'c> {
        let binary = encode_big_integer(self);
        if let Some((term, _)) = env.binary_to_term(&binary) {
            term
        } else {
            error().encode(env)
        }
    }
}

#[rustler::nif]
fn bytes_to_integer<'a>(binary: Binary) -> NifResult<BigInt> {
    Ok(num_bigint::BigInt::from_bytes_be(Sign::Plus, binary.as_slice()).into())
}

#[rustler::nif]
fn exor<'a>(env: Env<'a>, term1: Term<'a>, term2: Term<'a>) -> NifResult<Binary<'a>> {
    let bin1 = term1.decode_as_binary()?;
    let bin2 = term2.decode_as_binary()?;

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

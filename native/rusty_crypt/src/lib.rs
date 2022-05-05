use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rustler::{Binary, NewBinary};
use rustler::{Env, Error, NifResult, Term};
use sha2::{Digest, Sha256, Sha512};
use std::io::Write;

#[rustler::nif]
fn sha256<'a>(env: Env<'a>, a: Binary) -> Binary<'a> {
    let mut binary = NewBinary::new(env, Sha256::output_size());
    binary
        .as_mut_slice()
        .write_all(&Sha256::digest(a.as_slice()))
        .unwrap();
    binary.into()
}

#[rustler::nif]
fn aes256gcm<'a>(env: Env<'a>, key: Binary, text: Binary<'a>, iv: Binary) -> Binary<'a> {
    use aes_gcm::aead::heapless::Vec;

    let key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(key);
    let mut binary = NewBinary::new(env, 128);

    let nonce = Nonce::from_slice(iv.as_slice()); // 96-bits; unique per message

    // let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for GCM tag
    // buffer.extend_from_slice(text.as_slice());

    cipher
        .encrypt_in_place(nonce, b"", &mut text.as_mut_slice())
        .expect("encryption failure!");

    // binary.as_mut_slice().write_all(&buffer).unwrap();
    // binary.into()
    text
}

rustler::init!("Elixir.RustyCrypt", [sha256, aes256gcm]);

// :crypto.crypto_one_time_aead(:aes_256_gcm)

// key = <<0::256>>
// iv = <<1::256>>
// text = "hallo"
// # aad = "Some bytes"
// aad = <<>>

// {out, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, text, aad, true)
// :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, out, aad, tag, false)

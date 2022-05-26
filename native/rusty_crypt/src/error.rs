#[derive(rustler::NifUnitEnum)]
pub enum CryptoError {
    EncryptFailed,
    DecryptFailed,
    BadIVLength,
    BadKeyLength,
    BadTagLength,
}


impl CryptoError {
    pub fn to_nif_error(self) -> rustler::Error {
        rustler::Error::Term(Box::new(CryptoError::BadKeyLength))
    }
}
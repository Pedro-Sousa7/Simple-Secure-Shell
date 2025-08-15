use std::fmt::write;

/*
 * ########################################################
 * Errors enum for a better code base organization,
 * where it will support many types of errors as:
 *
 * Io - IO errors
 * Str - Error for parsing UTF8
 * Static - For defined errors
 * 
 * Also has Result<T> which is the same as Result<T,Error>
 * ########################################################
 */
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Str(std::str::Utf8Error),
    Static(&'static str),
    CryptoRSA(rsa::Error),
    CryptoPkcs1(rsa::pkcs1::Error),
}

impl From<rsa::pkcs1::Error> for Error {
    fn from(e: rsa::pkcs1::Error) -> Self {
        Error::CryptoPkcs1(e)
    }
}

impl From<rsa::Error> for Error {
    fn from(e: rsa::Error) -> Self {
        Error::CryptoRSA(e)
    }
    
}

impl From<&'static str> for Error {
    fn from(e: &'static str) -> Self {
        Error::Static(e)
    }
}

impl From<std::str::Utf8Error> for Error{
    fn from(e: std::str::Utf8Error) -> Self {
        Error::Str(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "Error: {}", e),
            Error::Static(e) => write!(f, "Error: {}",e),
            Error::Str(e) => write!(f, "Error: {}",e),
            Error::CryptoRSA(e) => write!(f,"Error: {}", e),
            Error::CryptoPkcs1(e) => write!(f,"Error: {}",e),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

use rsa::pkcs8::der::zeroize::Zeroizing;
use rsa::sha2::{Digest, Sha256};
use rsa::{ RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::Pkcs1v15Sign;

use crate::crypto::is_valid_public_key_pem;
use crate::error::{Result,Error};
/*
 *#########################################
 * File responsible for containing the key
 * generation for RSA Encryption used on
 * authentication.
 *
 * Will be generated a public key and a private key
 * ########################################
 */

//The RSA Key size used
const RSA_PRIVATE_KEY_SIZE:usize = 4096;
const GENERATION_ERROR:&str = "Failed to generate key";
const ERROR_PRIVATE_KEY_CONVERSION :&str = "Error converting the private key";
const ERROR_PUBLIC_KEY_CONVERSION : &str = "Error converting the public key";

pub struct RSAKeys{
    pub private_key : RsaPrivateKey,
    pub public_key : RsaPublicKey,
}

impl RSAKeys {
    
    pub fn new() -> Self{
        
        let mut rng = rand::thread_rng();

        let private_key = RsaPrivateKey::new(&mut rng,RSA_PRIVATE_KEY_SIZE).expect(GENERATION_ERROR);
        let public_key = RsaPublicKey::from(&private_key);

        Self { private_key, public_key}

    }

    //Converts the keys to a pem formact
    pub fn to_pem(&self) -> (Zeroizing<String>,String){

        let private_pem = self.private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).expect(ERROR_PRIVATE_KEY_CONVERSION);
        let public_pem = self.public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).expect(ERROR_PUBLIC_KEY_CONVERSION);

        (private_pem,public_pem)
    }

    //Validates a public key PEM, returns true or false if is valid 
    pub fn is_valid_pem(pem : &str) -> bool{

        RsaPublicKey::from_pkcs1_pem(pem).is_ok()

    }

    pub fn is_valid_signature_sha256(public_pem: &str, bytes: &[u8], signature: &[u8]) -> Result<()>{


        if !is_valid_public_key_pem(public_pem){
            return Err(Error::Static(ERROR_PUBLIC_KEY_CONVERSION))
        }

        let public_key = RsaPublicKey::from_pkcs1_pem(public_pem)?;

        let hashed = Sha256::digest(bytes);
        public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)?;
    
        Ok(())
    }

}

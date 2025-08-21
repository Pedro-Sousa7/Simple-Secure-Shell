use num_bigint::{BigUint};
use num_bigint::RandBigInt;
use num_traits::{Num, One};
use rand::seq::SliceRandom;
use rand::distributions::{Alphanumeric,DistString};
use crate::crypto::dhkeys::DHKeys;
use crate::crypto::session_keys::SessionKeys;
use crate::error::Result;

use crate::crypto::rsa::RSAKeys;
use crate::crypto::dhprimes::GROUPS;

mod dhprimes;
mod rsa;
pub mod dhkeys;
pub mod session_keys;
/*
 *###############################################
 * File responsible for number generation,
 * and some other calculations for crtptography
 *###############################################
 */

 
pub const HEX_RADIX: u32 = 16;

//Generates a int with a size
pub fn generate_random_int(size: u64) -> BigUint {
    rand::thread_rng().gen_biguint(size)
}

pub fn generate_dhkeys() -> DHKeys{
    DHKeys::new()
}

//Chooses a random pre-computed prime number
pub fn choose_random_prime() -> (BigUint,BigUint){
    
    let mut rng = rand::thread_rng();
    let values = GROUPS.choose(&mut rng).unwrap();
    
    let hex = values.0.replace([' ', '\n'], ""); //Clears the prime string
    let prime = BigUint::from_str_radix(&hex, 16).expect("Invalid Hex Prime");

    (prime, BigUint::from(values.1))
}

/*
 *  A subgroup of a number N, is the interval of [1,N-1]
 */
pub fn is_subgroup_of(group_max : &BigUint, value : &BigUint ) -> bool{
    *value < BigUint::one() || *value >= *group_max
}

//Generetes RSA Keys a public key and a private
pub fn generate_rsa_keys()-> RSAKeys{
    RSAKeys::new()
}

//Validates a PEM to check if is a valid public key 
pub fn is_valid_public_key_pem(pem: &str) -> bool{
    RSAKeys::is_valid_pem(pem)
}

pub fn generate_random_string(size: usize) -> String{
    Alphanumeric.sample_string(&mut rand::thread_rng(), size)
}

pub fn is_valid_signature_sha256(public_pem: &str, bytes: &[u8], signature: &[u8]) -> Result<()>{
    RSAKeys::is_valid_signature_sha256(public_pem, bytes, signature)
}

pub fn generate_session_keys(session_hash: &Vec<u8>, shared_key : BigUint) -> SessionKeys{
    SessionKeys::new(session_hash, shared_key)
}

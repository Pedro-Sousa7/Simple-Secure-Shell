use num_bigint::BigUint;
use num_traits::{Zero};
use crate::crypto;
use crate::error::{Error, Result};
/*
 *######################################################
 * Diffie-Hellman Key Exchange is an algorithm
 * used to exchange sessions keys in a TCP connection,
 * used to encrypt data.
 *
 * The keys are an:
 * p - Prime Number of 2048 bits
 * g - A primitive root of p
 * a - Private Key of 512 bits
 * A - Public Key
 * K - Exchanged Key
 *
 * First, both machine will agree on a p and a g, then
 * each machine will generate a random private key,
 * and the public key will be calculated.
 *
 * A = g^a mod p 
 *
 * After, that they both will exchange the public keys,
 * and will calculate a common K.
 *
 * K = B^a mod p 
 *
 * This K, will be used to encrypt the communications
 *######################################################
 */

const PRIVATE_KEY_SIZE: u64 = 512;
const INVALID_PUBLIC_KEY_ERROR: &'static str = "Received Invalid Public Key";

//Keys and values that are exchanged
struct ExchangedKeys {
    public_key : BigUint,
    prime : BigUint,
    generator: BigUint
}

pub struct DHKeys {
    private_key: BigUint,
    other_keys: ExchangedKeys
} 


impl DHKeys {

    //Creates a new set of keys for DH
    pub fn new() -> Self{

        let prime_and_generator = crypto::choose_random_prime();
        
        //Creates all keys attributes
        let mut private_key : BigUint = BigUint::zero();
        let prime: BigUint = prime_and_generator.0;
        let generator: BigUint = prime_and_generator.1;
        let mut public_key: BigUint = BigUint::zero();

        Self::generate_keys(&mut private_key, &mut public_key, &prime, &generator);

        Self {private_key ,other_keys: ExchangedKeys::new(public_key,prime,generator)}
    }


    //Function responsible for creating values for keys correctly
    fn generate_keys(private_key:&mut BigUint,public_key : &mut BigUint, p :&BigUint,g:&BigUint){
        
        while !crypto::is_subgroup_of(p, public_key) { //While the private key is invalid
            
            *private_key = crypto::generate_random_int(PRIVATE_KEY_SIZE); //Creates a random private
                                                                         //key of 2048 bits

            *public_key = g.modpow(private_key,p);

        }

    }

    //Computes the shared key, returning an error in case of the received public key
    //being invalid
    pub fn compute_shared_key(&self,public_key : &BigUint) -> Result<BigUint>{
        
        if crypto::is_subgroup_of(&self.other_keys.prime, public_key){ //Checks if the public key is
                                                                     //valid

            return Ok(public_key.modpow(&self.private_key, &self.other_keys.prime));
        }
        Err(Error::Static(INVALID_PUBLIC_KEY_ERROR))
    }

    pub fn get_exchanged_keys(&self) -> &ExchangedKeys{
        &self.other_keys
    }
}

impl ExchangedKeys{

   pub fn new(public_key: BigUint, prime: BigUint, generator: BigUint) -> Self{

       Self {public_key,prime,generator}
    } 
}


/*
 * ####################################
 * File responsible for DH key exchange
 * ####################################
 *
 */

use std::io::{Write,Read};
use std::net::TcpStream;

use num_bigint::BigUint;

use crate::crypto::dhkeys::DHKeys;
use crate::error::Result;
use crate::session::{protocol, utils};

pub fn handle_dh_keys_exchange(stream : &mut TcpStream) -> Result<BigUint>{

    let keys = DHKeys::new(); //Generates a new set of keys 

    send_keys(stream, &keys)?; //sends the keys 
                              
    let public_key = receive_public_key(stream)?;

    keys.compute_shared_key(&public_key)
}  
//Sends the keys as prime, generator and this public key for the other machine
fn send_keys(stream : &mut TcpStream,keys: &DHKeys) -> Result<()>{


    let byte = protocol::SsshMessages::KeyExchange as u8; //sends the byte for key exchange 
                                                    
    stream.write_all(&[byte])?;

    let exchanged_keys = keys.get_exchanged_keys(); //Gets the shared keys

    let shared_key_bytes = bincode::serialize(&exchanged_keys).unwrap();
    stream.write_all(&shared_key_bytes)?;

    Ok(())

}

//First reads, the key size, then the key
fn receive_public_key(stream :&mut TcpStream) -> Result<BigUint>{


    let key_data = utils::read_from_tcp(stream)?;

    Ok(BigUint::from_bytes_be(&key_data)) 



}

/*
 * #####################################
 *  File responsible for the connection
 * functions, during all the process
 * #####################################
 *
 */

use std::{io::{Read, Write}, net::{Ipv4Addr, SocketAddrV4, TcpStream}};

use crate::{crypto, file_sys, session::protocol};
use crate::error::{Result,Error};

const CONNECTION_ERROR : &str = "Cannot connect to the given address and port";
const PROTOCOL_ERROR: &str = "The server, is working with a different protocol on the same port";

const CHALLENGE_STRING_SIZE : usize = 32;
/*
 * The function will verify if the port is valid,
 * also will verify if the host is known.
 * This verification is made, by requesting a public key,
 * and 
 * 
 * Then will request a DH Key exchange to encrypt messages.
 */
pub fn start_connection(socket: &SocketAddrV4) -> Result<TcpStream>{

    let mut stream = verify_port(socket)?;

    handle_public_key_verification(socket, &mut stream)?;
    
    //TODO: Start DH Exchange, it must return the hash (Session)

    Ok(stream)

}

//Verifies if the other machine is on, and if is the same protocol
fn verify_port(socket: &SocketAddrV4) -> Result<TcpStream>{


    if let Ok(mut stream) = TcpStream::connect(socket){

        let banner_as_bytes = protocol::PROTOCOL_BANNER.as_bytes();
        let _ = stream.write_all(banner_as_bytes); //Sends the banner as bytes
        
        let mut buffer = [0u8;protocol::BUFFER_MAX_SIZE]; //For reading the response

        let size = stream.read(&mut buffer)?;

        //Verifies if the banners match
        if buffer[..size].trim_ascii() != banner_as_bytes{
            return Err(Error::Static(PROTOCOL_ERROR));
        }

        Ok(stream)

    }else{
        Err(Error::Static(CONNECTION_ERROR))
    }


}

fn handle_public_key_verification(socket: &SocketAddrV4, stream: &mut TcpStream) -> Result<()>{

    //asks for the other machine public key
    let public_key_pem = ask_public_key(stream)?;
  

    let address : Ipv4Addr = *socket.ip();

    //Gets the server stored key
    let stored_public_key_pem = file_sys::get_known_host_key(&address)?;

    //Verifies if the keys, match and if they don't will warn the user about it
    file_sys::handle_key_verification_on_known_hosts(&stored_public_key_pem, &public_key_pem,&address)?;
   

   //Tests if the server actually has the private key 
    verify_server_private_key_with_challenge(stream, &public_key_pem)?;
    


    Ok(())

}

//Asks the other machine for their public key, for comparing
fn ask_public_key(stream: &mut TcpStream) -> Result<String>{

    //Requests the server a public key
    let byte = protocol::SsshMessages::PublicKey as u8;
    stream.write_all(&[byte])?;


    //Reads response 
    let mut buffer = [0u8; protocol::BUFFER_MAX_SIZE];

    let size = stream.read(&mut buffer)?;

    match str::from_utf8(&buffer[..size]) {

        Ok(public_key_pem) => Ok(public_key_pem.trim().to_string()),
        Err(e) => Err(Error::from(e)),
        
    } 

}

//Will create a public key challenge to test if the other machine has the private key of 
//the public key, where this function will ask the server to sign with their private key a random
//32 bytes string, and we must with the public key verify it, and compare if they match.

fn verify_server_private_key_with_challenge(stream : &mut TcpStream, public_key_pem : &str) -> Result<()>{

    //Generates the 32 random string
    let binding = crypto::generate_random_string(CHALLENGE_STRING_SIZE);
    let random_str = binding.as_bytes();

    //Sends a byte for starting the challenge
    let byte = protocol::SsshMessages::Challenge as u8;

    //Sends the byte
    stream.write_all(&[byte])?;
    stream.write_all(random_str)?;

    let mut buffer = [0u8;protocol::BUFFER_MAX_SIZE];

    let size = stream.read(&mut buffer)?;

    let signature = &buffer[..size];

    crypto::is_valid_signature_sha256(public_key_pem, random_str, signature)
}

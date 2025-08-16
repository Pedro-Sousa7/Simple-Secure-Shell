use std::{io::{Read, Write}, net::{Ipv4Addr, SocketAddrV4, TcpStream}};
use crate::{crypto, file_sys, session::protocol};
use crate::error::{Result, Error};
use std::str;

const CHALLENGE_STRING_SIZE: usize = 32;

pub fn handle_public_key_verification(socket: &SocketAddrV4, stream: &mut TcpStream) -> Result<()> {
    // asks for the other machine public key
    let public_key_pem = ask_public_key(stream)?;

    let address: Ipv4Addr = *socket.ip();

    // gets the server stored key
    let stored_public_key_pem = file_sys::get_known_host_key(&address)?;

    // verifies if the keys match, and if not, will warn the user
    file_sys::handle_key_verification_on_known_hosts(&stored_public_key_pem, &public_key_pem, &address)?;

    // tests if the server actually has the private key
    verify_server_private_key_with_challenge(stream, &public_key_pem)?;

    Ok(())
}

// reads exactly N bytes from the stream
fn read_exact_n(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// asks the other machine for their public key, for comparing
fn ask_public_key(stream: &mut TcpStream) -> Result<String> {
    // requests the server a public key
    let byte = protocol::SsshMessages::PublicKey as u8;
    stream.write_all(&[byte])?;

    // first read the size (1 byte)
    let mut size_buf = [0u8; 1];
    stream.read_exact(&mut size_buf)?;
    let size = size_buf[0] as usize;

    // then read the payload with that size
    let buffer = read_exact_n(stream, size)?;

    match str::from_utf8(&buffer) {
        Ok(public_key_pem) => Ok(public_key_pem.trim().to_string()),
        Err(e) => Err(Error::from(e)),
    }
}

// will create a public key challenge to test if the other machine has the private key 
// of the public key, where this function will ask the server to sign with their private key 
// a random 32 bytes string, and we must verify it with the public key.
fn verify_server_private_key_with_challenge(stream: &mut TcpStream, public_key_pem: &str) -> Result<()> {
    // generates the 32 random string
    let binding = crypto::generate_random_string(CHALLENGE_STRING_SIZE);
    let random_str = binding.as_bytes();

    // sends a byte for starting the challenge
    let byte = protocol::SsshMessages::Challenge as u8;
    stream.write_all(&[byte])?;
    stream.write_all(random_str)?;

    // first read size (1 byte)
    let mut size_buf = [0u8; 1];
    stream.read_exact(&mut size_buf)?;
    let size = size_buf[0] as usize;

    // then read the signature
    let buffer = read_exact_n(stream, size)?;
    let signature = &buffer[..];

    crypto::is_valid_signature_sha256(public_key_pem, random_str, signature)
}


/// Sends a string to the server, receives a signed response, and validates it
pub fn send_and_verify_signed_message(stream: &mut TcpStream,public_key_pem: &str,message: &str,) -> Result<()> {
    // Send the original message
    let msg_bytes = message.as_bytes();
    stream.write_all(&(msg_bytes.len() as u8).to_be_bytes())?; // send size first
    stream.write_all(msg_bytes)?;

    // Receive size of signature
    let mut size_buf = [0u8; 1];
    stream.read_exact(&mut size_buf)?;
    let sig_size = size_buf[0] as usize;

    // Receive the signature
    let mut sig_buf = vec![0u8; sig_size];
    stream.read_exact(&mut sig_buf)?;

    // Validate the signature with the provided public key
    crypto::is_valid_signature_sha256(public_key_pem, msg_bytes, &sig_buf)

}

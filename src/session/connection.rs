/*
 * #####################################
 *  File responsible for the connection
 * functions, during all the process
 * #####################################
 *
 */

use std::{io::{Read, Write}, net::{SocketAddrV4, TcpStream}};

use num_bigint::BigUint;

use crate::session::{challenge, dhkeys, protocol, utils};
use crate::error::{Result,Error};

const CONNECTION_ERROR : &str = "Cannot connect to the given address and port";
const PROTOCOL_ERROR: &str = "The server, is working with a different protocol on the same port";
/*
 * The function will verify if the port is valid,
 * also will verify if the host is known.
 * This verification is made, by requesting a public key,
 * and 
 * 
 * Then will request a DH Key exchange to encrypt messages.
 */
pub fn start_connection(socket: &SocketAddrV4) -> Result<(TcpStream,BigUint)> {

    let mut stream = verify_port(socket)?;

    challenge::handle_public_key_verification(socket, &mut stream)?;
    
    //Stats an DH Key exchange and calculates the shared key
    let shared_key = dhkeys::handle_dh_keys_exchange(&mut stream)?;
    Ok((stream,shared_key))

}

//Verifies if the other machine is on, and if is the same protocol
fn verify_port(socket: &SocketAddrV4) -> Result<TcpStream>{


    if let Ok(mut stream) = TcpStream::connect(socket){

        let banner_as_bytes = protocol::PROTOCOL_BANNER.as_bytes();
        let _ = stream.write_all(banner_as_bytes); //Sends the banner as bytes
        
        let buffer = utils::read_from_tcp(&mut stream)?;

        //Verifies if the banners match
        if buffer[..].trim_ascii() != banner_as_bytes{
            return Err(Error::Static(PROTOCOL_ERROR));
        }

        Ok(stream)

    }else{
        Err(Error::Static(CONNECTION_ERROR))
    }


}

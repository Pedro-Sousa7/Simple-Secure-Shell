use std::fmt::format;
use std::net::{SocketAddr, SocketAddrV4};

mod protocol;
mod utils;
mod connection;
mod challenge;
mod dhkeys;

use num_bigint::BigUint;
use rsa::sha2::{Digest, Sha256};

use crate::error::Result;
use crate::crypto::dhkeys::DHKeys;
use crate::file_sys;
/*
 *#########################################################
 *File responsible for the SSSH Session, where
* it contains the struct Session, which has the
 * connected socket, the user, and a hash, which is 
 * session unique.
 *
 * Also has many methods of connection with the server.
 *
 * The hash is computed with:
 *
 * H = HASH(shared key || Server public key || user)
 *
 * Now we may derive all necessary keys.
 * We may use a key for the HMAC and one for the message
 *
 * HMAC_KEY = HASH( H || K || "B")
 * ENC_KEY = HASH(H || K || "A")
 * 
 * HMAC = MAC(key, sequence number || uncrypted packet)
 *
 *#########################################################
 *
 */

pub struct Session{
    user : String,
    socket : SocketAddr,
    hash : String,
    dhkeys : DHKeys,
}

impl Session {

    /* 
     * The identifier is a string which has an user and the ip, in the following format 
     * user#ip , also has the port, if it is not the default one
     */
    pub fn connect(identifier: &str, _port: Option<u16>)-> Result<()>{

        //If a different port is selected different than the default
        let port = _port.unwrap_or(protocol::DEFAULT_PORT);
        
        let identifier_splitted = utils::identifier_to_user_ip(identifier)?;

        let _user = identifier_splitted.0;//Gets the user 
        let _socket = SocketAddrV4::new(identifier_splitted.1, port); //Creates a socket 

        let (stream,shared_key) = connection::start_connection(&_socket)?;

        let hash = Session::compute_hash(&shared_key,&_user);

        Ok(())
    }

    fn compute_hash(shared_key : &BigUint,  user : &str) -> Result<String>{
        
        let public_key_pem = match file_sys::get_known_host_key(&address){
            Ok(p) => p.unwrap(),
            Err(e) => return Err(e),
        };


        let mut hasher = Sha256::new();
        hasher.update(shared_key.to_bytes_be());
        hasher.update(public_key_pem.as_bytes());
        hasher.update(user.as_bytes());

        let result = hasher.finalize();

        let hex : String = result.iter().map(|b| format!("{:02x}",b)).collect();
        Ok(hex)
    }
}



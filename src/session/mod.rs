use std::net::{SocketAddr, SocketAddrV4};

mod protocol;
mod utils;
mod connection;

use crate::error::Result;
/*
 *#####################################################
 *File responsible for the SSSH Session, where
* it contains the struct Session, which has the
 * connected socket, the user, and a hash, which is 
 * session unique.
 *
 * Also has many methods of connection with the server.
 *######################################################
 *
 */

pub struct Session{
    user : String,
    socket : SocketAddr,
    hash : String,
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

        connection::start_connection(&_socket)?;

        Ok(())
    }
}




/*
 * #######################################
 * File responsible for the inclusion
 * of utility functions, for the process
 * #######################################
 */

use std::net::Ipv4Addr;
use crate::error::{Result,Error};

const SPLIT_CHAR : char = '#';
const SPLIT_IDENTIFIER_INVALID_ERROR : &str = "Invalid identifier format use: user#ip";
const IP_INVALID_ERROR : &str = "Invalid IP address format";

//Divides an identifier, which is user#ip, into a IPV4 and a String
pub fn identifier_to_user_ip(identifier: &str) -> Result<(String, Ipv4Addr)>{


    if let Some((user,ip_str)) = identifier.split_once(SPLIT_CHAR){
        
        let ip : Ipv4Addr = ip_str.parse().map_err(|_| Error::Static(IP_INVALID_ERROR))?;
        Ok((user.to_string(),ip))    
    }else {
        Err(Error::Static(SPLIT_IDENTIFIER_INVALID_ERROR))
    }
}

use std::net::Ipv4Addr;
use crate::error::Result;
mod path;
mod utils;
mod hosts;
pub mod rsa;

/*
 *#########################################
 * File System, the file controling all 
 * files, and operations from the protocol
 *#########################################
 */

pub fn add_new_known_host(address : &Ipv4Addr, public_key_pem : &str) -> Result<()>{
    hosts::write_new_host(address, public_key_pem)
}

pub fn get_known_host_key(address : &Ipv4Addr) -> Result<Option<String>>{
    hosts::get_host_public_key_by_ip(address)
}

pub fn update_host_key(address : &Ipv4Addr, new_public_key_pem : &str) -> Result<()>{
    hosts::replace_host_key(address, new_public_key_pem)
}

pub fn handle_key_verification_on_known_hosts(stored_public_key_pem: &Option<String>, public_key_pem : &str, address : &Ipv4Addr) -> Result<()>{
    hosts::public_key_file_verification(stored_public_key_pem, public_key_pem, address)
}

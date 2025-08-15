use std::env;
use std::path::PathBuf;
use crate::file_sys::utils::ensure_relative_path;
use crate::error::{Error,Result};
/*
 *#############################################################
 * All the used file paths from the system
 *
 * SSSH_SERVER_KEYS_PATH - The path to the server keys 
 * SSSH_SERVER_PRIVATE_KEY - The private key from the server
 * SSSH_SERVER_PUBLIC_KEY - The public key from the server
 *
 *##############################################################
 */

pub const SSSH_SERVER_KEYS_PATH : &str = "/etc/sssh/";
pub const SSSH_RELATIVE_PATH : &str = ".sssh/";
pub const SSSH_SERVER_PRIVATE_KEY: &str = "/etc/sssh/priv";
pub const SSSH_SERVER_PUBLIC_KEY : &str = "/etc/sssh/public.pub";
pub const SSSH_RELATIVE_KNOWN_HOSTS : &str = ".sssh/known_hosts";

const HOME_NOT_SET : &str = "HOME variable not set";


//Gets the known_hosts since only knows the user running during execution.
pub fn known_hosts_path() -> Result<PathBuf> {

    ensure_relative_path()?;


    let path = get_home_path()?;

    return Ok(path.join(SSSH_RELATIVE_KNOWN_HOSTS));

    
}

pub fn get_home_path() -> Result<PathBuf>{

    match env::var_os("HOME") {
        Some(home) => Ok(PathBuf::from(home)),
        None => Err(Error::Static(HOME_NOT_SET)),
    }
}

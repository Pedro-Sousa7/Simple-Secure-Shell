use std::io::Write;
use std::{fs::File, path::Path};
use std::fs;

use crate::error::Result;
use crate::file_sys::path::{ SSSH_SERVER_PRIVATE_KEY, SSSH_SERVER_PUBLIC_KEY};
use crate::file_sys::utils::ensure_base_path;


/*
 *##################################################
 * File responsible for SSSH RSA Keys writing
 *
 * ensure_server_keys() -> Checks if the server keys
 * exist, else creates them
 *
 * generate_server_key() -> Creates the server keys
 * ##################################################
 */


 //Ensures that the server keys exist, else we create it
 pub fn ensure_server_keys() -> Result<()> {
    
    ensure_base_path()?;

    // If at at least one of the keys does not exist we create both 
    if !keys_exist() {
        generate_server_key_files_and_store()?
    }

    Ok(())
}


// Checks if both keys exist
fn keys_exist() -> bool {
    Path::new(SSSH_SERVER_PRIVATE_KEY).exists() &&
    Path::new(SSSH_SERVER_PUBLIC_KEY).exists()
}

// Deletes the existing key
fn remove_keys_if_exist() -> Result<()> {
    if Path::new(SSSH_SERVER_PRIVATE_KEY).exists() {
        fs::remove_file(SSSH_SERVER_PRIVATE_KEY)?;
    }
    if Path::new(SSSH_SERVER_PUBLIC_KEY).exists() {
        fs::remove_file(SSSH_SERVER_PUBLIC_KEY)?;
    }
    Ok(())
}

//Creates new keys, after deleting old ones
fn generate_server_key_files_and_store() -> Result<()>{

    remove_keys_if_exist()?; //Removes if one of the keys is there

    //Writes both keys
    write_server_keys_in_files()?;

    Ok(())
}

//For public use, to update the server keys
pub fn generate_server_key() -> Result<()>{

    ensure_base_path()?;
    generate_server_key_files_and_store()?;

    Ok(())
}

//Generates the RSA Keys, and writes them
fn write_server_keys_in_files() -> Result<()>{

    let rsa_keys = crate::crypto::generate_rsa_keys();

    //Converts the keys to PEM format
    let (private_pem,public_pem) = rsa_keys.to_pem();

    //Creates the key files
    let mut priv_file = File::create(SSSH_SERVER_PRIVATE_KEY)?;
    let mut pub_file = File::create(SSSH_SERVER_PUBLIC_KEY)?;

    //Writes on the files the pem
    priv_file.write_all(private_pem.as_bytes())?;
    pub_file.write_all(public_pem.as_bytes())?;

    Ok(())
}

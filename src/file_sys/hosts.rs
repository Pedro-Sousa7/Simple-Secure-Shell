use std::fs::{File, OpenOptions};
use std::net::Ipv4Addr;
use std::io::{BufReader, Write, BufRead};
use crate::file_sys::path::known_hosts_path;
use crate::error::{Result,Error};
use crate::file_sys::update_host_key;
/*
 * #########################################################
 * Contains the logic behind verifying if a machine
 * is safe to connect, by comparing the public key.
 *
 * Also the file represents the logic to add a new server, 
 * and his public key.
 *
 * The file will store by the following rules: 
 *
 * SERVER_A_IP#\nPUBLIC_KEY_A\n\nSERVER_B_IP#\nPUBLIC_KEY_B\n\n...
 * #########################################################
 */

const INVALID_PUBLIC_KEY_PEM_ERROR : &str = "The received public key is invalid";

 const WARNING_PUBLIC_KEY_CHANGED : &str = "The following address, has a different public key from the stored one at 
~/.ssh/known_hosts, this could be an ATTACK, known as MITM (Man In The Middle).\n If you are sure the connection is safe you may continue at your own risk. This will overwrite the stored key by the new one if you proceed."; 


//Verifies if the file exists and creates it, if not exists
fn ensure_known_hosts_file() -> Result<()> {
    let path = known_hosts_path()?;

    if !path.exists() {
        OpenOptions::new().create(true).write(true).truncate(true).open(&path)?;
    }

    Ok(())
}

//Writes a new host on the file
pub fn write_new_host(address : &Ipv4Addr, public_key_pem : &str) -> Result<()>{

    ensure_known_hosts_file()?;

    let path = known_hosts_path()?;
   let mut file = OpenOptions::new().append(true).open(path)?;

   write!(file,"{}#\n{}\n\n",address,public_key_pem)?;

    Ok(())
}

pub fn get_host_public_key_by_ip(address: &Ipv4Addr) -> Result<Option<String>>{

    ensure_known_hosts_file()?;

    let path = known_hosts_path()?;
    let file = File::open(path)?;

    let reader = BufReader::new(file);

    let target = format!("{}#",address);

    let mut lines = reader.lines();

    while let Some(line) = lines.next(){

        let line = line?;

        if line.trim() == target {
            //Reads the PEM
            let mut pem_lines = Vec::new();

            for pem_line in lines.by_ref() {
                let pem_line = pem_line?;
                // Stops at the end of the key
                if pem_line.trim().is_empty() {
                    break;
                }
                pem_lines.push(pem_line);
            }

            return Ok(Some(pem_lines.join("\n")));
        }



    }

    Ok(None) //No IP was found stored

}


//Updates a host key
pub fn replace_host_key(address: &Ipv4Addr, new_public_key_pem: &str) -> Result<()> {
    ensure_known_hosts_file()?;

    let path = known_hosts_path()?;
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let target = format!("{}#", address);

    let mut lines: Vec<String> = Vec::new();
    let mut lines_iter = reader.lines().peekable();

    let mut replaced = false;

    while let Some(line) = lines_iter.next() {
        let line = line?;
        if line.trim() == target && !replaced {
            lines.push(line);

            while let Some(Ok(pem_line)) = lines_iter.peek() {
                if pem_line.trim().is_empty() {
                    break;
                }
                lines_iter.next();
            }

            if let Some(Ok(pem_line)) = lines_iter.peek() {
                if pem_line.trim().is_empty() {
                    lines_iter.next();
                }
            }
            lines.push(new_public_key_pem.to_string());
            lines.push(String::new());
            replaced = true;
        } else {
            lines.push(line);
        }
    }

    if replaced {
        let mut file = OpenOptions::new().write(true).truncate(true).open(&path)?;
        for line in lines {
            writeln!(file, "{}", line)?;
        }
    }

    Ok(())
}

/*
 * Handles the known host verification of an address 
 */
pub fn public_key_file_verification(stored_public_key_pem: &Option<String>, public_key_pem : &str, address : &Ipv4Addr) -> Result<()>{

    //Validates public key received in pem format 
    if !crate::crypto::is_valid_public_key_pem(&public_key_pem){
        return Err(Error::Static(INVALID_PUBLIC_KEY_PEM_ERROR)); //Error because is not valid
    }   

    if let Some(stored_key) = stored_public_key_pem {

        //if the key changed could mean a man in the middle
        if stored_key != public_key_pem {
        
            //Asks confirmation if wants to save and progress on the connection
            let flag : bool = crate::utils::ask_confirmation(WARNING_PUBLIC_KEY_CHANGED);

            //Updates the key
            if flag {
                update_host_key(address, public_key_pem)?;
            }else{
                std::process::exit(0); //Closes the program, if the user does not want to continue
            }
        }

    } else {
        // if there is no key, we save this one
        write_new_host(address, public_key_pem)?;
    }
    Ok(())

}



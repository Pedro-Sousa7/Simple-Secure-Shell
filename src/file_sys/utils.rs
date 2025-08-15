use std::path::{Path, PathBuf};
use std::fs;
use crate::file_sys::path::{SSSH_SERVER_KEYS_PATH,SSSH_RELATIVE_PATH};
use crate::error::Result;
/*
 * ################################################
 * File responsible for holding auxiliary functions
 * ################################################
 */


//Creates the sssh path if not exists
pub fn ensure_base_path() -> Result<()>{

    let base_path = Path::new(SSSH_SERVER_KEYS_PATH);

    if !base_path.exists(){
        
        fs::create_dir(base_path)?

    }
    Ok(())
}

//Creates the sssh relative to user path if does not exist
pub fn ensure_relative_path() -> Result<()>{

    let home_path: PathBuf = crate::file_sys::path::get_home_path()?;

    let relative_path: PathBuf = home_path.join(SSSH_RELATIVE_PATH);

    
    if !relative_path.exists(){
        
        fs::create_dir(relative_path)?

    }
    Ok(())
}

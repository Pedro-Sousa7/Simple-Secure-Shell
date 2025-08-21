/*
 * ###################################################
 * File responsible for containing the keys struct,
 * which will be used for the communication encryption,
 * this keys will be:
 *
 * Client -> Server Encryption = Hash(H || K || "A")
 * Server -> Client Encryption = Hash(H || K || "B")
 *
 * Used for encryption e decryption.
 *
 * Client -> Server Integrity = Hash(H || K || "C")
 * Server -> Client Integrity = Hash(H || K || "D")
 *
 * This keys are the MAC, which verifies the Integrity
 * of the packet.
 *
 * MAC = Hash(sequence number | Decripted packet)
 * ###################################################
 */

use num_bigint::BigUint;
use rsa::sha2::{Sha256, Digest};
use crate::session::protocol::{CLIENT_SERVER_ENCRYPTION_BYTE,SERVER_CLIENT_ENCRYPTION_BYTE,CLIENT_SERVER_INTEGRITY_BYTE,SERVER_CLIENT_INTEGIRTY_BYTE};


pub struct SessionKeys{
    pub client_server_enc_key : Vec<u8>,
    pub server_client_enc_key : Vec<u8>,
    pub client_server_mac_key : Vec<u8>,
    pub server_client_mac_key : Vec<u8>,
}

impl SessionKeys {
    
    pub fn new(session_hash: &Vec<u8>, shared_key : BigUint) -> Self{


        let shared_key_bytes = shared_key.to_bytes_be();
        
        let client_server_enc_key = Self::derive_key(session_hash,&shared_key_bytes,CLIENT_SERVER_ENCRYPTION_BYTE);
        let server_client_enc_key = Self::derive_key(session_hash,&shared_key_bytes,SERVER_CLIENT_ENCRYPTION_BYTE);
        let client_server_mac_key = Self::derive_key(session_hash,&shared_key_bytes,CLIENT_SERVER_INTEGRITY_BYTE);
        let server_client_mac_key = Self::derive_key(session_hash,&shared_key_bytes,SERVER_CLIENT_INTEGIRTY_BYTE);

        Self {client_server_enc_key, server_client_enc_key, client_server_mac_key, server_client_mac_key}


    }

    fn derive_key(h : &Vec<u8>, k: &Vec<u8>, constant: u8) -> Vec<u8>{

        let mut hasher = Sha256::new();

        hasher.update(h);
        hasher.update(k);
        hasher.update([constant]);


        hasher.finalize().to_vec()
    }
}



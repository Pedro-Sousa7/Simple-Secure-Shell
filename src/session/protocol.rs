/*
 *##################################################################
 *File contains banners, and the
 *type of message, exchanged between
 *machines during the connection
 *
 * BANNER - Is used when the connection is
 * made to confirm the protocol
 *
 * SsshMessages - The trype of connections made.
 *
 *  PublicKey - Asks for the servers public key
 *  Challenge - Verifies if the server is owner of the private key
 *  KeyExchange - Starts the Diffie-Hellman.
 *  Auth - Sends the user and id_rsa.
 *  AuthSuccess - If the Auth was successful
 *  AuthFailure - If the Auth was a AuthFailure
 *  End - To end the connection between points
 *
 *###################################################################
 */

//Protocol banner
pub const PROTOCOL_BANNER : &str = "sssh_0.1";
pub const DEFAULT_PORT : u16 = 69;
pub const BUFFER_MAX_SIZE : usize = 2048;
//The sssh types of connection
#[repr(u8)]
pub enum SsshMessages {
    PublicKey = 0,
    Challenge = 1,
    KeyExchange = 2,
    Auth = 3,
    AuthSuccess = 4,
    AuthFailure = 5,
    End = 6,
}

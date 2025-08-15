use std::net::Ipv4Addr;
pub mod error;
mod utils;
mod session;
mod crypto;
mod file_sys;

fn main(){

    let address = Ipv4Addr::new(124, 34, 1, 1);
    /*let pem = String::from("-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAq3DnhgYgLVJknvDA3clATozPtjI7yauqD4/ZuqgZn4KzzzkQ4BzJ
ar4jRygpzbghlFn0Luk1mdVKzPUgYj0VkbRlHyYfcahbgOHixOOnXkKXrtZW7yWG
jXPqy/ZJ/+...
-----END RSA PUBLIC KEY-----");

    match file_sys::add_new_known_host(&address, &pem){
        Ok(_) => println!("Sucesso"),
        Err(e) => panic!("Error: {}",e),
    }

    let adress2 = Ipv4Addr::new(124,34,1,2);

   match file_sys::get_known_host_key(&adress2) {

       Ok(Some(key)) => println!("Chave: {}", key),
       Ok(None) => println!("Endereço não encontrado"),
       Err(e) => panic!("Error: {}",e),
       
   } 

   let pem2 = String::from("-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAq3DnhgYgLVJknvDA3clATozPtjI7yauqD4/ZuqgZn4KzzzkQ4BzJ
ar4jRygpzbghlFn0Luk1mdVKzPUgYj0VkbRlHyYfcahbgOHixOOnXkKXrtZW7yWG
jXPqy/ZJ/+...ABC
-----END RSA PUBLIC KEY-----");

    match file_sys::update_host_key(&address, &pem2) {
        Ok(_) => {},
        Err(e) => panic!("Error: {}",e),
    }
    */
}


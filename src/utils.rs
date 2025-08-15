/*
 *#############################################
 * File with functions that may not specific
 *#############################################
 */


/*
 * Asks for an input from a user,
 * this confirmation is a y/n
 *
 * returns if the user wants to progress
 */ 


pub fn ask_confirmation(prompt : &str) -> bool {

    loop{
        println!("{}",prompt);
        print!("Proceed? (y/n): ");
        
        let mut input = String::new();

        std::io::stdin().read_line(&mut input).unwrap();

        input = input.to_lowercase().trim().to_string();

        if input == "y" {
            return true;
        }
        if input == "n"{
            return false;
        }
    } 
}



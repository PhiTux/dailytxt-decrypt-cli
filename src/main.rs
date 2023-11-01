use colored::Colorize;
use std::env;
mod config;
mod encryption;
mod filesystem;

fn help() {
    println!("\n
******************************************************
* DailyTxT decrypt CLI - Decrypt your dailytxt files *
******************************************************

This tool decrypts your dailytxt files (as long as you know your password).
You can:
- choose to decrypt ALL files at once (either one file per month, or all logs in one large file), 
- or you can just decrypt a specific month.
The history will always be omitted!

Allowed commands:

dailytxt_decrypt -h 
    Show this help.

{}
dailytxt_decrypt [-a | --all] [--to-single-file] (-u | --user) <username> (-p | --password) <password> <from_path> <to_path>
    Decrypt all files in <from_path> and save them in <to_path>. 
    The filesystem in <from_path> must be the same as originally stored on the server.
    If --to-single-file is set, all files will be saved in one single file, nicely formatted. The history of each log will be omitted.
    Without --to-single-file, the original file structure will be restored.

{}   
dailytxt_decrypt (-s | --single) (-m | --month) <month> (-y | --year) <year> (-u | --user) <username> (-p | --password) <password> <from_path> <to_path>
    Decrypt a single file specified by month and year, which is found in the filesystem in <from_path> and save it in <to_path>.

{}
    Username and password MUST be given. Password can also be a backup code.
    <from_path> and <to_path> must be the last two parameters in exactly this order.
    ", "Decrypt all files".bold().underline(), "Decrypt a specific month".bold().underline(), "Important".bold().underline());
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = config::Config::new(&args).unwrap_or_else(|err| {
        println!("Problem parsing arguments: {}", err);

        help();
        std::process::exit(1);
    });

    if config.help {
        help();
        std::process::exit(0);
    }

    if !filesystem::path_exists(&config.from_path) {
        println!(
            "Source path does not exist!\n\nYou can use 'dailytxt_decrypt -h' to show the help."
        );
        std::process::exit(1);
    }

    println!("-> Calculating encryption key...");

    // get user_id and encryption_key
    let (user_id, encryption_key) = match filesystem::get_user_id_and_encryption_key(
        &config.user,
        &config.password,
        &config.from_path,
    ) {
        Ok((user_id, encryption_key)) => (user_id, encryption_key),
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    println!("-> Decrypting and writing files...");
    // start decrypting files
    if config.all {
        filesystem::decrypt_all_files(&config, user_id, encryption_key);
    } else {
        filesystem::decrypt_single_file(&config, user_id, encryption_key);
    }

    println!("-> Done!");
}

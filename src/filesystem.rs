use super::config;
use super::encryption;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::str;

pub fn path_exists(path: &str) -> bool {
    Path::new(path).exists()
}

fn get_content_of_file(path: &str) -> String {
    //Result<String, String> {
    let content = fs::read_to_string(path).map_err(|err| format!("Error: {}", err));
    match content {
        Ok(content) => content,
        Err(err) => {
            println!("Error with file {}: {}", path, err);
            std::process::exit(1);
        }
    }
}

fn password_valid(full_hash: String, password: &str) -> bool {
    let password = password.as_bytes();

    let parts: Vec<&str> = full_hash.split('$').collect();
    let salt = parts[1].as_bytes();
    let hash = parts[2];

    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC can take key of any size");
    mac.update(password);

    let calculated_hash = format!("{:x}", mac.finalize().into_bytes());

    calculated_hash == hash
}

pub fn get_user_id_and_encryption_key(
    user: &str,
    user_password: &str,
    from_path: &str,
) -> Result<(String, String), String> {
    // open users.json
    let content = get_content_of_file(
        (from_path.to_owned() + if from_path.ends_with("/") { "" } else { "/" } + "users.json")
            .as_str(),
    );

    // parse users.json
    json::parse(content.as_str())
        .map_err(|err| format!("Error: {}", err))
        .and_then(|users_json| {
            // find user
            let user_json = users_json["users"]
                .members()
                .find(|user_json| user_json["username"] == user)
                .ok_or_else(|| String::from("User not found!"))?;

            let user_id = user_json["user_id"].to_string();

            // check if password is valid (perhaps even as backup_code)
            let mut password = user_password.to_string();
            if !password_valid(user_json["password"].to_string(), &user_password) {
                password = "".to_string();

                // check if backup_codes are available
                if user_json["backup_codes"] == json::JsonValue::Null
                    || user_json["backup_codes"].len() == 0
                {
                    return Err(String::from("Wrong password!"));
                }

                for bc in user_json["backup_codes"].members() {
                    if password_valid(bc["password"].to_string(), &user_password) {
                        // calculate key to decrypt original password...
                        let mut password_key = [0u8; 32];
                        pbkdf2_hmac::<Sha256>(
                            user_password.as_bytes(),
                            &general_purpose::URL_SAFE
                                .decode(bc["salt"].to_string())
                                .unwrap(),
                            100000,
                            &mut password_key,
                        );

                        // decrypt original password with fernet
                        let key: String = general_purpose::URL_SAFE.encode(password_key);

                        let decryption_result =
                            encryption::decrypt_by_key(&key, &bc["enc_orig_password"].to_string());
                        password = match decryption_result {
                            Ok(encryption_key) => {
                                str::from_utf8(&encryption_key).unwrap().to_string()
                            }
                            Err(err) => {
                                println!("Error decrypting encryption key: {}", err);
                                std::process::exit(1);
                            }
                        };
                        break;
                    }
                }
            }
            if password == "" {
                return Err(String::from("Wrong password!"));
            }

            let mut password_key = [0u8; 32];
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                &general_purpose::URL_SAFE
                    .decode(user_json["salt"].to_string())
                    .unwrap(),
                100000,
                &mut password_key,
            );

            // decrypt encryption key with fernet
            let key = general_purpose::URL_SAFE.encode(password_key);

            let decryption_result =
                encryption::decrypt_by_key(&key, &user_json["enc_enc_key"].to_string());
            let encryption_key = match decryption_result {
                Ok(encryption_key) => str::from_utf8(&encryption_key).unwrap().to_string(),
                Err(err) => {
                    println!("Error decrypting encryption key: {}", err);
                    std::process::exit(1);
                }
            };

            Ok((user_id, encryption_key))
        })
}

fn add_to_nice_file(
    config: &config::Config,
    user_id: &str,
    year: &str,
    month: &str,
    nice_data: &Vec<(u8, String, Vec<(String, String)>)>,
) {
    let filepath = if config.to_single_file {
        config.to_path.to_owned() + "/" + user_id + "/logs.txt"
    } else {
        config.to_path.to_owned() + "/" + user_id + "/" + year + "/" + month + ".txt"
    };

    // create parent dirs
    fs::create_dir_all(Path::new(&filepath).parent().unwrap()).unwrap();

    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(filepath)
        .unwrap();

    let mut text_to_write: String = "".to_string();
    for (day, text, files) in nice_data {
        if text.trim() == "" && files.len() == 0 {
            continue;
        }
        text_to_write +=
            format!("-----------\n{}-{}-{}:\n-----------\n", year, month, day,).as_str();

        if text.trim() != "" {
            text_to_write += text;
            text_to_write += "\n\n";
        }

        if files.len() > 0 {
            text_to_write += "Files:\n";

            for (filename, uuid_filename) in files {
                text_to_write += format!("{} (with uuid: {})\n", filename, uuid_filename).as_str();
            }

            text_to_write += "\n";
        }

        text_to_write += "\n";
    }
    file.write_all(text_to_write.as_bytes()).unwrap();
}

/**
 * Handles the decryption of an uploaded data-file
 */
fn decrypt_file(
    config: &config::Config,
    user_id: &str,
    encryption_key: &str,
    filename: String,
    uuid_filename: &str,
) {
    // get file content
    let content =
        get_content_of_file((format!("{}/files/{}", config.from_path, uuid_filename)).as_str());

    // decrypt file content
    let decryption_result = encryption::decrypt_by_key(encryption_key, &content);
    let file_content = match decryption_result {
        Ok(file_content) => file_content,
        Err(err) => {
            println!("Error decrypting file: {}", err);
            b"Error decrypting file - Sorry!".to_vec()
        }
    };

    // write file
    let filepath = config.to_path.to_owned()
        + "/"
        + user_id
        + "/files/"
        + Path::new(&filename).file_stem().unwrap().to_str().unwrap()
        + "_"
        + uuid_filename
        + "."
        + Path::new(&filename).extension().unwrap().to_str().unwrap();
    fs::create_dir_all(Path::new(&filepath).parent().unwrap()).unwrap();
    fs::write(filepath, file_content).unwrap();
}

/**
 * Handles all the decryption of the content of a single file
 */
fn decrypt_file_content(
    config: &config::Config,
    user_id: &str,
    encryption_key: &str,
    year: &str,
    month: &str,
    content: &str,
) {
    let json = json::parse(content)
        .map_err(|err| format!("Error: {}", err))
        .unwrap();

    let mut nice_data: Vec<(u8, String, Vec<(String, String)>)> = [].to_vec();

    json["days"].members().for_each(|day| {
        // decrypt text
        let text: String;
        if day["text"] != json::JsonValue::Null && day["text"].as_str().unwrap() != "" {
            let decryption_result =
                encryption::decrypt_by_key(encryption_key, day["text"].as_str().unwrap());
            text = match decryption_result {
                Ok(text) => str::from_utf8(&text).unwrap().to_string(),
                Err(err) => {
                    println!("Error decrypting text: {}", err);
                    "Error decrypting text - Sorry!".to_string()
                }
            };
        } else {
            text = "".to_string();
        }

        // decrypt filenames
        let mut files: Vec<(String, String)> = [].to_vec();
        if day["files"] != json::JsonValue::Null && day["files"].len() > 0 {
            day["files"].members().for_each(|file| {
                let decryption_result = encryption::decrypt_by_key(
                    encryption_key,
                    file["enc_filename"].as_str().unwrap(),
                );
                let filename = match decryption_result {
                    Ok(file) => str::from_utf8(&file).unwrap().to_string(),
                    Err(err) => {
                        println!("Error decrypting file: {}", err);
                        "Error decrypting file - Sorry!".to_string()
                    }
                };
                files.push((
                    filename,
                    file["uuid_filename"].as_str().unwrap().to_string(),
                ))
            });
        }

        // decrypt files
        for f in &files {
            decrypt_file(config, user_id, encryption_key, f.0.to_string(), &f.1)
        }

        nice_data.push((day["day"].as_u8().unwrap(), text, files));

        return;
    });

    nice_data.sort_by_key(|k| k.0);
    add_to_nice_file(config, user_id, year, month, &nice_data)
}

pub fn decrypt_all_files(config: &config::Config, user_id: String, encryption_key: String) {
    let dirpath = config.from_path.to_owned()
        + if config.from_path.ends_with("/") {
            ""
        } else {
            "/"
        }
        + user_id.as_str();

    // get all dirs in user_id dir
    let readdir = match fs::read_dir(dirpath.as_str()) {
        Ok(readdir) => readdir,
        Err(err) => {
            println!("Error reading directory {}: {}", dirpath, err);
            std::process::exit(1);
        }
    };

    let mut paths: Vec<_> = readdir
        .filter_map(|r| {
            let entry = r.unwrap();
            if entry.metadata().unwrap().is_dir() {
                Some(entry)
            } else {
                None
            }
        })
        .collect();

    paths.sort_by_key(|dir| dir.path());

    for path in paths {
        let dirpath = path.path();
        let year = dirpath.file_name().unwrap().to_str().unwrap();

        let mut files: Vec<_> = fs::read_dir(path.path())
            .unwrap()
            .filter_map(|r| {
                let entry = r.unwrap();
                if entry.metadata().unwrap().is_file() {
                    Some(entry)
                } else {
                    None
                }
            })
            .collect();

        files.sort_by_key(|file| file.path());

        for file in files {
            let filepath = file.path();
            let month = filepath.file_stem().unwrap().to_str().unwrap();

            let content = get_content_of_file(file.path().to_str().unwrap());
            decrypt_file_content(config, &user_id, &encryption_key, year, month, &content);
        }
    }
}

pub fn decrypt_single_file(config: &config::Config, user_id: String, encryption_key: String) {
    let year = config.year.to_string();

    // make month two digits
    let month = if config.month.to_string().len() == 1 {
        "0".to_string() + config.month.to_string().as_str()
    } else {
        config.month.to_string()
    };

    let content = get_content_of_file(
        (config.from_path.to_owned()
            + if config.from_path.ends_with("/") {
                ""
            } else {
                "/"
            }
            + &user_id
            + "/"
            + &year
            + "/"
            + &month
            + ".json")
            .as_str(),
    );
    decrypt_file_content(config, &user_id, &encryption_key, &year, &month, &content);
}

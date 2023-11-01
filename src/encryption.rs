use fernet::{DecryptionError, Fernet};

pub fn decrypt_by_key(key: &str, message: &str) -> Result<Vec<u8>, DecryptionError> {
    let fernet = Fernet::new(key).unwrap();
    fernet.decrypt(message)
}

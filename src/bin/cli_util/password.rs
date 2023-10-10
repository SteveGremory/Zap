use rpassword::prompt_password;
use sha2::{Digest, Sha256, Sha512};

use zap::error::{HashingError, InputError, PasswordError};

pub fn get_password_confirm(key_len: usize) -> Result<Vec<u8>, PasswordError> {
    let pass = match prompt_password("Enter a password for encryption: ") {
        Ok(val) => val,
        Err(e) => return Err(InputError::from(e).into()),
    };

    let confirm_pass = match prompt_password("Repeat encryption password: ") {
        Ok(val) => val,
        Err(e) => return Err(InputError::from(e).into()),
    };

    if pass.is_empty() {
        return Err(PasswordError::PasswordEmpty);
    }

    if pass.ne(&confirm_pass) {
        return Err(PasswordError::PasswordsDoNotMatch);
    }

    Ok(convert_pw_to_key(pass, key_len)?)
}

pub fn get_password_noconf(key_len: usize) -> Result<Vec<u8>, PasswordError> {
    let pass = match prompt_password("Enter a password for encryption: ") {
        Ok(val) => val,
        Err(e) => return Err(InputError::from(e).into()),
    };

    Ok(convert_pw_to_key(pass, key_len)?)
}

// This will need to be reworked later as more encryption algorithms are
// brought in. May also need to be moved to 'bin'.
pub fn convert_pw_to_key(pw: String, len: usize) -> Result<Vec<u8>, HashingError> {
    match len {
        256 => Ok(Vec::from(&Sha256::digest(pw.as_bytes())[..])),
        512 => Ok(Vec::from(&Sha512::digest(pw.as_bytes())[..])),
        _ => Err(HashingError::UnrecognisedAlgorithmLength(len)),
    }
}
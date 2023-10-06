use clap::ValueEnum;
use rpassword::prompt_password;
use sha2::{Sha256, Digest};

use crate::{error::{HashingError, PasswordError, InputError, EncryptionSecretError, EncryptionKeyError}, util::return_if_equal};

// Consider moving
#[derive(Debug, Clone, ValueEnum)]
pub enum EncryptionType {
    Password,
    Key
}

pub enum EncryptionSecret {
    Password(Vec<u8>),
    Key(String)
}

impl TryFrom<(EncryptionType, Option<String>)> for EncryptionSecret {
    type Error = EncryptionSecretError;

    fn try_from(value: (EncryptionType, Option<String>)) -> Result<Self, Self::Error> {
        match value {
            (EncryptionType::Password, _) => match get_password_confirm(256) {
                Ok(pass) => Ok(EncryptionSecret::Password(pass)),
                Err(e) => Err(
                    e.into()
                )
            },
            // Unimplemented
            (EncryptionType::Key, Some(keyfile)) => Ok(EncryptionSecret::Key(keyfile)),
            (EncryptionType::Key, None) => Err(EncryptionKeyError::KeyfileNotProvided.into()),
        }
    }
}

pub fn get_password_confirm(key_len: usize) -> Result<Vec<u8>, PasswordError>
{

    let pass = match prompt_password("Enter a password for encryption: ") {
        Ok(val) => val,
        Err(e) => return Err(InputError::from(e).into())
    };

    let confirm_pass = match prompt_password("Repeat encryption password: ") {
        Ok(val) => val,
        Err(e) => return Err(InputError::from(e).into())
    };

    let user_pass = match return_if_equal(
        pass,
        confirm_pass
    ) {
        Some(p) => p,
        None => return Err(PasswordError::PasswordsDoNotMatch)
    };

    Ok(convert_pw_to_key(
        user_pass,
        key_len
    )?)
}

pub fn get_password_noconf(key_len: usize) -> Result<Vec<u8>, PasswordError>
{
    let pass = match prompt_password("Enter a password for encryption: ") {
        Ok(val) => val,
        Err(e) => return Err(InputError::from(e).into())
    };

    Ok(convert_pw_to_key(
        pass, 
        key_len
    )?)
}

// This will need to be reworked later as more encryption algorithms are
// brought in. May also need to be moved to 'bin'. 
pub fn convert_pw_to_key(pw: String, len: usize) -> Result<Vec<u8>, HashingError>
{
    match len {
        256 => {
            let mut out = Vec::new();

            out.extend_from_slice(&Sha256::digest(pw.as_bytes())[..]);

            Ok(out)
        },
        _ => Err(
            HashingError::UnrecognisedAlgorithmLength(len)
        )
    }
}
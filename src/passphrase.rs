// teleport, Copyright (c) 2022, Maximilian Burke
// This file is distributed under the FreeBSD(-ish) license.
// See LICENSE.TXT for details

use sodiumoxide::crypto::secretbox::Key;

use crate::error::Error;

pub(crate) struct Passphrase {
    pub key: Key,
    pub code: String,
}

pub(crate) fn create() -> Passphrase {
    use sodiumoxide::crypto::secretbox::gen_key;

    let key = gen_key();
    let code = hex::encode(&key);
    Passphrase { key, code }
}

pub(crate) fn key(code: &str) -> Result<Key, Error> {
    use http::StatusCode;
    use sodiumoxide::crypto::secretbox::KEYBYTES;

    let mut key = [0u8; KEYBYTES];
    if code.len() != 2 * KEYBYTES {
        return Err(Error::WithStatusCode(
            StatusCode::BAD_REQUEST,
            "invalid code length",
        ));
    }

    hex::decode_to_slice(code, &mut key).map_err(|e| Error::Internal(e.into()))?;
    Key::from_slice(&key).ok_or_else(|| Error::from("unable to create key"))
}

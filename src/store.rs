// teleport, Copyright (c) 2022, Maximilian Burke
// This file is distributed under the FreeBSD(-ish) license.
// See LICENSE.TXT for details

use once_cell::sync::OnceCell;
use tokio::sync::Mutex;

use crate::error::Error;

const DATA: &[u8] = &[b'D', b'A', b'T', b'A'];
const NAME: &[u8] = &[b'N', b'A', b'M', b'E'];
const STRING: &[u8] = &[b'S', b'T', b'R', b'N'];
const FIELDLEN: usize = 4;
const HEADERLEN: usize = 8;
static RETRIEVE_LOCK: OnceCell<Mutex<()>> = OnceCell::new();

pub(crate) enum Value {
    Secret(String),
    File {
        name: String,
        data: Vec<u8>,
        content_type: &'static str,
    },
}

pub(crate) struct SerializedData(Vec<u8>);

struct Chunk<'a> {
    base: &'a [u8],
    current: usize,
}

impl<'a> Chunk<'a> {
    fn new(base: &'a [u8]) -> Self {
        Self { base, current: 0 }
    }

    fn id(&self) -> &[u8] {
        let current = self.current;
        let base = self.base;
        &base[current..current + FIELDLEN]
    }

    fn len(&self) -> usize {
        let current = self.current;
        let base = self.base;
        let len: [u8; 4] = [
            base[current + FIELDLEN],
            base[current + FIELDLEN + 1],
            base[current + FIELDLEN + 2],
            base[current + FIELDLEN + 3],
        ];
        u32::from_le_bytes(len) as usize
    }

    fn data(&self) -> &[u8] {
        let len = self.len();
        let current = self.current;
        &self.base[current + HEADERLEN..current + HEADERLEN + len]
    }

    fn next(&mut self) -> bool {
        let len = self.len();
        let current = self.current;
        let base = self.base;
        self.current = current + HEADERLEN + len;

        current + HEADERLEN + len < base.len()
    }
}

pub(crate) fn init() -> Result<(), Error> {
    if RETRIEVE_LOCK.set(Mutex::new(())).is_ok() {
        Ok(())
    } else {
        Err(Error::AlreadyInitialized)
    }
}

pub(crate) fn serialize_secret(data: &str) -> Result<SerializedData, Error> {
    use http::StatusCode;

    if data.is_empty() {
        return Err(Error::WithStatusCode(
            StatusCode::BAD_REQUEST,
            "Secret must be non-empty",
        ));
    }

    let mut buf = STRING.to_vec();
    let bytes = data.as_bytes();
    let len = bytes.len() as u32;
    buf.extend(len.to_le_bytes());
    buf.extend(bytes);

    Ok(SerializedData(buf))
}

pub(crate) fn serialize_file_map(file_map: &[(String, Vec<u8>)]) -> Result<SerializedData, Error> {
    use http::StatusCode;

    if file_map.is_empty() {
        return Err(Error::WithStatusCode(
            StatusCode::BAD_REQUEST,
            "No files provided",
        ));
    }

    let mut buf = Vec::new();

    for (name, data) in file_map {
        buf.extend(NAME);
        let bytes = name.as_bytes();
        let len = bytes.len() as u32;
        buf.extend(len.to_le_bytes());
        buf.extend(bytes);

        buf.extend(DATA);
        let len = data.len() as u32;
        buf.extend(len.to_le_bytes());
        buf.extend(data);
    }

    Ok(SerializedData(buf))
}

async fn read(id: &str) -> Result<Vec<u8>, Error> {
    use std::fs::{read, remove_file};
    use std::path::PathBuf;

    use crate::CONFIG;

    let _guard = RETRIEVE_LOCK
        .get()
        .expect("mutex is not initialized; how did this happen?")
        .lock()
        .await;

    let data_dir = {
        let c = CONFIG.get().unwrap();
        &c.data_dir
    };

    // Check to make sure that we're not accidentally referring to anything outside
    // our intended scope by normalizing the path and validating that we still have
    // the same data directory root + id stem
    let path: PathBuf = [data_dir, id]
        .iter()
        .collect::<PathBuf>()
        .canonicalize()
        .map_err(|err| {
            use std::io::ErrorKind;

            if err.kind() == ErrorKind::NotFound {
                Error::SecretNotFound
            } else {
                error!("unable to canonicalize path: err='{:?}' id='{}'", err, id);
                Error::InvalidId
            }
        })?;

    if !path.starts_with(data_dir) {
        warn!(
            "canonicalized path does not start with data directory: id='{}' path='{:?}'",
            id, path
        );
        return Err(Error::InvalidId);
    }

    if path
        .file_name()
        .ok_or(Error::InvalidId)?
        .to_str()
        .ok_or(Error::InvalidId)?
        != id
    {
        warn!(
            "canonicalized path does not start with data directory: id='{}' path='{:?}'",
            id, path
        );
        return Err(Error::InvalidId);
    }

    let content = read(&path).map_err(|err| {
        error!(
            "unable to read data file: id='{}' path='{:?}' err='{}'",
            id, path, err
        );
        Error::InvalidId
    })?;
    remove_file(&path).map_err(|e| Error::Internal(e.into()))?;

    if path.exists() {
        return Err(Error::from(format!(
            "file should have been removed but wasn't: {:?}",
            path
        )));
    }

    Ok(content)
}

pub(crate) async fn retrieve(id: &str, code: &str) -> Result<Value, Error> {
    use http::StatusCode;
    use sodiumoxide::crypto::secretbox::{self, Nonce, NONCEBYTES};
    use std::io::{Cursor, Write};
    use zip::write::{FileOptions, ZipWriter};

    use crate::passphrase::key;
    use crate::CONFIG;

    let content = read(id).await?;

    let nonce = Nonce::from_slice(&content[0..NONCEBYTES])
        .ok_or_else(|| Error::from("unable to reinitialize nonce"))?;
    let ciphertext = &content[NONCEBYTES..];
    let key = key(code)?;
    let data = secretbox::open(ciphertext, &nonce, &key).map_err(|err| {
        warn!("unable to decrypt secret: err='{:?}'", err);
        Error::WithStatusCode(StatusCode::UNAUTHORIZED, "Unable to decrypt secret")
    })?;

    let mut chunk = Chunk::new(&data);
    let id = chunk.id();

    if id == STRING {
        let secret = std::str::from_utf8(chunk.data())
            .map(ToOwned::to_owned)
            .map_err(|e| Error::Internal(Box::new(e)))?;
        Ok(Value::Secret(secret))
    } else if id == NAME {
        let deny_files = {
            let c = CONFIG.get().unwrap();
            c.deny_files
        };

        if deny_files {
            return Err(Error::WithStatusCode(
                StatusCode::BAD_REQUEST,
                "Server has been configured to not allow sharing of files.",
            ));
        }

        let mut files = Vec::new();
        loop {
            let name = std::str::from_utf8(chunk.data())
                .map_err(|_| Error::InvalidData)?
                .to_owned();

            if !chunk.next() && chunk.id() != DATA {
                return Err(Error::WithStatusCode(
                    StatusCode::BAD_REQUEST,
                    "Data malformed",
                ));
            }

            let data = chunk.data().to_vec();
            files.push((name, data));

            if !chunk.next() {
                break;
            }
        }

        if files.len() == 1 {
            let entry = files.pop().unwrap();
            Ok(Value::File {
                name: entry.0,
                data: entry.1,
                content_type: "application/octet-stream",
            })
        } else {
            let mut data = Vec::new();
            {
                let mut cursor = Cursor::new(&mut data);
                let mut writer = ZipWriter::new(&mut cursor);
                for (name, data) in files {
                    writer.start_file(name, FileOptions::default())?;
                    writer.write_all(&data)?;
                }

                writer.finish()?;
            }

            Ok(Value::File {
                name: "teleport.zip".to_owned(),
                data,
                content_type: "application/zip",
            })
        }
    } else {
        Err(Error::WithStatusCode(
            StatusCode::BAD_REQUEST,
            "Data malformed",
        ))
    }
}

pub(crate) fn write(data: &SerializedData) -> Result<(String, String), Error> {
    use crate::passphrase::{self, Passphrase};
    use crate::CONFIG;

    use nix::errno::Errno;
    use nix::fcntl::OFlag;
    use nix::unistd::{linkat, LinkatFlags};
    use sodiumoxide::crypto::secretbox;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    let data_dir = {
        let c = CONFIG.get().unwrap();
        &c.data_dir
    };

    let Passphrase { key, code } = passphrase::create();

    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(&data.0, &nonce, &key);

    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(OFlag::O_TMPFILE.bits())
        .open(data_dir)?;

    file.write_all(nonce.as_ref())?;
    file.write_all(&ciphertext)?;

    let raw_fd_str = file.as_raw_fd().to_string();
    let tempfile_path = ["/proc/self/fd", &raw_fd_str].iter().collect::<PathBuf>();
    loop {
        let id = hex::encode(sodiumoxide::randombytes::randombytes(16));
        let perm_path = [data_dir, &id].iter().collect::<PathBuf>();

        let res = linkat(
            None,
            &tempfile_path,
            None,
            &perm_path,
            LinkatFlags::SymlinkFollow,
        );

        match res {
            Ok(()) => return Ok((id, code)),
            Err(Errno::EEXIST) => continue,
            Err(errno) => {
                return Err(Error::from(format!(
                    "unable to rename file, received error code {}",
                    errno
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        use http::StatusCode;
        match serialize_secret("") {
            Err(Error::WithStatusCode(StatusCode::BAD_REQUEST, _)) => (),
            _ => panic!(),
        }

        const SECRET: &str = "this is TOP SECRET";
        let serialized_data = serialize_secret(SECRET).unwrap();
        let chunk = Chunk::new(&serialized_data.0);
        assert_eq!(chunk.id(), STRING);
        let chunk_data = chunk.data();
        let res = std::str::from_utf8(chunk_data)
            .map(ToOwned::to_owned)
            .unwrap();
        assert_eq!(SECRET, res);

        // test file serialization
        match serialize_file_map(&[]) {
            Err(Error::WithStatusCode(StatusCode::BAD_REQUEST, _)) => (),
            _ => panic!(),
        }

        let file_map = [
            ("file1.txt".to_owned(), b"file 1 content".to_vec()),
            ("file2.txt".to_owned(), b"file 2 content".to_vec()),
        ];
        let serialized_data = serialize_file_map(&file_map).unwrap();
        let mut chunk = Chunk::new(&serialized_data.0);
        assert_eq!(chunk.id(), NAME);
        assert_eq!(chunk.data(), b"file1.txt");
        assert!(chunk.next());
        assert_eq!(chunk.id(), DATA);
        assert_eq!(chunk.data(), b"file 1 content");
        assert!(chunk.next());
        assert_eq!(chunk.id(), NAME);
        assert_eq!(chunk.data(), b"file2.txt");
        assert!(chunk.next());
        assert_eq!(chunk.id(), DATA);
        assert_eq!(chunk.data(), b"file 2 content");
        assert!(!chunk.next());
    }

    #[tokio::test]
    async fn test_store_retrieve() {
        crate::init().unwrap();

        const SECRET: &str = "this is TOP SECRET";
        let serialized_data = serialize_secret(SECRET).unwrap();
        let (id0, passphrase0) = write(&serialized_data).unwrap();
        let value = retrieve(&id0, &passphrase0).await.unwrap();
        if let Value::Secret(v) = value {
            assert_eq!(v, SECRET);
        } else {
            panic!()
        };

        match retrieve(&id0, &passphrase0).await {
            Err(Error::SecretNotFound) => (),
            Err(e) => panic!("unexpected error: {:?}", e),
            Ok(_) => panic!("value should have already been claimed"),
        }

        let file_map = [("file1.txt".to_owned(), b"file 1 content".to_vec())];
        let serialized_data = serialize_file_map(&file_map).unwrap();
        let (id1, passphrase1) = write(&serialized_data).unwrap();

        assert!(passphrase0 != passphrase1);
        assert!(id0 != id1);

        let value = retrieve(&id1, &passphrase1).await.unwrap();
        if let Value::File {
            name,
            data,
            content_type,
        } = value
        {
            assert_eq!(name, "file1.txt");
            assert_eq!(data, b"file 1 content");
            assert_eq!(content_type, "application/octet-stream");
        } else {
            panic!();
        }

        let file_map = [
            ("file1.txt".to_owned(), b"file 1 content".to_vec()),
            ("file2.txt".to_owned(), b"file 2 content".to_vec()),
        ];
        let serialized_data = serialize_file_map(&file_map).unwrap();
        let (id2, passphrase2) = write(&serialized_data).unwrap();

        assert!(passphrase1 != passphrase2);
        assert!(id1 != id2);

        let value = retrieve(&id2, &passphrase2).await.unwrap();
        if let Value::File {
            name,
            data,
            content_type,
        } = value
        {
            assert_eq!(name, "teleport.zip");
            let cursor = std::io::Cursor::new(&data);
            let mut zip = zip::ZipArchive::new(cursor).unwrap();
            assert_eq!(zip.len(), 2);

            {
                let mut file0 = zip.by_index(0).unwrap();
                assert_eq!(file0.name(), "file1.txt");

                let mut v0 = Vec::new();
                std::io::copy(&mut file0, &mut v0).unwrap();
                assert_eq!(&v0, b"file 1 content");
            }

            {
                let mut file1 = zip.by_index(1).unwrap();
                assert_eq!(file1.name(), "file2.txt");

                let mut v1 = Vec::new();
                std::io::copy(&mut file1, &mut v1).unwrap();
                assert_eq!(&v1, b"file 2 content");
            }

            assert_eq!(content_type, "application/zip");
        } else {
            panic!();
        }
    }
}

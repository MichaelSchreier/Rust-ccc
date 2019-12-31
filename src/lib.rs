extern crate fatfs;
extern crate fscommon;
extern crate openssl;
extern crate rand;
extern crate crc;

pub mod rustccc {
    use std::io::prelude::*;
    use std::io::Error;
    use fscommon::BufStream;
    use rand::rngs::OsRng;
    use rand::Rng;
    use crc::{crc32};

    /// Holds the reference to a an encrypted file container along with the container specifications
    pub struct ContainerFile {
        file: std::fs::File,          // Reference to the file on disk
        unlocked: bool,               // Indicates whether the file can be read from / written to
        volume_key: Option<[u8; 64]>, // Actual key for the encrypted file system in the container
        volume_size: Option<i64>,     // Size of the file system within the container file
        volume_offset: Option<i64>,   // Offset (in bytes) from the beginning of the container file
                                      // to when the file system begins
    }

    const BLOCK_SIZE: usize = 512;

    /// Takes a raw (plain text) password and derives a secure key (hash) to be used as an
    /// encryption key.
    fn strengthen(password: &[u8], salt: [u8; 64]) -> std::io::Result<[u8; 64]> {
        let mut buf: [u8; 64] = [0u8; 64];
        openssl::pkcs5::pbkdf2_hmac(
            password,
            &salt,
            500000,
            openssl::hash::MessageDigest::sha256(),
            &mut buf
        )?;
        Ok(buf)
    }

    impl ContainerFile {
        /// Opens an existing encrypted file in _locked_ state. File can be unlocked by using
        /// `<ContainerFile>.unlock(password)`, where `password` is the key that was used to encrypt
        /// the container.
        pub fn open(filename: &str) -> Result<ContainerFile, Error> {
            Ok(ContainerFile {
                file: std::fs::OpenOptions::new().read(true).write(true).open(filename)?,
                unlocked: false,
                volume_key: None,
                volume_size: None,
                volume_offset: None
            })
        }

        /// Creates the container header that describes various properties of the file system and
        /// its encryption.
        fn create_header(buf: &mut [u8; 131072], password: &[u8; 64], size: u64) -> Result<(), Error> {
            let mut rng = OsRng::new()?;
            rng.try_fill(&mut buf[0..64])?;  // Salt
            buf[64..68].copy_from_slice(&[86, 69, 82, 65]); // ASCII string "VERA"
            buf[68..70].copy_from_slice(&[0, 5]); // Volume header format version
            buf[70..72].copy_from_slice(&[1, 11]); //  Minimum program version required to open the volume

            // CRC32 calculated below
            buf[72..76].copy_from_slice(&[0, 0, 0, 0]); // CRC-32 checksum of the (decrypted) bytes 256-511

            buf[76..92].copy_from_slice(&[0; 16]); // Reserved (must contain zeroes)
            buf[92..100].copy_from_slice(&[0; 8]); // Size of hidden volume (set to zero in non-hidden volumes)
            buf[100..108].copy_from_slice(&size.to_be_bytes()); // Size of volume
            buf[108..116].copy_from_slice(&(131072 as i64).to_be_bytes()); // Byte offset of the start of the master key scope
            buf[116..124].copy_from_slice(&size.to_be_bytes()); // Size of the encrypted area within the master key scope
            buf[124..128].copy_from_slice(&[0, 0, 0, 0]); // Flag bits
            buf[128..132].copy_from_slice(&(BLOCK_SIZE as i32).to_be_bytes()); // Sector size (in bytes)
            buf[132..252].copy_from_slice(&[0; 120]); // Reserved (must contain zeroes)

            // CRC32 calculated below
            buf[252..256].copy_from_slice(&[0; 4]); // CRC-32 checksum of the (decrypted) bytes 64-251

            buf[256..320].copy_from_slice(password); // Concatenated primary and secondary master keys

            // calculate CRC32 here
            let mut checksum_buf = [0u8; 256];
            checksum_buf.copy_from_slice(&buf[256..512]);
            buf[72..76].copy_from_slice(&crc32::checksum_ieee(&checksum_buf).to_be_bytes()); // CRC-32 checksum of the (decrypted) bytes 256-511

            let mut checksum_buf = [0u8; 188];
            checksum_buf.copy_from_slice(&buf[64..252]);
            buf[252..256].copy_from_slice(&crc32::checksum_ieee(&checksum_buf).to_be_bytes()); // CRC-32 checksum of the (decrypted) bytes 64-251

            rng.try_fill(&mut buf[65536..131072])?; // Hidden volume header -- random data

            Ok(())
        }

        /// Receives a reference to a file, some content, encryption key and initialisation vector,
        /// encrypts and writes the content to the file.
        /// Returns the updated initialisation vector to be used in subsequent calls to
        /// `encrpt_and_write`.
        fn encrypt_and_write(
            mut file: &std::fs::File,
            buf: &[u8],
            key: &[u8; 64],
            mut iv: [u8; 16]
        ) -> Result<[u8; 16], Error> {
            let cipher = openssl::symm::Cipher::aes_256_xts();
            let mut bytes_encrypted: usize = 0;
            let mut chunk_size = BLOCK_SIZE;
            let buffer_length = buf.len();
            let start_iv_value = u128::from_le_bytes(iv) as usize;

            while bytes_encrypted < buffer_length {
                if buffer_length - bytes_encrypted < BLOCK_SIZE {
                    chunk_size = buffer_length - bytes_encrypted;
                }

                let encrypted_content = openssl::symm::encrypt(
                    cipher,
                    key,
                    Some(&iv),
                    &buf[bytes_encrypted..bytes_encrypted + chunk_size]
                )?;
                bytes_encrypted += chunk_size;

                file.write_all(&encrypted_content)?;

                // update iv
                iv = (((start_iv_value + bytes_encrypted) / BLOCK_SIZE) as u128).to_le_bytes();
            }

            Ok(iv)
        }

        /// Creates an encrypted container file and returns an instance of `<ContainerFile>` in
        /// _unlocked_ state.
        pub fn create(filename: &str, password: &str, size: usize) -> Result<ContainerFile, Error> {
            // create file
            let mut file = std::fs::File::create(filename)?;
            file.set_len(size as u64 + 2 * 131072)?;

            // define header parameters
            let mut primary_header = [0u8; 131072];
            let mut secondary_header = [0u8; 131072];
            let mut rng = OsRng::new()?;
            let mut volume_password = [0u8; 64];
            rng.try_fill(&mut volume_password)?;

            // create header and backup header
            ContainerFile::create_header(&mut primary_header, &volume_password, size as u64)?;
            ContainerFile::create_header(&mut secondary_header, &volume_password, size as u64)?;

            // and encrypt them
            let mut iv: [u8; 16] = [0u8; 16];
            let mut salt = [0u8; 64];
            salt.copy_from_slice(&primary_header[0..64]);
            let primary_header_key = strengthen(password.as_bytes(), salt)?;

            salt.copy_from_slice(&secondary_header[0..64]);
            let secondary_header_key = strengthen(password.as_bytes(), salt)?;

            // write primary header to file
            // salt first (unencrypted)
            file.write_all(&primary_header[0..64])?;
            // then content
            iv = ContainerFile::encrypt_and_write(
                &file,
                &primary_header[64..],
                &primary_header_key,
                iv
            )?;

            // write empty volume
            let content = [0u8; BLOCK_SIZE];
            for _i in 0..(size / BLOCK_SIZE) {
                iv = ContainerFile::encrypt_and_write(
                &file,
                &content,
                &volume_password,
                iv
                )?;
            }

            // write secondary (backup) header to file
            // salt first (unencrypted)
            file.write_all(&secondary_header[0..64])?;
            // then content
            ContainerFile::encrypt_and_write(
                &file,
                &secondary_header[64..],
                &secondary_header_key,
                iv
            )?;

            // make sure all of the above actually written to disk
            file.flush()?;

            // open the file and unlock it
            let mut created_file = ContainerFile::open(filename)?;
            created_file.unlock(password)?;

            // and create an empty partition in its file system section
            fatfs::format_volume(
                &mut created_file,
                fatfs::FormatVolumeOptions::new().bytes_per_cluster(2048)
            )?;

            Ok(created_file)
        }

        /// Lock an instance of `<ContainerFile>` so that it can no longer be read from and written
        /// to. Also removes any previously obtained decryption key from the struct.
        pub fn lock(&mut self) -> Result<(), Error> {
            self.unlocked = false;
            self.volume_key = None;

            Ok(())
        }

        /// Unlocks an instance of `<ContainerFile>` so that it can be read from and written to.
        pub fn unlock(&mut self, password: &str) -> Result<(), Error> {
            if ContainerFile::is_unlocked(&self) == true {
                return Ok(())
            }

            // define buffers
            let mut file_buffer = [0u8; 512];
            let mut salt = [0u8; 64];
            let iv = [0u8; 16];

            // read header into buffer
            self.file.seek(std::io::SeekFrom::Start(0))?;
            self.file.read(&mut file_buffer)?;
            // take salt
            &mut salt.copy_from_slice(&mut file_buffer[0..64]);

            // create hashed header password
            let header_password = strengthen(password.as_bytes(), salt)?;

            // define cipher
            let cipher = openssl::symm::Cipher::aes_256_xts();

            // decrypt header
            let decrypted_header = openssl::symm::decrypt(
                cipher,
                &header_password,
                Some(&iv),
                &file_buffer[64..]
            )?;

            // check if first four bytes == 'VERA' or 'TRUE'
            if &decrypted_header[0..4] != [86, 69, 82, 65]
                && &decrypted_header[0..4] != [84, 82, 85, 69] {
                return std::result::Result::Err(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Wrong password"
                    )
                );
            }

            // TODO: check CRC32 matches value in header

            // take volume attributes
            let mut i64_buffer = [0u8; 8];
            let mut volume_key = [0u8; 64];

            i64_buffer.copy_from_slice(&decrypted_header[36..44]);
            self.volume_size = Some(i64::from_be_bytes(i64_buffer));

            i64_buffer.copy_from_slice(&decrypted_header[44..52]);
            self.volume_offset = Some(i64::from_be_bytes(i64_buffer));

            volume_key.copy_from_slice(&decrypted_header[192..256]);
            self.volume_key = Some(volume_key);

            // set file position to beginning of volume
            if let Some(offset) = self.volume_offset {
                self.file.seek(std::io::SeekFrom::Start(offset as u64))?;
            }

            // set unlocked
            self.unlocked = true;

            Ok(())
        }

        /// Check whether an instance of `<ContainerFile>` is unlocked.
        pub fn is_unlocked(&self) -> bool {
            if !self.unlocked {
                return false
            }
            return true
        }

        /// Applied to an _unlocked_ instance of `<ContainerFile>` this provides a file system
        /// reference to the volume in the container. This allows higher level access to read and
        /// write files.
        pub fn mount(self) -> Result<fatfs::FileSystem<BufStream<ContainerFile>>, std::io::Error> {
            let buf_stream = fscommon::BufStream::new(self);
            let file_system = fatfs::FileSystem::new(
                buf_stream,
                fatfs::FsOptions::new()
            )?;
            Ok(file_system)
        }
    }

    /// Reimplementation of read, write & seek io functions to work with instances of
    /// `<ContainerFile>`.
    impl std::io::Read for ContainerFile {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            // verify if file is unlocked
            if !self.unlocked {
                return std::result::Result::Err(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Container locked!"
                    )
                );
            }

            // read from volume considering offset in file and encryption; 512 bytes blocks
            let len_buf = buf.len();
            let mut tmp_buf = [0u8; BLOCK_SIZE];

            // define some cryptographic helpers
            let cipher = openssl::symm::Cipher::aes_256_xts();
            let mut iv: [u8; 16];
            let mut volume_key = [0u8; 64];
            if let Some(key) = self.volume_key {
                volume_key.copy_from_slice(&key);
            }

            // determine correct starting byte to read from
            let starting_pos = self.seek(std::io::SeekFrom::Current(0))?;
            let mut bytes_to_shift: i64 = 0;
            if starting_pos % BLOCK_SIZE as u64 != 0 {
                bytes_to_shift = (starting_pos % BLOCK_SIZE as u64) as i64; // current_pos as i64 - 512;
                self.seek(std::io::SeekFrom::Current(-bytes_to_shift))?;
            }

            // define some buffers, offsets and counters
            let mut segment_size = BLOCK_SIZE;
            let mut remaining_bytes = len_buf;
            let mut bytes_written = len_buf - remaining_bytes;
            let mut segment_offset = bytes_to_shift as usize;
            let mut bytes_read: usize;

            // read blocks of `BLOCK_SIZE` from the file, taking into account the block structure
            // of the encryption cipher
            while remaining_bytes > 0 {
                if remaining_bytes >= BLOCK_SIZE {
                    segment_size =  BLOCK_SIZE - segment_offset;
                } else if remaining_bytes + segment_offset <= BLOCK_SIZE {
                    segment_size = remaining_bytes;
                } else {
                    segment_size = BLOCK_SIZE - segment_offset;
                }

                // update initialisation vector
                iv = (self.seek(std::io::SeekFrom::Current(0))? as u128 / BLOCK_SIZE as u128 + 256).to_le_bytes();

                // read in the current block (encrypted)
                bytes_read = self.file.read(&mut tmp_buf)?;

                // decrypt the block
                let tmp_buf_decrypted = openssl::symm::decrypt(
                    cipher,
                    &volume_key,
                    Some(&iv),
                    &tmp_buf
                )?;

                // copy to buffer
                remaining_bytes -= segment_size;
                if bytes_read < segment_size {
                    segment_size = bytes_read;
                }

                // append whatever amount of bytes was read
                buf[bytes_written..bytes_written + segment_size].copy_from_slice(
                    &tmp_buf_decrypted[segment_offset as usize..segment_offset as usize + segment_size]
                );

                // keep track how many bytes have been read
                bytes_written += segment_size;
                segment_offset = 0;
            }

            // correct bytes read and seek position in case segment size wasn't BLOCK_SIZE
            if segment_size != BLOCK_SIZE {
                let correction: i64 = (starting_pos + bytes_written as u64) as i64 % BLOCK_SIZE as i64 - BLOCK_SIZE as i64;
                self.seek(std::io::SeekFrom::Current(correction))?;
            }

            Ok(bytes_written)
        }
    }

    impl std::io::Seek for ContainerFile {
        fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64, Error> {
            // verify if file is unlocked
            if !self.unlocked {
                return std::result::Result::Err(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Container locked!"
                    )
                );
            }

            // seek inner
            let mut result: u64 = 0;
            if let std::io::SeekFrom::Current(n) = pos {
                result = self.file.seek(std::io::SeekFrom::Current(n))?;
            } else if let std::io::SeekFrom::Start(n) = pos {
                if let Some(offset) = self.volume_offset {
                    result = self.file.seek(std::io::SeekFrom::Start(n + offset as u64))?;
                }
            } else if let std::io::SeekFrom::End(n) = pos {
                if let Some(offset) = self.volume_offset {
                    result = self.file.seek(std::io::SeekFrom::End(n - offset))?;
                }
            }

            let mut volume_size: i64 = 0;
            if let Some(value) = self.volume_size {
                volume_size = value;
            }

            match self.volume_offset {
                Some(offset) => {
                    // throw error if past end of file ...
                    if result as i64 - offset > volume_size {
                        return std::result::Result::Err(
                            std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Seek returned a position beyond the end of the encrypted volume"
                            )
                        )
                    } else if result as i64 - offset < 0 { // ... or before the encrypted volume starts
                        return std::result::Result::Err(
                            std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Seek returned a position before the beginning of the encrypted volume"
                            )
                        )
                    }
                    Ok((result as i64 - offset) as u64)
                },
                None => return std::result::Result::Err(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Container locked!"
                    )
                )
            }
        }
    }

    impl std::io::Write for ContainerFile {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
            // verify if file is unlocked
            if !self.unlocked {
                return std::result::Result::Err(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Container locked!"
                    )
                );
            }

            let len_buf = buf.len();
            let mut block_buffer = [0u8; BLOCK_SIZE];

            // determine correct starting byte to read from
            let starting_pos = self.seek(std::io::SeekFrom::Current(0))?;
            let mut bytes_to_shift: i64 = 0;
            if starting_pos % BLOCK_SIZE as u64 != 0 {
                bytes_to_shift = (starting_pos % BLOCK_SIZE as u64) as i64;
                self.seek(std::io::SeekFrom::Current(-bytes_to_shift))?;
            }

            // define some buffers, offsets and counters
            let mut segment_size = BLOCK_SIZE;
            let mut remaining_bytes = len_buf;
            let mut bytes_written = len_buf - remaining_bytes;
            let mut segment_offset = bytes_to_shift as usize;
            let mut bytes_read: usize;

            // define some cryptographic  helpers
            let cipher = openssl::symm::Cipher::aes_256_xts();
            let mut iv: [u8; 16];
            let mut volume_key = [0u8; 64];
            if let Some(key) = self.volume_key {
                volume_key.copy_from_slice(&key);
            }

            // write blocks of `BLOCK_SIZE` until the buffer is filled
            while remaining_bytes > 0 {
                // read block into temporary buffer
                bytes_read = self.read(&mut block_buffer)?;
                // reset position to start of block - we read in the block first (decrypted), append
                // our content, encrypt it and write it back
                self.seek(std::io::SeekFrom::Current(-512))?;

                if remaining_bytes >= BLOCK_SIZE {
                    segment_size =  BLOCK_SIZE - segment_offset;
                } else if remaining_bytes + segment_offset <= BLOCK_SIZE {
                    segment_size = remaining_bytes;
                } else {
                    segment_size = BLOCK_SIZE - segment_offset;
                }

                // correct how many bytes still have to be written
                remaining_bytes -= segment_size;

                // ensure the right amount of bytes is copied into the temporary buffer
                if bytes_read < segment_size {
                    segment_size = bytes_read;
                }
                block_buffer[segment_offset..segment_offset + segment_size]
                    .copy_from_slice(&buf[bytes_written..bytes_written + segment_size]);
                // keep track of bytes written
                bytes_written += segment_size;
                segment_offset = 0;

                // update initialisation vector
                iv = (self.seek(std::io::SeekFrom::Current(0))? as u128 / BLOCK_SIZE as u128 + 256).to_le_bytes();

                // (re-)encrypt temporary buffer
                let tmp_buf_encrypted = openssl::symm::encrypt(
                    cipher,
                    &volume_key,
                    Some(&iv),
                    &block_buffer
                )?;

                // write back to file
                self.file.write(&tmp_buf_encrypted)?;
            }

            // correct bytes read and seek position in case segment size wasn't 512
            if segment_size != BLOCK_SIZE {
                let correction: i64 = (starting_pos + bytes_written as u64) as i64 % BLOCK_SIZE as i64 - BLOCK_SIZE as i64;
                self.seek(std::io::SeekFrom::Current(correction))?;
            }

            Ok(bytes_written)
        }

        fn flush(&mut self) -> Result<(), Error> {
            self.file.flush()?;
            Ok(())
        }
    }
}

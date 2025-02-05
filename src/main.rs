use anyhow::{Result, bail};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::Aead;
use dialoguer::{Select, Password, Input};
use sha2::{Digest, Sha512};

fn main() -> Result<()> {
    main_menu()?;
    Ok(())
}

fn main_menu() -> Result<()> {
    let items = ["Encrypt", "Decrypt", "Quit"];
    loop {
        let selection = Select::new()
            .with_prompt("\nWhat do you want to do?")
            .items(&items)
            .default(0)
            .interact().unwrap_or(items.len());
        match selection {
            0 => encrypt()?,
            1 => decrypt()?,
            2 => break,
            _ => break,
        }
    }
    Ok(())
}

/// Ask the user for the phrase they want to encrypt and the password they want
/// to use as the key for encryption.
fn encrypt() -> Result<()> {
    // get phrase from user
    let phrase: String = Input::new()
        .with_prompt("Enter phrase")
        .interact_text()?;

    // get password from user
    let password = get_password()?;  // TODO: consider using something like `secmem` to zero out the memory

    // create KeyAndNonce from password
    let kn = KeyAndNonce::new(password.as_bytes());

    // encrypt phrase using KeyAndNonce
    let result = do_encrypt(&kn, phrase.as_bytes())?;

    println!("Encrypted phrase (hex): {}", result);

    Ok(())
}

/// Use the given key and nonce to encrypt the given phrase.
fn do_encrypt(kn: &KeyAndNonce, phrase: &[u8]) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(&kn.key);
    match cipher.encrypt(&kn.nonce, phrase) {
        Ok(result) => Ok(hex::encode(result)),
        Err(e) => bail!("{}", e),
    }
}

/// Asks the user for the encrypted phrase (in hex) and the password used as the
/// key for encryption and decrypts the phrase.
fn decrypt() -> Result<()> {
    // get encrypted phrase from user
    let input: String = Input::new()
        .with_prompt("Enter encrypted phrase (hex)")
        .interact_text()?;

    // get password from user
    let password = get_password()?;

    // create KeyAndNonce from password
    let kn = KeyAndNonce::new(password.as_bytes());

    // decrypt encrypted phrase using KeyAndNonce
    let phrase = do_decrypt(&kn, input.as_bytes())?;

    println!("Decrypted phrase: \"{}\"", phrase);

    Ok(())
}

/// Use the given key and nonce to decrypt the given ciphertext (in hex).
fn do_decrypt(kn: &KeyAndNonce, hex_ciphertext: &[u8]) -> Result<String> {
    let ciphertext = hex::decode(hex_ciphertext)?;
    let cipher = ChaCha20Poly1305::new(&kn.key);
    match cipher.decrypt(&kn.nonce, ciphertext.as_ref()) {
        Ok(result) => Ok(String::from_utf8(result)?),
        Err(e) => bail!("{}", e),
    }
}

/// Asks the user for a password while hiding the input from the terminal and
/// requires them to confirm that password.
fn get_password() -> std::io::Result<String> {
    Password::new()
        .with_prompt("Enter password")
        .with_confirmation("Confirm password", "Password did not match, try again")
        .interact()
}

#[derive(Debug)]
struct KeyAndNonce {
    pub key: Key,
    pub nonce: Nonce,
}

// TODO: consider using `generate_key` or `generate_nonce` or salting the password
impl KeyAndNonce {
    /// Creates a Key and Nonce from the given password in the following way:
    /// 1) Hash the password with SHA512
    /// 2) Use the password length as the starting offset in the SHA512 for the Key
    /// 3) From the starting offset take 32 bytes from the SHA512 (wrap around if necessary)
    /// 4) Use the length of the Key (32) as the starting offset in the SHA512 for the Nonce
    /// 5) From the starting offset take 12 bytes from the SHA512 (wrap around if necessary)
    fn new(password: &[u8]) -> Self {
        let hash = sha512(password); // 64-byte hashed password
        let key = { // 32-bytes
            const LEN: usize = 32;
            let mut k: Vec<u8> = Vec::new();
            let start = password.len().rem_euclid(hash.len());
            if start + LEN > hash.len() {
                let front = &hash[start..];
                let back = &hash[0..LEN-front.len()];
                k.extend_from_slice(front);
                k.extend_from_slice(back);
            } else {
                k.extend_from_slice(&hash[start..start+LEN]);
            }
            *Key::from_slice(&k)
        };
        let nonce = { // 12-bytes
            const LEN: usize = 12;
            let mut n: Vec<u8> = Vec::new();
            let start = key.len().rem_euclid(hash.len());
            if start + LEN > hash.len() {
                let front = &hash[start..];
                let back = &hash[0..LEN-front.len()];
                n.extend_from_slice(front);
                n.extend_from_slice(back);
            } else {
                n.extend_from_slice(&hash[start..start+LEN]);
            }
            *Nonce::from_slice(&n)
        };
        Self {
            key,
            nonce,
        }
    }
}

/// Hashes the given content to SHA512.
fn sha512(content: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(content);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use hex;
    use super::*;

    #[test]
    fn sha_512() {
        let contents = ["password", "passsword", "a", "b", "$(0kfjweSif,@f==", ""];
        let expected = [ // hex
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
            "e7b87c3edeb70d135368fa6e1afc997961ab9186c310e20e9d3e89fdbbda3b8a6d715274187a1ab8a502a7373b6427e40589f01874d36ddbfc53e86334d3927e",
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
            "5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da",
            "125a19e9fc614399e293de3881cb34f6e1303ac4e8367c2dc0d6bb887371b6a5e5a88887b5b82d45d420aade6d2752fb68f6d3911584152c702dfb0b5c1023a6",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ];
        for i in 0..expected.len() {
            let hash = sha512(contents[i].as_bytes());
            assert_eq!(expected[i], hex::encode(hash), "index: {}", i);
        }
    }

    #[test]
    fn key_and_nonce_creation() {
        let passwords = ["password", "passsword", "a", "b", "$(0kfjweSif,@f==", ""];
        let keys = [ // hex
            "2441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec",
            "68fa6e1afc997961ab9186c310e20e9d3e89fdbbda3b8a6d715274187a1ab8a5",
            "40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302",
            "67768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5",
            "e1303ac4e8367c2dc0d6bb887371b6a5e5a88887b5b82d45d420aade6d2752fb",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
        ];
        let nonces = [ // hex
            "80b1d7785e5976ec049b46df",
            "6d715274187a1ab8a502a737",
            "02860c652bf08d560252aa5e",
            "b5ef7b18d1ff41c59370efb0",
            "e5a88887b5b82d45d420aade",
            "47d0d13c5d85f2b0ff8318d2",
        ];
        for i in 0..passwords.len() {
            let kn = KeyAndNonce::new(passwords[i].as_bytes());
            assert_eq!(hex::decode(keys[i]).unwrap(), kn.key.to_vec(), "key index: {}", i);
            assert_eq!(hex::decode(nonces[i]).unwrap(), kn.nonce.to_vec(), "nonce index: {}", i);
        }
    }

    #[test]
    fn encrypt_decrypt() -> Result<()> {
        let kn = KeyAndNonce::new("g@id0-$%==2@gg_".as_bytes());
        let phrases = ["a b c", "1 2 3", "this is cool", "zooce"];
        let ciphertexts = [ // hex
            "fff286ebc793136fdf888f68bf2dc2305c83946ccb",
            "aff2d6eb97b87309e33129b13d254f7da88d5ff0f7",
            "eaba8db8841cd533def9ae1520de6fadc11200ec46ef096530d28c62",
            "e4bd8ba8c1e135e85b214d74043e26d40cfad3b2a5",
        ];
        for i in 0..phrases.len() {
            let ciphertext = do_encrypt(&kn, phrases[i].as_bytes())?;
            assert_eq!(ciphertexts[i], ciphertext, "ciphertext index {}", i);
            let phrase = do_decrypt(&kn, ciphertexts[i].as_bytes())?;
            assert_eq!(phrases[i], phrase, "phrase index {}", i);
        }
        Ok(())
    }
}

#![allow(missing_docs)]
//! A sender's side of the AirPlay 2 wire, written apart from the library's (its TLV8 and its encrypted
//! channel): the integration tests check the server against an independent implementation, not against its own.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

/// TLV8 tags the tests use (HAP).
#[derive(Clone, Copy)]
pub enum TlvType {
    Method = 0,
    Identifier = 1,
    Salt = 2,
    PublicKey = 3,
    Proof = 4,
    EncryptedData = 5,
    Error = 7,
    State = 6,
    Signature = 10,
    Flags = 19,
}

/// A TLV8 message: values longer than 255 bytes go as consecutive items of the same tag.
#[derive(Default)]
pub struct TlvValues(Vec<(u8, Vec<u8>)>);

impl TlvValues {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, tag: u8, value: &[u8]) {
        self.0.push((tag, value.to_vec()));
    }

    pub fn get_type(&self, tag: TlvType) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(t, _)| *t == tag as u8)
            .map(|(_, v)| v.as_slice())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in &self.0 {
            let mut chunks = value.chunks(255).peekable();
            if chunks.peek().is_none() {
                out.extend_from_slice(&[*tag, 0]);
            }
            for chunk in chunks {
                out.push(*tag);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut rest = data;
        let mut last_full = false;
        while let [tag, len, tail @ ..] = rest {
            let value = tail.get(..usize::from(*len))?;
            match items.last_mut() {
                Some((t, v)) if *t == *tag && last_full => v.extend_from_slice(value),
                _ => items.push((*tag, value.to_vec())),
            }
            last_full = *len == 255;
            rest = &tail[usize::from(*len)..];
        }
        rest.is_empty().then_some(Self(items))
    }
}

/// One direction of HAP's encrypted framing: frames of at most 1024 bytes, a 2-byte little-endian length as the
/// additional data, ChaCha20-Poly1305 with the nonce `[0; 4] || counter as u64 little-endian`.
pub struct Cipher {
    key: [u8; 32],
    counter: u64,
}

impl Cipher {
    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        n
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for frame in plain.chunks(1024) {
            let aad = (frame.len() as u16).to_le_bytes();
            let nonce = self.nonce();
            let sealed = ChaCha20Poly1305::new((&self.key).into())
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: frame,
                        aad: &aad,
                    },
                )
                .ok()?;
            out.extend_from_slice(&aad);
            out.extend_from_slice(&sealed);
        }
        Some(out)
    }

    /// The plaintext of the whole frames in `data`, and the bytes they took.
    pub fn decrypt(&mut self, data: &[u8]) -> Option<(Vec<u8>, usize)> {
        let (mut plain, mut pos) = (Vec::new(), 0);
        while let Some(&[a, b]) = data.get(pos..pos + 2) {
            let end = pos + 2 + usize::from(u16::from_le_bytes([a, b])) + 16;
            let Some(sealed) = data.get(pos + 2..end) else {
                break;
            };
            let nonce = self.nonce();
            let opened = ChaCha20Poly1305::new((&self.key).into())
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: sealed,
                        aad: &[a, b],
                    },
                )
                .ok()?;
            plain.extend_from_slice(&opened);
            pos = end;
        }
        Some((plain, pos))
    }
}

/// The controller's side of an encrypted channel (HKDF-SHA512 of the pairing's shared secret).
pub struct EncryptedChannel {
    pub encrypt_ctx: Cipher,
    pub decrypt_ctx: Cipher,
}

impl EncryptedChannel {
    pub fn new(
        secret: &[u8],
        write_salt: &str,
        write_info: &str,
        read_salt: &str,
        read_info: &str,
    ) -> Option<Self> {
        let key = |salt: &str, info: &str| {
            let mut k = [0u8; 32];
            hkdf::Hkdf::<sha2::Sha512>::new(Some(salt.as_bytes()), secret)
                .expand(info.as_bytes(), &mut k)
                .ok()
                .map(|()| Cipher { key: k, counter: 0 })
        };
        Some(Self {
            encrypt_ctx: key(write_salt, write_info)?,
            decrypt_ctx: key(read_salt, read_info)?,
        })
    }
}

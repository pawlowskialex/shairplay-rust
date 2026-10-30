//! Cryptographic primitives for AirPlay authentication and encryption.

pub mod aes;
pub mod fairplay;
mod fairplay_garble;
mod fairplay_tables;
pub mod pairing;
pub mod rsa;

#[cfg(feature = "ap2-core")]
pub mod chacha_transport;
#[cfg(feature = "ap2-core")]
mod mont;
#[cfg(feature = "ap2-core")]
pub mod pairing_homekit;
#[cfg(feature = "ap2-core")]
pub mod tlv;
#[cfg(feature = "video")]
pub mod video_cipher;
#[cfg(feature = "video")]
pub mod video_key;

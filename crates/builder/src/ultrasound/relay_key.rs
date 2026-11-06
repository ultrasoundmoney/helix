//! The relay signing key, held encrypted on disk and decrypted in memory when
//! an operator posts the KEK. Replaces upstream's plaintext `RELAY_KEY`.
//!
//! The blob is what `private-key-ceremony`'s `encrypt-payment-key` writes:
//! `nonce[12] || ct_and_tag`, AES-256-GCM, plaintext the raw 32-byte secret.
//! 1Password holds the KEK, sharded 2-of-3.
//!
//! Nothing merges until the key arrives: `main` waits on [`LockedKey::unlock`]
//! before the merging spine starts, so a keyless builder is one the relay
//! simply cannot connect to.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use alloy_primitives::{Address, hex};
use alloy_signer_local::PrivateKeySigner;
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use eyre::WrapErr;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

const CIPHERTEXT_ENV: &str = "RELAY_KEY_CIPHERTEXT";
const SIGNER_ADDRESS_ENV: &str = "RELAY_SIGNER_ADDRESS";
const DECRYPT_LISTEN_ADDR_ENV: &str = "DECRYPT_LISTEN_ADDR";
const DEFAULT_DECRYPT_LISTEN_ADDR: &str = "0.0.0.0:8647";

/// The KEK is 32 bytes, so 64 hex chars. 4 KiB is room to spare.
const MAX_BODY_BYTES: usize = 4096;
const KEK_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(180);

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("kek must be 32 bytes of hex")]
    InvalidKek,
    #[error("ciphertext is shorter than a nonce")]
    Truncated,
    #[error("decryption failed; wrong kek or corrupt ciphertext")]
    Failed,
    #[error("decrypted {got} bytes, expected 32")]
    WrongSecretLength { got: usize },
    #[error("decrypted key is not a valid secp256k1 scalar")]
    InvalidSecret,
    #[error("decrypted key derives to {got}, expected {expected}")]
    AddressMismatch { expected: Address, got: Address },
}

/// Everything needed to decrypt the key, read before the node boots so a
/// missing setting fails at startup rather than once the node has synced.
pub struct LockedKey {
    ciphertext: Vec<u8>,
    expected: Address,
    listen_addr: SocketAddr,
}

impl LockedKey {
    pub fn from_env() -> eyre::Result<Self> {
        let path = required_env(CIPHERTEXT_ENV)?;
        let ciphertext = std::fs::read(&path)
            .wrap_err_with(|| format!("failed to read the encrypted relay key at {path}"))?;

        let expected = required_env(SIGNER_ADDRESS_ENV)?
            .parse()
            .wrap_err_with(|| format!("{SIGNER_ADDRESS_ENV} is not an address"))?;

        let listen_addr = std::env::var(DECRYPT_LISTEN_ADDR_ENV)
            .unwrap_or_else(|_| DEFAULT_DECRYPT_LISTEN_ADDR.to_owned())
            .parse()
            .wrap_err_with(|| format!("{DECRYPT_LISTEN_ADDR_ENV} is not a socket address"))?;

        Ok(Self { ciphertext, expected, listen_addr })
    }

    pub async fn unlock(self) -> eyre::Result<PrivateKeySigner> {
        serve_until_decrypted(self.listen_addr, self.ciphertext, self.expected).await
    }
}

fn required_env(name: &str) -> eyre::Result<String> {
    std::env::var(name).wrap_err_with(|| format!("{name} must be set"))
}

/// Decrypts `ciphertext` under `kek_body` and checks the result is the
/// expected account. The address check is what makes a wrong-but-valid
/// ciphertext loud: without it the mistake surfaces only when a collateral
/// Safe rejects the signature mid-slot.
pub fn decrypt(
    ciphertext: &[u8],
    kek_body: &[u8],
    expected: Address,
) -> Result<PrivateKeySigner, DecryptError> {
    let kek = parse_kek(kek_body)?;

    if ciphertext.len() <= NONCE_LEN {
        return Err(DecryptError::Truncated);
    }
    let (nonce, sealed) = ciphertext.split_at(NONCE_LEN);

    let secret = Zeroizing::new(
        Aes256Gcm::new((&*kek).into())
            .decrypt(Nonce::from_slice(nonce), sealed)
            .map_err(|_| DecryptError::Failed)?,
    );

    if secret.len() != KEK_LEN {
        return Err(DecryptError::WrongSecretLength { got: secret.len() });
    }

    let signer = PrivateKeySigner::from_slice(&secret).map_err(|_| DecryptError::InvalidSecret)?;

    if signer.address() != expected {
        return Err(DecryptError::AddressMismatch { expected, got: signer.address() });
    }

    Ok(signer)
}

fn parse_kek(body: &[u8]) -> Result<Zeroizing<[u8; KEK_LEN]>, DecryptError> {
    let text = std::str::from_utf8(body).map_err(|_| DecryptError::InvalidKek)?;
    let trimmed = text.trim();
    let raw = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    let decoded = Zeroizing::new(hex::decode(raw).map_err(|_| DecryptError::InvalidKek)?);
    let bytes: [u8; KEK_LEN] =
        decoded.as_slice().try_into().map_err(|_| DecryptError::InvalidKek)?;

    Ok(Zeroizing::new(bytes))
}

struct DecryptState {
    ciphertext: Vec<u8>,
    expected: Address,
    decrypted: mpsc::Sender<PrivateKeySigner>,
}

/// Serves `POST /decrypt` and returns once a valid KEK arrives. The listener
/// stays up afterwards, answering later attempts with 409, so an operator who
/// retries gets a clear answer rather than a refused connection.
async fn serve_until_decrypted(
    listen_addr: SocketAddr,
    ciphertext: Vec<u8>,
    expected: Address,
) -> eyre::Result<PrivateKeySigner> {
    let (decrypted, mut arrived) = mpsc::channel(1);
    let state = Arc::new(DecryptState { ciphertext, expected, decrypted });

    let app = Router::new()
        .route("/decrypt", post(handler))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .wrap_err_with(|| format!("failed to bind the decrypt listener on {listen_addr}"))?;

    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            error!(%error, "decrypt listener stopped");
        }
    });

    info!(%listen_addr, %expected, "waiting for the kek; not merging until it arrives");

    let received = tokio::select! {
        received = arrived.recv() => received,
        () = heartbeat() => None,
    };

    received.ok_or_else(|| eyre::eyre!("decrypt listener stopped before a kek arrived"))
}

/// A node stuck here is silent otherwise: it syncs, serves nothing, and looks
/// healthy. Loops until the caller drops it.
async fn heartbeat() {
    let mut waited = Duration::ZERO;
    loop {
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        waited += HEARTBEAT_INTERVAL;
        error!(
            waited_seconds = waited.as_secs(),
            "still waiting for the kek; this node is not merging"
        );
    }
}

async fn handler(
    State(state): State<Arc<DecryptState>>,
    body: axum::body::Bytes,
) -> (StatusCode, &'static str) {
    match decrypt(&state.ciphertext, &body, state.expected) {
        Ok(signer) => match state.decrypted.try_send(signer) {
            Ok(()) => {
                info!("relay signer installed");
                (StatusCode::OK, "decrypted")
            }
            Err(_) => (StatusCode::CONFLICT, "already decrypted"),
        },
        Err(error) => {
            // The address mismatch names both accounts, which is public
            // information and the whole point of the check.
            warn!(%error, "decrypt attempt failed");
            (StatusCode::BAD_REQUEST, "decrypt failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEK: [u8; KEK_LEN] = [7; KEK_LEN];
    const SECRET: [u8; 32] = [42; 32];
    const NONCE: [u8; NONCE_LEN] = [9; NONCE_LEN];

    /// The ceremony's layout: `nonce || ct_and_tag`.
    fn seal(secret: &[u8]) -> Vec<u8> {
        let sealed = Aes256Gcm::new((&KEK).into()).encrypt(Nonce::from_slice(&NONCE), secret);
        [NONCE.as_slice(), &sealed.unwrap()].concat()
    }

    fn expected() -> Address {
        PrivateKeySigner::from_slice(&SECRET).unwrap().address()
    }

    #[test]
    fn decrypts_the_ceremony_blob() {
        let body = format!("0x{}\n", hex::encode(KEK));
        let signer = decrypt(&seal(&SECRET), body.as_bytes(), expected()).unwrap();
        assert_eq!(signer.address(), expected());
    }

    #[test]
    fn rejects_a_wrong_kek() {
        let body = hex::encode([8; KEK_LEN]);
        let error = decrypt(&seal(&SECRET), body.as_bytes(), expected()).unwrap_err();
        assert!(matches!(error, DecryptError::Failed));
    }

    #[test]
    fn rejects_a_key_for_another_account() {
        let body = hex::encode(KEK);
        let error = decrypt(&seal(&SECRET), body.as_bytes(), Address::ZERO).unwrap_err();
        assert!(matches!(error, DecryptError::AddressMismatch { .. }));
    }

    #[test]
    fn rejects_malformed_input() {
        let short_kek = hex::encode([7; 16]);
        assert!(matches!(
            decrypt(&seal(&SECRET), short_kek.as_bytes(), expected()),
            Err(DecryptError::InvalidKek)
        ));

        let body = hex::encode(KEK);
        assert!(matches!(
            decrypt(&NONCE, body.as_bytes(), expected()),
            Err(DecryptError::Truncated)
        ));
        assert!(matches!(
            decrypt(&seal(&[42; 31]), body.as_bytes(), expected()),
            Err(DecryptError::WrongSecretLength { got: 31 })
        ));
    }
}

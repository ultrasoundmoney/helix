use std::{sync::Arc, time::Duration};

use crossbeam_channel::Sender;
use rustc_hash::FxHashSet;
use tracing::{info, warn};

use crate::engine::{EngineEvent, convert::eaddr};

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

const STARTUP_ATTEMPTS: u32 = 5;
const STARTUP_RETRY_DELAY: Duration = Duration::from_secs(2);

pub type DisallowSet = Arc<FxHashSet<ethrex_common::Address>>;

type FetchError = Box<dyn std::error::Error + Send + Sync>;

/// Fetches and parses the list (json array of address strings) from `url`.
pub async fn fetch(client: &reqwest::Client, url: &str) -> Result<DisallowSet, FetchError> {
    let body = client.get(url).send().await?.error_for_status()?.text().await?;
    let addresses: Vec<alloy_primitives::Address> = serde_json::from_str(&body)?;
    Ok(Arc::new(addresses.into_iter().map(eaddr).collect()))
}

/// Loads the list at startup, then exits the process if it cannot be read: a
/// builder that merges for an OFAC proposer without its sanctions list would
/// fail open, and a block it appends to would be rejected at get_payload
/// anyway.
pub async fn fetch_or_exit(url: &str) -> DisallowSet {
    let client = reqwest::Client::new();
    for attempt in 1..=STARTUP_ATTEMPTS {
        match fetch(&client, url).await {
            Ok(disallow) => {
                info!(count = disallow.len(), %url, "loaded disallow list");
                return disallow;
            }
            Err(error) => {
                warn!(attempt, %url, %error, "failed to fetch disallow list at startup");
                tokio::time::sleep(STARTUP_RETRY_DELAY).await;
            }
        }
    }
    panic!(
        "could not fetch disallow list from {url} after {STARTUP_ATTEMPTS} attempts; refusing to start"
    );
}

/// Re-fetches on an interval, pushing each successful read into the engine. A
/// failed refresh leaves the engine on the list it already holds.
pub fn spawn_refresh(url: String, events: Sender<EngineEvent>) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match fetch(&client, &url).await {
                Ok(disallow) => {
                    if events.send(EngineEvent::Disallow(disallow)).is_err() {
                        break;
                    }
                }
                Err(error) => warn!(%url, %error, "failed to refresh disallow list"),
            }
        }
    });
}

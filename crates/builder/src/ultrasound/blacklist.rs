//! Upstream refreshes the blacklist in the background and, until its first
//! fetch succeeds, merges for filtering proposers with an empty list. That
//! fails open, so the builder refuses to start until the list has loaded once.

use std::time::Duration;

use alloy_primitives::Address;
use dashmap::DashSet;
use helix_common::blacklist::DisallowListPayload;
use tracing::{info, warn};

use crate::validation::server::refresh_disallow;

const STARTUP_ATTEMPTS: u32 = 5;
const STARTUP_RETRY_DELAY: Duration = Duration::from_secs(2);

pub async fn load_or_fail(endpoint: &str, disallow: &DashSet<Address>) -> eyre::Result<()> {
    let client = reqwest::Client::new();

    for attempt in 1..=STARTUP_ATTEMPTS {
        match fetch(&client, endpoint).await {
            Ok(payload) => {
                refresh_disallow(disallow, payload);
                info!(%endpoint, size = disallow.len(), "loaded disallow list");
                return Ok(());
            }
            Err(error) => {
                warn!(attempt, %endpoint, %error, "failed to fetch disallow list at startup");
            }
        }

        if attempt < STARTUP_ATTEMPTS {
            tokio::time::sleep(STARTUP_RETRY_DELAY).await;
        }
    }

    eyre::bail!(
        "could not load the disallow list from {endpoint} after {STARTUP_ATTEMPTS} attempts; refusing to start"
    )
}

async fn fetch(client: &reqwest::Client, endpoint: &str) -> eyre::Result<DisallowListPayload> {
    Ok(client.get(endpoint).send().await?.error_for_status()?.json().await?)
}

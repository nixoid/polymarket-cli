//! Polymarket Relayer client for deposit-wallet (`poly1271`) on-chain calls.
//!
//! Submits EIP-712 signed `WALLET` batches to `relayer-v2.polymarket.com` so CTF
//! redeem/split/merge execute as `POLYMARKET_FUNDER`, not the EOA.

use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::{Context, Result, bail};
use polymarket_client_sdk_v2::POLYGON;
use polymarket_client_sdk_v2::auth::Signer;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth;

const DEFAULT_RELAYER_URL: &str = "https://relayer-v2.polymarket.com";
const DEPOSIT_WALLET_FACTORY: &str = "0x00000000000Fb5C9ADea0298D729A0CB3823Cc07";
const DOMAIN_NAME: &str = "DepositWallet";
const DOMAIN_VERSION: &str = "1";
const DEADLINE_SECS: u64 = 240;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize)]
struct NonceResponse {
    nonce: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitResponse {
    transaction_id: String,
    #[allow(dead_code)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayerTx {
    state: Option<String>,
    transaction_hash: Option<String>,
}

fn relayer_url() -> String {
    std::env::var("POLYMARKET_RELAYER_URL")
        .or_else(|_| std::env::var("RELAYER_URL"))
        .unwrap_or_else(|_| DEFAULT_RELAYER_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn relayer_api_key() -> Result<String> {
    std::env::var("RELAYER_API_KEY")
        .or_else(|_| std::env::var("POLYMARKET_RELAYER_API_KEY"))
        .context(
            "RELAYER_API_KEY (or POLYMARKET_RELAYER_API_KEY) required for poly1271 on-chain calls",
        )
}

fn relayer_api_key_address() -> Result<String> {
    std::env::var("RELAYER_API_KEY_ADDRESS")
        .or_else(|_| std::env::var("POLYMARKET_RELAYER_API_KEY_ADDRESS"))
        .context(
            "RELAYER_API_KEY_ADDRESS (or POLYMARKET_RELAYER_API_KEY_ADDRESS) required for poly1271 on-chain calls",
        )
}

fn deposit_wallet() -> Result<Address> {
    let raw = std::env::var("POLYMARKET_FUNDER").context(
        "POLYMARKET_FUNDER required for poly1271 on-chain calls (deposit wallet address)",
    )?;
    Address::from_str(raw.trim()).context("Invalid POLYMARKET_FUNDER address")
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("Failed to build relayer HTTP client")
}

fn auth_headers() -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "RELAYER_API_KEY",
        relayer_api_key()?
            .parse()
            .context("Invalid RELAYER_API_KEY header value")?,
    );
    headers.insert(
        "RELAYER_API_KEY_ADDRESS",
        relayer_api_key_address()?
            .parse()
            .context("Invalid RELAYER_API_KEY_ADDRESS header value")?,
    );
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    Ok(headers)
}

fn encode_address_word(addr: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice());
    out
}

fn encode_u256_word(v: U256) -> [u8; 32] {
    v.to_be_bytes::<32>()
}

fn call_type_hash() -> B256 {
    keccak256(b"Call(address target,uint256 value,bytes data)")
}

fn batch_type_hash() -> B256 {
    keccak256(
        b"Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)Call(address target,uint256 value,bytes data)",
    )
}

fn domain_type_hash() -> B256 {
    keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
}

fn domain_separator(chain_id: u64, wallet: Address) -> B256 {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(domain_type_hash().as_slice());
    buf.extend_from_slice(keccak256(DOMAIN_NAME.as_bytes()).as_slice());
    buf.extend_from_slice(keccak256(DOMAIN_VERSION.as_bytes()).as_slice());
    buf.extend_from_slice(&encode_u256_word(U256::from(chain_id)));
    buf.extend_from_slice(&encode_address_word(wallet));
    keccak256(&buf)
}

fn hash_call(target: Address, value: U256, data: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(32 * 4);
    buf.extend_from_slice(call_type_hash().as_slice());
    buf.extend_from_slice(&encode_address_word(target));
    buf.extend_from_slice(&encode_u256_word(value));
    buf.extend_from_slice(keccak256(data).as_slice());
    keccak256(&buf)
}

fn hash_calls(calls: &[(Address, Vec<u8>)]) -> B256 {
    let mut acc = Vec::with_capacity(calls.len() * 32);
    for (target, data) in calls {
        acc.extend_from_slice(hash_call(*target, U256::ZERO, data).as_slice());
    }
    keccak256(&acc)
}

fn batch_struct_hash(
    wallet: Address,
    nonce: U256,
    deadline: U256,
    calls: &[(Address, Vec<u8>)],
) -> B256 {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(batch_type_hash().as_slice());
    buf.extend_from_slice(&encode_address_word(wallet));
    buf.extend_from_slice(&encode_u256_word(nonce));
    buf.extend_from_slice(&encode_u256_word(deadline));
    buf.extend_from_slice(hash_calls(calls).as_slice());
    keccak256(&buf)
}

fn eip712_digest(
    chain_id: u64,
    wallet: Address,
    nonce: U256,
    deadline: U256,
    calls: &[(Address, Vec<u8>)],
) -> B256 {
    let domain = domain_separator(chain_id, wallet);
    let struct_hash = batch_struct_hash(wallet, nonce, deadline, calls);
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain.as_slice());
    buf.extend_from_slice(struct_hash.as_slice());
    keccak256(&buf)
}

async fn fetch_nonce(client: &reqwest::Client, owner: Address) -> Result<U256> {
    let url = format!(
        "{}/nonce?address={:?}&type=WALLET",
        relayer_url(),
        owner
    );
    let resp = client
        .get(&url)
        .headers(auth_headers()?)
        .send()
        .await
        .context("Relayer GET /nonce failed")?
        .error_for_status()
        .context("Relayer GET /nonce HTTP error")?;
    let body: NonceResponse = resp.json().await.context("Invalid /nonce JSON")?;
    U256::from_str(&body.nonce).context("Invalid nonce value from relayer")
}

async fn submit_wallet_batch(
    client: &reqwest::Client,
    body: &Value,
) -> Result<SubmitResponse> {
    let url = format!("{}/submit", relayer_url());
    let resp = client
        .post(&url)
        .headers(auth_headers()?)
        .json(body)
        .send()
        .await
        .context("Relayer POST /submit failed")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("Relayer POST /submit failed ({status}): {text}");
    }
    serde_json::from_str(&text).context(format!("Invalid /submit JSON: {text}"))
}

async fn poll_confirmed(
    client: &reqwest::Client,
    transaction_id: &str,
) -> Result<(B256, u64)> {
    let url = format!("{}/transaction?id={transaction_id}", relayer_url());
    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("Timed out waiting for relayer tx {transaction_id}");
        }
        let resp = client
            .get(&url)
            .headers(auth_headers()?)
            .send()
            .await
            .context("Relayer GET /transaction failed")?;
        if resp.status().is_success() {
            let value: Value = resp.json().await.context("Invalid /transaction JSON")?;
            let tx = parse_relayer_tx(&value)?;
            let state = tx.state.as_deref().unwrap_or("");
            match state {
                "STATE_CONFIRMED" | "STATE_MINED" | "STATE_EXECUTED" => {
                    if let Some(hash) = tx.transaction_hash.as_deref()
                        && !hash.is_empty()
                        && hash != "0x"
                    {
                        let hash = B256::from_str(hash)
                            .context("Invalid transactionHash from relayer")?;
                        // Prefer confirmed; accept mined/executed once hash is present.
                        if state == "STATE_CONFIRMED" || state == "STATE_MINED" {
                            return Ok((hash, 0));
                        }
                    }
                    if state == "STATE_CONFIRMED" {
                        // Confirmed without hash yet — keep polling briefly.
                    }
                }
                "STATE_FAILED" | "STATE_INVALID" => {
                    bail!(
                        "Relayer tx {transaction_id} failed (state={state}, hash={:?})",
                        tx.transaction_hash
                    );
                }
                _ => {}
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn parse_relayer_tx(value: &Value) -> Result<RelayerTx> {
    if let Some(arr) = value.as_array() {
        let first = arr
            .first()
            .context("Relayer /transaction returned empty array")?;
        return serde_json::from_value(first.clone()).context("Invalid relayer tx object");
    }
    serde_json::from_value(value.clone()).context("Invalid relayer tx object")
}

/// Execute one or more calls as the deposit wallet via the gasless relayer.
pub async fn send_deposit_wallet_calls(
    private_key: Option<&str>,
    calls: Vec<(Address, Vec<u8>)>,
) -> Result<(B256, u64, usize)> {
    if calls.is_empty() {
        bail!("No contract calls to send");
    }
    let wallet = deposit_wallet()?;
    let signer = auth::resolve_signer(private_key)?;
    let owner = polymarket_client_sdk_v2::auth::Signer::address(&signer);
    let client = http_client()?;
    let nonce = fetch_nonce(&client, owner).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs();
    let deadline = U256::from(now + DEADLINE_SECS);

    let digest = eip712_digest(POLYGON, wallet, nonce, deadline, &calls);
    let sig = signer
        .sign_hash(&digest)
        .await
        .context("Failed to sign deposit-wallet batch")?;
    let sig_hex = sig.to_string();

    let call_json: Vec<Value> = calls
        .iter()
        .map(|(target, data)| {
            json!({
                "target": format!("{target:?}"),
                "value": "0",
                "data": format!("0x{}", hex::encode(data)),
            })
        })
        .collect();

    let body = json!({
        "type": "WALLET",
        "from": format!("{owner:?}"),
        "to": DEPOSIT_WALLET_FACTORY,
        "nonce": nonce.to_string(),
        "signature": sig_hex,
        "depositWalletParams": {
            "depositWallet": format!("{wallet:?}"),
            "deadline": deadline.to_string(),
            "calls": call_json,
        }
    });

    let submitted = submit_wallet_batch(&client, &body).await?;
    let (hash, block) = poll_confirmed(&client, &submitted.transaction_id).await?;
    Ok((hash, block, calls.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_type_hash_matches_spec() {
        assert_eq!(
            format!("{:?}", call_type_hash()),
            format!("{:?}", keccak256(b"Call(address target,uint256 value,bytes data)"))
        );
    }

    #[test]
    fn empty_calls_hash_is_keccak_empty() {
        assert_eq!(hash_calls(&[]), keccak256([]));
    }
}

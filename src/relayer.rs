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
struct SubmitResponse {
    // Relayer returns `transactionID` (capital ID), not serde camelCase `transactionId`.
    #[serde(alias = "transactionID", alias = "transactionId", alias = "transaction_id")]
    transaction_id: String,
    #[allow(dead_code)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RelayerTx {
    state: Option<String>,
    #[serde(alias = "transactionHash", alias = "transaction_hash")]
    transaction_hash: Option<String>,
}

fn relayer_url() -> String {
    std::env::var("POLYMARKET_RELAYER_URL")
        .or_else(|_| std::env::var("RELAYER_URL"))
        .unwrap_or_else(|_| DEFAULT_RELAYER_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn env_nonempty(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
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

/// Builder HMAC (url-safe base64, keep `=`), matching `@polymarket/builder-signing-sdk`.
fn builder_hmac_signature(
    secret_b64: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<String> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let secret = STANDARD
        .decode(secret_b64.trim())
        .or_else(|_| URL_SAFE.decode(secret_b64.trim()))
        .context("Invalid POLY_BUILDER_SECRET (expected base64)")?;
    let mut message = format!("{timestamp}{method}{path}");
    if let Some(body) = body {
        message.push_str(body);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).context("Invalid HMAC key")?;
    mac.update(message.as_bytes());
    let digest = mac.finalize().into_bytes();
    // url-safe base64 but keep '=' padding
    Ok(STANDARD
        .encode(digest)
        .replace('+', "-")
        .replace('/', "_"))
}

fn auth_headers(method: &str, path: &str, body: Option<&str>) -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );

    // Prefer Relayer API keys (Settings → Relayer API keys).
    if let (Some(key), Some(address)) = (
        env_nonempty(&["RELAYER_API_KEY", "POLYMARKET_RELAYER_API_KEY"]),
        env_nonempty(&[
            "RELAYER_API_KEY_ADDRESS",
            "POLYMARKET_RELAYER_API_KEY_ADDRESS",
        ]),
    ) {
        headers.insert(
            "RELAYER_API_KEY",
            key.parse().context("Invalid RELAYER_API_KEY header value")?,
        );
        headers.insert(
            "RELAYER_API_KEY_ADDRESS",
            address
                .parse()
                .context("Invalid RELAYER_API_KEY_ADDRESS header value")?,
        );
        return Ok(headers);
    }

    // Fallback: Builder API keys also authenticate relayer /submit (Polymarket docs).
    let key = env_nonempty(&["POLY_BUILDER_API_KEY", "BUILDER_API_KEY"]);
    let secret = env_nonempty(&["POLY_BUILDER_SECRET", "BUILDER_SECRET"]);
    let passphrase = env_nonempty(&["POLY_BUILDER_PASSPHRASE", "BUILDER_PASSPHRASE"]);
    if let (Some(key), Some(secret), Some(passphrase)) = (key, secret, passphrase) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before epoch")?
            .as_secs()
            .to_string();
        let signature = builder_hmac_signature(&secret, &timestamp, method, path, body)?;
        headers.insert(
            "POLY_BUILDER_API_KEY",
            key.parse()
                .context("Invalid POLY_BUILDER_API_KEY header value")?,
        );
        headers.insert(
            "POLY_BUILDER_PASSPHRASE",
            passphrase
                .parse()
                .context("Invalid POLY_BUILDER_PASSPHRASE header value")?,
        );
        headers.insert(
            "POLY_BUILDER_TIMESTAMP",
            timestamp
                .parse()
                .context("Invalid POLY_BUILDER_TIMESTAMP header value")?,
        );
        headers.insert(
            "POLY_BUILDER_SIGNATURE",
            signature
                .parse()
                .context("Invalid POLY_BUILDER_SIGNATURE header value")?,
        );
        return Ok(headers);
    }

    bail!(
        "poly1271 on-chain calls require either RELAYER_API_KEY + RELAYER_API_KEY_ADDRESS \
         or POLY_BUILDER_API_KEY + POLY_BUILDER_SECRET + POLY_BUILDER_PASSPHRASE"
    );
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
    let path = format!("/nonce?address={:?}&type=WALLET", owner);
    let resp = client
        .get(&url)
        .headers(auth_headers("GET", &path, None)?)
        .send()
        .await
        .context("Relayer GET /nonce failed")?
        .error_for_status()
        .context("Relayer GET /nonce HTTP error")?;
    let body: NonceResponse = resp.json().await.context("Invalid /nonce JSON")?;
    U256::from_str(&body.nonce).context("Invalid nonce value from relayer")
}

fn tx_hash_if_done(tx: &RelayerTx) -> Option<B256> {
    let state = tx.state.as_deref().unwrap_or("");
    if !matches!(
        state,
        "STATE_CONFIRMED" | "STATE_MINED" | "STATE_EXECUTED"
    ) {
        return None;
    }
    let hash = tx.transaction_hash.as_deref()?;
    if hash.is_empty() || hash == "0x" {
        return None;
    }
    B256::from_str(hash).ok()
}

async fn submit_wallet_batch(
    client: &reqwest::Client,
    body: &Value,
) -> Result<(SubmitResponse, Option<B256>)> {
    let url = format!("{}/submit", relayer_url());
    let body_str = serde_json::to_string(body).context("Failed to serialize /submit body")?;
    let resp = client
        .post(&url)
        .headers(auth_headers("POST", "/submit", Some(&body_str))?)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body_str)
        .send()
        .await
        .context("Relayer POST /submit failed")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("Relayer POST /submit failed ({status}): {text}");
    }
    // /submit sometimes returns only {transactionID,state:NEW}; sometimes already EXECUTED+hash.
    let value: Value =
        serde_json::from_str(&text).context(format!("Invalid /submit JSON: {text}"))?;
    let submitted: SubmitResponse = serde_json::from_value(value.clone())
        .context(format!("Invalid /submit JSON: {text}"))?;
    let early = parse_relayer_tx(&value)
        .ok()
        .and_then(|tx| tx_hash_if_done(&tx));
    Ok((submitted, early))
}

async fn poll_confirmed(
    client: &reqwest::Client,
    transaction_id: &str,
) -> Result<(B256, u64)> {
    let path = format!("/transaction?id={transaction_id}");
    let url = format!("{}{path}", relayer_url());
    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("Timed out waiting for relayer tx {transaction_id}");
        }
        let resp = client
            .get(&url)
            .headers(auth_headers("GET", &path, None)?)
            .send()
            .await
            .context("Relayer GET /transaction failed")?;
        if resp.status().is_success() {
            let value: Value = resp.json().await.context("Invalid /transaction JSON")?;
            let tx = parse_relayer_tx(&value)?;
            let state = tx.state.as_deref().unwrap_or("");
            if matches!(state, "STATE_FAILED" | "STATE_INVALID") {
                bail!(
                    "Relayer tx {transaction_id} failed (state={state}, hash={:?})",
                    tx.transaction_hash
                );
            }
            if let Some(hash) = tx_hash_if_done(&tx) {
                return Ok((hash, 0));
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

    let (submitted, early_hash) = submit_wallet_batch(&client, &body).await?;
    let (hash, block) = if let Some(hash) = early_hash {
        (hash, 0)
    } else {
        poll_confirmed(&client, &submitted.transaction_id).await?
    };
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

#[cfg(test)]
mod submit_parse_tests {
    use super::*;

    #[test]
    fn submit_response_accepts_transaction_id_capital() {
        let raw = r#"{"transactionID":"019f812c-7dfd-7595-b7c3-19b2abad9e41","transactionHash":"0x19c7ef07fdd5396f221589a955ff1d4f8fa8b009937e38e0a3377b6e2ef3333d","state":"STATE_EXECUTED"}"#;
        let parsed: SubmitResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.transaction_id, "019f812c-7dfd-7595-b7c3-19b2abad9e41");
        let value: Value = serde_json::from_str(raw).unwrap();
        let tx = parse_relayer_tx(&value).unwrap();
        assert!(tx_hash_if_done(&tx).is_some());
    }
}

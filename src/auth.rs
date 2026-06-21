use std::str::FromStr;
use std::time::Duration;

use alloy::providers::ProviderBuilder;
use anyhow::{Context, Result};
use polymarket_client_sdk_v2::auth::state::Authenticated;
use polymarket_client_sdk_v2::auth::{LocalSigner, Normal, Signer as _};
use polymarket_client_sdk_v2::clob::types::SignatureType;
use polymarket_client_sdk_v2::types::Address;
use polymarket_client_sdk_v2::{POLYGON, clob};
use reqwest::Client;

use crate::config;

const DEFAULT_CLOB_HOST: &str = "https://clob.polymarket.com";
const DEFAULT_RPC_URL: &str = "https://polygon.drpc.org";
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn clob_host() -> String {
    std::env::var("POLYMARKET_CLOB_HOST").unwrap_or_else(|_| DEFAULT_CLOB_HOST.to_string())
}

fn rpc_url() -> String {
    std::env::var("POLYMARKET_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string())
}

fn rpc_url_parsed() -> Result<reqwest::Url> {
    rpc_url()
        .parse()
        .context("Invalid POLYMARKET_RPC_URL")
}

fn configure_http_client(builder: reqwest::ClientBuilder) -> Client {
    builder
        .timeout(RPC_REQUEST_TIMEOUT)
        .connect_timeout(RPC_CONNECT_TIMEOUT)
        .build()
        .expect("reqwest client build")
}

fn parse_signature_type(s: &str) -> SignatureType {
    match s {
        config::DEFAULT_SIGNATURE_TYPE => SignatureType::Proxy,
        "gnosis-safe" => SignatureType::GnosisSafe,
        "poly1271" | "deposit" => SignatureType::Poly1271,
        _ => SignatureType::Eoa,
    }
}

/// Optional funder (deposit wallet / proxy) address, read from `POLYMARKET_FUNDER`.
/// Required for the `poly1271` deposit-wallet flow; the maker is set to this address.
fn funder() -> Result<Option<Address>> {
    match std::env::var("POLYMARKET_FUNDER") {
        Ok(s) if !s.is_empty() => Ok(Some(
            Address::from_str(&s).context("Invalid POLYMARKET_FUNDER address")?,
        )),
        _ => Ok(None),
    }
}

pub fn resolve_signer(
    private_key: Option<&str>,
) -> Result<impl polymarket_client_sdk_v2::auth::Signer> {
    let (key, _) = config::resolve_key(private_key)?;
    let key = key.ok_or_else(|| anyhow::anyhow!("{}", config::NO_WALLET_MSG))?;
    LocalSigner::from_str(&key)
        .context("Invalid private key")
        .map(|s| s.with_chain_id(Some(POLYGON)))
}

pub async fn authenticated_clob_client(
    private_key: Option<&str>,
    signature_type_flag: Option<&str>,
) -> Result<clob::Client<Authenticated<Normal>>> {
    let signer = resolve_signer(private_key)?;
    authenticate_with_signer(&signer, signature_type_flag).await
}

pub async fn authenticate_with_signer(
    signer: &(impl polymarket_client_sdk_v2::auth::Signer + Sync),
    signature_type_flag: Option<&str>,
) -> Result<clob::Client<Authenticated<Normal>>> {
    let sig_type = parse_signature_type(&config::resolve_signature_type(signature_type_flag)?);

    let mut builder = unauthenticated_clob_client()?
        .authentication_builder(signer)
        .signature_type(sig_type);
    if let Some(funder) = funder()? {
        builder = builder.funder(funder);
    }
    builder
        .authenticate()
        .await
        .context("Failed to authenticate with Polymarket CLOB")
}

pub fn unauthenticated_clob_client() -> Result<clob::Client> {
    clob::Client::new(&clob_host(), clob::Config::default())
        .context("Failed to create Polymarket CLOB client")
}

pub async fn create_readonly_provider() -> Result<impl alloy::providers::Provider + Clone> {
    Ok(ProviderBuilder::new().with_reqwest(rpc_url_parsed()?, configure_http_client))
}

pub async fn create_provider(
    private_key: Option<&str>,
) -> Result<impl alloy::providers::Provider + Clone> {
    let (key, _) = config::resolve_key(private_key)?;
    let key = key.ok_or_else(|| anyhow::anyhow!("{}", config::NO_WALLET_MSG))?;
    let signer = LocalSigner::from_str(&key)
        .context("Invalid private key")?
        .with_chain_id(Some(POLYGON));
    Ok(ProviderBuilder::new()
        .wallet(signer)
        .with_reqwest(rpc_url_parsed()?, configure_http_client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signature_type_proxy() {
        assert_eq!(parse_signature_type("proxy"), SignatureType::Proxy);
    }

    #[test]
    fn parse_signature_type_gnosis_safe() {
        assert_eq!(
            parse_signature_type("gnosis-safe"),
            SignatureType::GnosisSafe
        );
    }

    #[test]
    fn parse_signature_type_eoa() {
        assert_eq!(parse_signature_type("eoa"), SignatureType::Eoa);
    }

    #[test]
    fn parse_signature_type_unknown_defaults_to_eoa() {
        assert_eq!(parse_signature_type("unknown"), SignatureType::Eoa);
    }
}

use std::str::FromStr;

use crate::error::CliError;
use anyhow::Result;
use reqwest::{Client, Url};
use tinycloud_lib::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation},
    libipld::Cid,
    resource::OrbitId,
    ssi::dids::DIDURLBuf,
};

#[derive(Debug, Clone)]
pub struct TinyCloudClient {
    client: Client,
    base_url: Url,
}

impl TinyCloudClient {
    pub fn new(base_url: Url) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// Generate a host key for the given orbit
    pub async fn generate_host_key(&self, orbit: &OrbitId) -> Result<DIDURLBuf> {
        let url = format!(
            "{}/peer/generate/{}",
            self.base_url,
            urlencoding::encode(&orbit.to_string())
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(CliError::HttpError)?;

        if !response.status().is_success() {
            return Err(CliError::HttpError(response.error_for_status().unwrap_err()).into());
        }

        let host_did = response
            .text()
            .await
            .map_err(CliError::HttpError)?
            .parse()?;
        Ok(host_did)
    }

    /// Submit a delegation to the server
    pub async fn delegate(&self, delegation: &TinyCloudDelegation) -> Result<Cid> {
        let url = format!("{}/delegate", self.base_url);

        // Encode the delegation as an authorization header
        let auth_header = delegation
            .encode()
            .map_err(|e| CliError::AuthorizationError(e.to_string()))?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(CliError::HttpError)?;

        let cid = response.text().await?.parse()?;
        Ok(cid)
    }

    /// Invoke a GET operation
    pub async fn invoke_get(&self, invocation: &TinyCloudInvocation) -> Result<Vec<u8>> {
        let url = format!("{}/invoke", self.base_url);

        let auth_header = invocation
            .encode()
            .map_err(|e| CliError::AuthorizationError(e.to_string()))?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(CliError::HttpError)?;

        if !response.status().is_success() {
            return Err(CliError::HttpError(response.error_for_status().unwrap_err()).into());
        }

        let bytes = response.bytes().await.map_err(CliError::HttpError)?;
        Ok(bytes.to_vec())
    }

    /// Invoke a PUT operation with data
    pub async fn invoke_put(&self, invocation: &TinyCloudInvocation, data: Vec<u8>) -> Result<()> {
        let url = format!("{}/invoke", self.base_url);

        let auth_header = invocation
            .encode()
            .map_err(|e| CliError::AuthorizationError(e.to_string()))?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(CliError::HttpError)?;

        if !response.status().is_success() {
            return Err(CliError::HttpError(response.error_for_status().unwrap_err()).into());
        }

        Ok(())
    }

    /// Invoke a HEAD operation to get metadata
    pub async fn invoke_head(&self, invocation: &TinyCloudInvocation) -> Result<String> {
        let url = format!("{}/invoke", self.base_url);

        let auth_header = invocation
            .encode()
            .map_err(|e| CliError::AuthorizationError(e.to_string()))?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(CliError::HttpError)?;

        if !response.status().is_success() {
            return Err(CliError::HttpError(response.error_for_status().unwrap_err()).into());
        }

        let metadata = response.text().await.map_err(CliError::HttpError)?;
        Ok(metadata)
    }

    /// Invoke a DELETE operation
    pub async fn invoke_delete(&self, invocation: &TinyCloudInvocation) -> Result<()> {
        let url = format!("{}/invoke", self.base_url);

        let auth_header = invocation
            .encode()
            .map_err(|e| CliError::AuthorizationError(e.to_string()))?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(CliError::HttpError)?;

        if !response.status().is_success() {
            return Err(CliError::HttpError(response.error_for_status().unwrap_err()).into());
        }

        Ok(())
    }
}

impl FromStr for TinyCloudClient {
    type Err = <Url as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let base_url = Url::parse(s)?;
        Ok(TinyCloudClient::new(base_url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = TinyCloudClient::new("https://demo.tinycloud.xyz/".parse().unwrap());
        assert_eq!(client.base_url.as_str(), "https://demo.tinycloud.xyz/");
    }
}

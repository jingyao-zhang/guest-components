// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;
use std::process::Command;

use std::env;

use anyhow::{bail, Context};
use async_trait::async_trait;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request, Response};
use kbs_types::{CombinedAttestation, TeeEvidence, CustomClaims, NestedTEE};
use log::{debug, warn};
use resource_uri::ResourceUri;
use serde::Deserialize;
use sha2::{Digest, Sha384};

use crate::{
    api::KbsClientCapabilities,
    client::{
        ClientTee, KbsClient, KBS_GET_RESOURCE_MAX_ATTEMPT, KBS_PREFIX, KBS_PROTOCOL_VERSION,
    },
    evidence_provider::EvidenceProvider,
    keypair::TeeKeyPair,
    token_provider::Token,
    Error, Result,
};

/// When executing get token, RCAR handshake should retry if failed to
/// make the logic robust. This constant is the max retry times.
const RCAR_MAX_ATTEMPT: i32 = 5;

/// The interval (seconds) between RCAR handshake retries.
const RCAR_RETRY_TIMEOUT_SECOND: u64 = 1;

fn fetch_h100_evidence() -> Result<(String, String)> {
    // 获取 HOME 环境变量
    let user = env::var("SUDO_USER").unwrap_or_else(|_| env::var("USER").unwrap());
    let home_dir = format!("/home/{}", user);
    debug!("HOME: {}", home_dir);

    // 使用 HOME 环境变量构建路径
    let python_path = format!("{}/miniconda3/envs/nvtrust/bin/python3", home_dir);
    let script_path = format!("{}/nvtrust/guest_tools/attestation_sdk/tests/LocalGPUTest.py", home_dir);

    // 执行命令
    let output = Command::new(python_path)
        .arg(script_path)
        .output()
        .expect("Failed to execute command");

    
    // let output = Command::new("/home/jzhan502/miniconda3/envs/nvtrust/bin/python3")
    //     .arg("/home/jzhan502/nvtrust/guest_tools/attestation_sdk/tests/LocalGPUTest.py")
    //     // .arg("/home/jzhan502/nvtrust/guest_tools/attestation_sdk/tests/RemoteGPUTest.py")
    //     .output()
    //     .expect("Failed to execute command");

        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
    
        // debug!("stdout: {}", stdout);
        // debug!("stderr: {}", stderr);
    
    Ok((stdout, stderr))
}

#[derive(Deserialize, Debug, Clone)]
struct AttestationResponseData {
    // Attestation token in JWT format
    token: String,
}

impl KbsClient<Box<dyn EvidenceProvider>> {
    /// Get a [`TeeKeyPair`] and a [`Token`] that certifies the [`TeeKeyPair`].
    /// It will check if the client already has a valid token. If so, return
    /// the token. If not, the client will generate a new key pair and do a new
    /// RCAR handshaking.
    pub async fn get_token(&mut self) -> Result<(Token, TeeKeyPair)> {
        if let Some(token) = &self.token {
            if token.check_valid().is_err() {
                let mut retry_times = 1;
                loop {
                    let res = self
                        .rcar_handshake()
                        .await
                        .map_err(|e| Error::RcarHandshake(e.to_string()));
                    match res {
                        Ok(_) => break,
                        Err(e) => {
                            if retry_times >= RCAR_MAX_ATTEMPT {
                                return Err(Error::RcarHandshake(format!("Get token failed because of RCAR handshake retried {RCAR_MAX_ATTEMPT} times.")));
                            } else {
                                warn!("RCAR handshake failed: {e}, retry {retry_times}...");
                                retry_times += 1;
                                tokio::time::sleep(Duration::from_secs(RCAR_RETRY_TIMEOUT_SECOND))
                                    .await;
                            }
                        }
                    }
                }
            }
        } else {
            let mut retry_times = 1;
            loop {
                let res = self
                    .rcar_handshake()
                    .await
                    .map_err(|e| Error::RcarHandshake(e.to_string()));
                match res {
                    Ok(_) => break,
                    Err(e) => {
                        if retry_times >= RCAR_MAX_ATTEMPT {
                            return Err(Error::RcarHandshake(format!("Get token failed because of RCAR handshake retried {RCAR_MAX_ATTEMPT} times.")));
                        } else {
                            warn!("RCAR handshake failed: {e}, retry {retry_times}...");
                            retry_times += 1;
                            tokio::time::sleep(Duration::from_secs(RCAR_RETRY_TIMEOUT_SECOND))
                                .await;
                        }
                    }
                }
            }
        }

        assert!(self.token.is_some());

        let token = self.token.clone().unwrap();
        let tee_key = self.tee_key.clone();
        Ok((token, tee_key))
    }

    /// Perform RCAR handshake with the given kbs host. If succeeds, the client will
    /// store the token.
    ///
    /// Note: if RCAR succeeds, the http client will record the cookie with the kbs server,
    /// which means that this client can be then used to retrieve resources.
    async fn rcar_handshake(&mut self) -> anyhow::Result<()> {
        let auth_endpoint = format!("{}/{KBS_PREFIX}/auth", self.kbs_host_url);

        let tee = match &self._tee {
            ClientTee::Unitialized => {
                let tee = self.provider.get_tee_type().await?;
                self._tee = ClientTee::_Initializated(tee.clone());
                tee
            }
            ClientTee::_Initializated(tee) => tee.clone(),
        };

        let request = Request {
            version: String::from(KBS_PROTOCOL_VERSION),
            tee,
            extra_params: String::new(),
        };

        debug!("send auth request to {auth_endpoint}");

        let mut challenge = self
            .http_client
            .post(auth_endpoint)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?
            .json::<Challenge>()
            .await?;

        // -----------------------------------------------------------
        // -----------------------------------------------------------

        let (device_report, stderr) = fetch_h100_evidence()?;

        // debug!("stdout-caller: {}", stdout);
        // debug!("stderr-caller: {}", stderr);
        debug!("Successfully get device_report from H100");
        // debug!("get challenge: {challenge:#?}");

        // -----------------------------------------------------------
        let nested_tee = NestedTEE {
            attestation_report: device_report.clone(),
        };
        let custom_claims = CustomClaims {
            nonce: challenge.nonce.clone(),
            inner_tee_pubkey: self.tee_key.export_pubkey()?,
            nested_tee: nested_tee,
        };
        // -----------------------------------------------------------



        // Assuming `device_report` is a String and `challenge.nonce` is also a String or similar
        let mut hasher = Sha384::new();
        hasher.update(device_report.as_bytes()); // Hash `device_report`
        hasher.update(challenge.nonce.as_bytes()); // Hash `challenge.nonce`

        // Finalize the hash and convert to a Vec<u8>
        let result_hash_bytes = hasher.finalize().to_vec();

        // Encode the final hash as base64
        let result_hash_base64 = base64::encode(result_hash_bytes);

        // debug!("Base64 Hashed output: {}", result_hash_base64);

        // Assign the base64 string to challenge.nonce
        challenge.nonce = result_hash_base64;

        // -----------------------------------------------------------
        // -----------------------------------------------------------

        debug!("Finish combining device_report and challenge.nonce");
        // debug!("get challenge: {challenge:#?}");
        let tee_pubkey = self.tee_key.export_pubkey()?;
        let materials = vec![tee_pubkey.k_mod.as_bytes(), tee_pubkey.k_exp.as_bytes()];
        let evidence = self.generate_evidence(challenge.nonce, materials).await?;

        // debug!("get evidence with challenge: {evidence}");

        // -----------------------------------------------------------
        debug!("Successfully get cpu_evidence");
        debug!("Build tee_evidence with cpu_evidence and custom_claims");
        let tee_evidence = TeeEvidence {
            tee_type: self.provider.get_tee_type().await?,
            // tee_type: "Sample".to_string(),
            cpu_evidence: evidence,
            custom_claims: custom_claims,
        };

        let attest_endpoint = format!("{}/{KBS_PREFIX}/attest", self.kbs_host_url);

        let combined_attest = CombinedAttestation {
            tee_pubkey: tee_pubkey,
            tee_evidence: tee_evidence,
        };
        // -----------------------------------------------------------

        // let attest_endpoint = format!("{}/{KBS_PREFIX}/attest", self.kbs_host_url);
        // let attest = Attestation {
        //     tee_pubkey,
        //     tee_evidence: evidence,
        // };

        debug!("send attest request.");
        let attest_response = self
            .http_client
            .post(attest_endpoint)
            .header("Content-Type", "application/json")
            .json(&combined_attest)
            // .json(&attest)
            .send()
            .await?;

        match attest_response.status() {
            reqwest::StatusCode::OK => {
                let resp = attest_response.json::<AttestationResponseData>().await?;
                let token = Token::new(resp.token)?;
                self.token = Some(token);
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                let error_info = attest_response.json::<ErrorInformation>().await?;
                bail!("KBS attest unauthorized, Error Info: {:?}", error_info);
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    attest_response.text().await?
                );
            }
        }

        debug!("Token received");

        Ok(())
    }

    async fn generate_evidence(&self, nonce: String, key_materials: Vec<&[u8]>) -> Result<String> {
        let mut hasher = Sha384::new();
        hasher.update(nonce.as_bytes());
        key_materials
            .iter()
            .for_each(|key_material| hasher.update(key_material));

        let ehd = hasher.finalize().to_vec();

        let tee_evidence = self
            .provider
            .get_evidence(ehd)
            .await
            .context("Get TEE evidence failed")
            .map_err(|e| Error::GetEvidence(e.to_string()))?;

        Ok(tee_evidence)
    }
}

#[async_trait]
impl KbsClientCapabilities for KbsClient<Box<dyn EvidenceProvider>> {
    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>> {
        let remote_url = format!(
            "{}/{KBS_PREFIX}/resource/{}/{}/{}",
            self.kbs_host_url, resource_uri.repository, resource_uri.r#type, resource_uri.tag
        );

        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            debug!("KBS client: trying to request KBS, attempt {attempt}");

            let res = self
                .http_client
                .get(&remote_url)
                .send()
                .await
                .map_err(|e| Error::HttpError(format!("get failed: {e}")))?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res
                        .json::<Response>()
                        .await
                        .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?;
                    let payload_data = self
                        .tee_key
                        .decrypt_response(response)
                        .map_err(|e| Error::DecryptResponseFailed(e.to_string()))?;
                    return Ok(payload_data);
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    warn!(
                        "Authenticating with KBS failed. Perform a new RCAR handshake: {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?,
                    );
                    self.rcar_handshake()
                        .await
                        .map_err(|e| Error::RcarHandshake(e.to_string()))?;

                    continue;
                }
                reqwest::StatusCode::NOT_FOUND => {
                    let errorinfo = format!(
                        "KBS resource Not Found (Error 404): {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::ResourceNotFound(errorinfo));
                }
                _ => {
                    let errorinfo = format!(
                        "KBS Server Internal Failed, Response: {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::KbsInternalError(errorinfo));
                }
            }
        }

        Err(Error::UnAuthorized)
    }
}

#[cfg(test)]
mod test {
    use std::{env, path::PathBuf};
    use testcontainers::{clients, images::generic::GenericImage};
    use tokio::fs;

    use crate::{
        evidence_provider::NativeEvidenceProvider, KbsClientBuilder, KbsClientCapabilities,
    };

    const CONTENT: &[u8] = b"test content";

    #[tokio::test]
    #[serial_test::serial]
    async fn test_client() {
        // prepare test resource
        let tmp = tempfile::tempdir().expect("create tempdir");
        let mut resource_path = PathBuf::new();
        resource_path.push(tmp.path());
        resource_path.push("default/key");
        fs::create_dir_all(resource_path.clone())
            .await
            .expect("create resource path");

        resource_path.push("testfile");
        fs::write(resource_path.clone(), CONTENT)
            .await
            .expect("write content");

        // launch kbs
        let docker = clients::Cli::default();

        // we should change the entrypoint of the kbs image by using
        // a start script
        let mut start_kbs_script = env::current_dir().expect("get cwd");
        start_kbs_script.push("test/start_kbs.sh");

        let image = GenericImage::new(
            "ghcr.io/confidential-containers/key-broker-service",
            "built-in-as-v0.7.0",
        )
        .with_exposed_port(8085)
        .with_volume(
            tmp.path().as_os_str().to_string_lossy(),
            "/opt/confidential-containers/kbs/repository",
        )
        .with_volume(
            start_kbs_script.into_os_string().to_string_lossy(),
            "/usr/local/bin/start_kbs.sh",
        )
        .with_entrypoint("/usr/local/bin/start_kbs.sh");
        let kbs = docker.run(image);

        let port = kbs.get_host_port_ipv4(8085);
        let kbs_host_url = format!("http://127.0.0.1:{port}");

        env::set_var("AA_SAMPLE_ATTESTER_TEST", "1");
        let evidence_provider = Box::new(NativeEvidenceProvider::new().unwrap());
        let mut client = KbsClientBuilder::with_evidence_provider(evidence_provider, &kbs_host_url)
            .build()
            .expect("client create");
        let resource_uri = "kbs:///default/key/testfile"
            .try_into()
            .expect("resource uri");

        let resource = client
            .get_resource(resource_uri)
            .await
            .expect("get resource");
        assert_eq!(resource, CONTENT);

        let (token, key) = client.get_token().await.expect("get token");
        println!("Get token : {token:?}");
        println!("Get key: {key:?}");
    }
}

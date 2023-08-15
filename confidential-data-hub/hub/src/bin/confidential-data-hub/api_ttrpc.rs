// This file is generated by ttrpc-compiler 0.6.1. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clipto_camel_casepy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
use protobuf::{CodedInputStream, CodedOutputStream, Message};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

#[derive(Clone)]
pub struct SealedSecretServiceClient {
    client: ::ttrpc::r#async::Client,
}

impl SealedSecretServiceClient {
    pub fn new(client: ::ttrpc::r#async::Client) -> Self {
        SealedSecretServiceClient {
            client,
        }
    }

    pub async fn unseal_secret(&self, ctx: ttrpc::context::Context, req: &super::api::UnsealSecretInput) -> ::ttrpc::Result<super::api::UnsealSecretOutput> {
        let mut cres = super::api::UnsealSecretOutput::new();
        ::ttrpc::async_client_request!(self, ctx, req, "api.SealedSecretService", "UnsealSecret", cres);
    }
}

struct UnsealSecretMethod {
    service: Arc<Box<dyn SealedSecretService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for UnsealSecretMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, api, UnsealSecretInput, unseal_secret);
    }
}

#[async_trait]
pub trait SealedSecretService: Sync {
    async fn unseal_secret(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::api::UnsealSecretInput) -> ::ttrpc::Result<super::api::UnsealSecretOutput> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/api.SealedSecretService/UnsealSecret is not supported".to_string())))
    }
}

pub fn create_sealed_secret_service(service: Arc<Box<dyn SealedSecretService + Send + Sync>>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("UnsealSecret".to_string(),
                    Box::new(UnsealSecretMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("api.SealedSecretService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}
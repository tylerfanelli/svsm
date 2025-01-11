// SDPX-License-Identifier: Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc
//
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::Context;
use teekms_lib::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct TeeKmsProtocol;

impl AttestationProtocol for TeeKmsProtocol {
    fn negotiation(
        cli: &Client,
        url: &str,
        request: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse> {
        let resp = cli
            .get(format!("{}/attest/challenge", url))
            .send()
            .context("unable to fetch challenge from TEE-KMS server")?;

        let text = resp
            .text()
            .context("unable to convert TEE-KMS challenge response to text")?;
        let challenge = Challenge::try_from(text).unwrap();

        println!("CHALLENGE FROM SERVER: {:?}", challenge);

        todo!();
    }

    fn attestation(
        cli: &Client,
        url: &str,
        request: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse> {
        todo!();
    }
}

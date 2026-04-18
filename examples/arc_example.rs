// Copyright (c) 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::num::NonZero;

use arc::{ArcError, Credential, CredentialRequest, CredentialResponse, SecretKey, Suite};
use rand::rngs::ThreadRng;

pub fn protocol<S: Suite>() -> Result<(), ArcError> {
    println!("Protocol runs with Suite: {}", S::NAME);

    // # Setup Issuer
    let prng = &mut ThreadRng::default();
    let key = SecretKey::<S>::new(prng);
    println!("Secret key: {} bytes", key.to_bytes().len());
    let params = key.issuer_params()?;
    println!("Issuer params: {} bytes", params.to_bytes().len());

    // # Credential Issuance
    //
    //   Client (params)                    Issuer (key)
    //       |                                 |
    //  [ Request ]                            |
    const REQUEST_CONTEXT: &[u8] = b"RequestContext";
    let (request, secrets) = CredentialRequest::new(prng, REQUEST_CONTEXT)?;
    println!("Credential Request: {} bytes", request.to_bytes().len());
    //       |                                 |
    //       |-------  CredentialRequest  ---->|
    //       |                                 |
    //       |                           [ Response ]
    let response = CredentialResponse::new(prng, &key, request.clone())?;
    println!("Credential Response: {} bytes", response.to_bytes().len());
    //       |                                 |
    //       |<------  CredentialResponse  ----|
    //       |                                 |
    //  [ Finalize ]                           |
    let credential = Credential::new(&params, request, secrets, response)?;
    println!("Credential: {} bytes", credential.to_bytes().len());
    //       |                                 |
    //   Credential                         (nothing)

    // # Presentation
    //
    //   Client (credential)                Issuer (key)
    //       |                                 |
    const N: NonZero<u32> = NonZero::new(3).expect("non-zero limit"); // Presentation Limit
    const PRESENTATION_CONTEXT: &[u8] = b"PresentationContext";
    let mut state = credential.presentation_state(N, PRESENTATION_CONTEXT)?;
    println!("State: {} bytes", state.to_bytes().len());
    //       |                                 |
    // +---------------------------------------------+
    // |  LOOP (N times)                             |
    // |     |                                 |     |
    // |  [ Present ]                          |     |
    let presentation = state.present(prng)?;
    println!("Presentation: {} bytes", presentation.to_bytes().len());
    // |     |                                 |     |
    // |     |-------  Presentation  --------->|     |
    // |     |                                 |     |
    // |     |                            [ Verify ] |
    let result = presentation.verify(&key, REQUEST_CONTEXT, N, PRESENTATION_CONTEXT);
    // |     |                                 |     |
    // |     |<--------  Result(Ok/Err) -------|     |
    // |     |                                 |     |
    assert!(result.is_ok());
    // |                                             |
    // +---------------------------------------------+
    result
}

fn main() -> Result<(), ArcError> {
    println!("ARC protocol example.");
    #[cfg(feature = "suite_p256")]
    protocol::<arc::suites::P256>()?;
    #[cfg(feature = "suite_ristretto255")]
    protocol::<arc::suites::Ristretto255>()?;
    Ok(())
}

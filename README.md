# Peerdid Python

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Unit Tests](https://github.com/sicpa-dlab/peer-did-python/workflows/verify/badge.svg)](https://github.com/sicpa-dlab/peer-did-python/actions/workflows/verify.yml)
[![Python Package](https://img.shields.io/pypi/v/peerdid)](https://pypi.org/project/peerdid/)

Implementation of the [Peer DID method specification](https://identity.foundation/peer-did-method-spec/) in Python.

Implements [static layers of support (1, 2a, 2b)](https://identity.foundation/peer-did-method-spec/#layers-of-support) only.

## Installation
```
pip install peerdid
```

## DIDComm + peerdid Demo
See https://github.com/sicpa-dlab/didcomm-demo.

## Example

Example code:

```python
from peerdid.dids import (
    create_peer_did_numalgo_0,
    create_peer_did_numalgo_2,
    resolve_peer_did,
)
from peerdid.keys import Ed25519VerificationKey, X25519KeyAgreementKey

encryption_keys = [
    X25519KeyAgreementKey.from_base58(
        "DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s"
    )
]
signing_keys = [
    Ed25519VerificationKey.from_base58(
        "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
    )
]
service = """
    {
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint1",
        "routingKeys": ["did:example:somemediator#somekey1"],
        "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
    }
"""

peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
peer_did_algo_2 = create_peer_did_numalgo_2(
    encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
)

did_doc_algo_0 = resolve_peer_did(peer_did=peer_did_algo_0)
did_doc_algo_2 = resolve_peer_did(peer_did=peer_did_algo_2)

did_doc_algo_0_json = did_doc_algo_0.to_json()
did_doc_algo_2_json = did_doc_algo_2.to_json()
```

Example of DID documents:

```jsonc
// did_doc_algo_0_json
{
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
    "verificationMethod": [
        {
            "id": "#6MkqRYqQ",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        }
    ],
    "authentication": ["#6MkqRYqQ"],
    "assertionMethod": ["#6MkqRYqQ"],
    "capabilityInvocation": ["#6MkqRYqQ"],
    "capabilityDelegation": ["#6MkqRYqQ"]
}

// did_doc_algo_2_json
{
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/x25519-2020/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ",
    "verificationMethod": [
        {
            "id": "#6LSpSrLx",
            "type": "X25519KeyAgreementKey2020",
            "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ",
            "publicKeyMultibase": "z6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
        },
        {
            "id": "#6MkqRYqQ",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDEiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MSJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ",
            "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
        }
    ],
    "authentication": ["#6MkqRYqQ"],
    "assertionMethod": ["#6MkqRYqQ"],
    "keyAgreement": ["#6LSpSrLx"],
    "capabilityInvocation": ["#6MkqRYqQ"],
    "capabilityDelegation": ["#6MkqRYqQ"],
    "service": [
        {
            "id": "#didcommmessaging-0",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint1",
            "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
            "routingKeys": ["did:example:somemediator#somekey1"]
        }
    ]
}
```

## Assumptions and limitations
- Only static layers [1, 2a, 2b](https://identity.foundation/peer-did-method-spec/#layers-of-support) are supported
- Only `X25519` keys are supported for key agreement
- Only `Ed25519` keys are supported for authentication
- Supported verification materials (input and in the resolved DID Document):
  - [Default] 2020 verification materials (`Ed25519VerificationKey2020` and `X25519KeyAgreementKey2020`) with multibase base58 (`publicKeyMultibase`) public key encoding.
  - JWK (`JsonWebKey2020`) using JWK (`publicKeyJwk`) public key encoding 
  - 2018/2019 verification materials (`Ed25519VerificationKey2018` and `X25519KeyAgreementKey2019`) using base58 (`publicKeyBase58`) public key encoding. 
 


## How to contribute

Pull requests are welcome!

Pull requests should have a descriptive name, include the summary of all changes made in the pull
request description, and include unit tests that provide good coverage of the feature or fix. A Continuous Integration (
CI)
pipeline is executed on all PRs before review and contributors are expected to address all CI issues identified.

### A Continuous Integration (CI) pipeline does the following jobs:

- Executes all unit tests from the pull request.
- Analyzes code style using Flake8.


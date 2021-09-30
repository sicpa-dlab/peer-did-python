# Peer DID python API

This is an implementation of the [Peer DID method specification](https://identity.foundation/peer-did-method-spec/).

This version of API implements
only [static layers of support (1, 2a, 2b)](https://identity.foundation/peer-did-method-spec/#layers-of-support).

## Example

Example code:

    encryption_keys = [
        PublicKeyAgreement(type=PublicKeyTypeAgreement.X25519, encoding_type=EncodingType.BASE58,
                           encoded_value="DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s")
    ]
    signing_keys = [
        PublicKeyAuthentication(type=PublicKeyTypeAuthentication.ED25519, encoding_type=EncodingType.BASE58,
                                encoded_value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7")
    ]
    service = \
        '''
            [
                {
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": "https://example.com/endpoint",
                    "routingKeys": ["did:example:somemediator#somekey"]
                },
                {
                    "type": "example",
                    "serviceEndpoint": "https://example.com/endpoint2",
                    "routingKeys": ["did:example:somemediator#somekey2"]
                }
            ]
        '''

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    peer_did_algo_2 = create_peer_did_numalgo_2(encryption_keys=encryption_keys,
                                                signing_keys=signing_keys,
                                                service=service)

    did_doc_algo_0 = resolve_peer_did(peer_did=peer_did_algo_0)
    did_doc_algo_2 = resolve_peer_did(peer_did=peer_did_algo_2)

Example of DID documents:

    # did_doc_algo_0
    {
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "authentication": [
          {
              "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
              "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
          }
        ]
    }

    # did_doc_algo_2
        {
           "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=",
           "authentication": [
               {
                   "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                   "type": "Ed25519VerificationKey2020",
                   "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=",
                   "publicKeyMultibase": "zByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
               },
               {
                   "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=#6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
                   "type": "Ed25519VerificationKey2020",
                   "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=",
                   "publicKeyMultibase": "z3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J"
               }
           ],
           "keyAgreement": [
               {
                   "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=#6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                   "type": "X25519KeyAgreementKey2020",
                   "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=",
                   "publicKeyMultibase": "zJhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
               }
           ],
           "service": [
               {
                   "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=#didcommmessaging-0",
                   "type": "DIDCommMessaging",
                   "serviceEndpoint": "https://example.com/endpoint",
                   "routingKeys": [
                       "did:example:somemediator#somekey"
                   ],
                   "accept": [
                        "didcomm/v2", "didcomm/aip2;env=rfc587"
                   ]
               }
           ]
       }

## Assumptions and limitations
- Input keys are expected in `base58` format only
- Only `X25519` keys are support for key agreement
- Only `Ed25519` keys are support for authentication
- Supported verification materials in the resolved DID DOC:
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


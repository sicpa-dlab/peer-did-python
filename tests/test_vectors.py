PEER_DID_NUMALGO_0 = "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"

DID_DOC_NUMALGO_O_BASE58 = """
    {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "verificationMethod": [
            {
                "id": "#6MkqRYqQ",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "publicKeyBase58": "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
            }
        ],
        "authentication": ["#6MkqRYqQ"],
        "assertionMethod": ["#6MkqRYqQ"],
        "capabilityInvocation": ["#6MkqRYqQ"],
        "capabilityDelegation": ["#6MkqRYqQ"]
    }
    """

DID_DOC_NUMALGO_O_MULTIBASE = """
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
    """

DID_DOC_NUMALGO_O_JWK = """
    {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "verificationMethod": [
            {
                "id": "#6MkqRYqQ",
                "type": "JsonWebKey2020",
                "controller": "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA"
                }
            }
        ],
        "authentication": ["#6MkqRYqQ"],
        "assertionMethod": ["#6MkqRYqQ"],
        "capabilityInvocation": ["#6MkqRYqQ"],
        "capabilityDelegation": ["#6MkqRYqQ"]
    }
    """

PEER_DID_NUMALGO_2 = (
    "did:peer:2"
    + ".Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
    + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    + ".Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
    + ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
)

DID_DOC_NUMALGO_2_BASE58 = """
    {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
        "verificationMethod": [
            {
                "id": "#6LSbysY2",
                "type": "X25519KeyAgreementKey2019",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyBase58": "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
            },
            {
                "id": "#6MkqRYqQ",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyBase58": "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
            },
            {
                "id": "#6MkgoLTn",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyBase58": "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J"
            }
        ],
        "authentication": ["#6MkqRYqQ", "#6MkgoLTn"],
        "assertionMethod": ["#6MkqRYqQ", "#6MkgoLTn"],
        "keyAgreement": ["#6LSbysY2"],
        "capabilityInvocation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "capabilityDelegation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "service": [
            {
                "id": "#didcommmessaging-0",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"],
                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
            }
        ]
    }
    """

DID_DOC_NUMALGO_2_MULTIBASE = """
    {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/x25519-2020/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
        "verificationMethod": [
            {
                "id": "#6LSbysY2",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            },
            {
                "id": "#6MkqRYqQ",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            },
            {
                "id": "#6MkgoLTn",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyMultibase": "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            }
        ],
        "authentication": ["#6MkqRYqQ", "#6MkgoLTn"],
        "assertionMethod": ["#6MkqRYqQ", "#6MkgoLTn"],
        "keyAgreement": ["#6LSbysY2"],
        "capabilityInvocation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "capabilityDelegation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "service": [
            {
                "id": "#didcommmessaging-0",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
                "routingKeys": ["did:example:somemediator#somekey"]
            }
        ]
    }
    """

DID_DOC_NUMALGO_2_JWK = """
    {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
        "verificationMethod": [
            {
                "id": "#6LSbysY2",
                "type": "JsonWebKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik"
                }
            },
            {
                "id": "#6MkqRYqQ",
                "type": "JsonWebKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA"
                }
            },
            {
                "id": "#6MkgoLTn",
                "type": "JsonWebKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "Itv8B__b1-Jos3LCpUe8EdTFGTCa_Dza6_3848P3R70"
                }
            }
        ],
        "authentication": ["#6MkqRYqQ", "#6MkgoLTn"],
        "assertionMethod": ["#6MkqRYqQ", "#6MkgoLTn"],
        "keyAgreement": ["#6LSbysY2"],
        "capabilityInvocation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "capabilityDelegation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "service": [
            {
                "id": "#didcommmessaging-0",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint",
                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
                "routingKeys": ["did:example:somemediator#somekey"]
            }
        ]
    }
    """

PEER_DID_NUMALGO_2_2_SERVICES = (
    "did:peer:2"
    + ".Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
    + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    + ".SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfV0"
)

DID_DOC_NUMALGO_2_MULTIBASE_2_SERVICES = """
    {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/x25519-2020/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfV0",
        "verificationMethod": [
            {
                "id": "#6LSpSrLx",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfV0",
                "publicKeyMultibase": "z6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
            },
            {
                "id": "#6MkqRYqQ",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5Il19LHsidCI6ImV4YW1wbGUiLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludDIiLCJyIjpbImRpZDpleGFtcGxlOnNvbWVtZWRpYXRvciNzb21la2V5MiJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfV0",
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
                "serviceEndpoint": "https://example.com/endpoint",
                "routingKeys": ["did:example:somemediator#somekey"]
            },
            {
                "id": "#example-1",
                "type": "example",
                "serviceEndpoint": "https://example.com/endpoint2",
                "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
                "routingKeys": ["did:example:somemediator#somekey2"]
            }
        ]
    }
    """

PEER_DID_NUMALGO_2_NO_SERVICES = (
    "did:peer:2"
    + ".Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
    + ".Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
)

DID_DOC_NUMALGO_2_MULTIBASE_NO_SERVICES = """
    {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/x25519-2020/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        "verificationMethod": [
            {
                "id": "#6LSpSrLx",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "publicKeyMultibase": "z6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud"
            },
            {
                "id": "#6MkqRYqQ",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSpSrLxbAhg2SHwKk7kwpsH7DM7QjFS5iK6qP87eViohud.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            }
        ],
        "authentication": ["#6MkqRYqQ"],
        "assertionMethod": ["#6MkqRYqQ"],
        "keyAgreement": ["#6LSpSrLx"],
        "capabilityInvocation": ["#6MkqRYqQ"],
        "capabilityDelegation": ["#6MkqRYqQ"]
    }
    """

PEER_DID_NUMALGO_2_MINIMAL_SERVICES = "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9"

DID_DOC_NUMALGO_2_MULTIBASE_MINIMAL_SERVICES = """
    {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/x25519-2020/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
        "verificationMethod": [
            {
                "id": "#6LSbysY2",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
                "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            },
            {
                "id": "#6MkqRYqQ",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
                "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            },
            {
                "id": "#6MkgoLTn",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
                "publicKeyMultibase": "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            }
        ],
        "authentication": ["#6MkqRYqQ", "#6MkgoLTn"],
        "assertionMethod": ["#6MkqRYqQ", "#6MkgoLTn"],
        "keyAgreement": ["#6LSbysY2"],
        "capabilityInvocation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "capabilityDelegation": ["#6MkqRYqQ", "#6MkgoLTn"],
        "service": [
            {
                "id": "#didcommmessaging-0",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint"
            }
        ]
    }
    """

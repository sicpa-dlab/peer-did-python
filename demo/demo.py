"""Demo application."""

from peerdid.dids import (
    create_peer_did_numalgo_0,
    create_peer_did_numalgo_2,
    resolve_peer_did,
)
from peerdid.keys import Ed25519VerificationKey, X25519KeyAgreementKey


def demo():
    """Generate peer DIDs using both numalgo methods."""
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
    service = {
        "type": "DIDCommMessaging",
        "serviceEndpoint": "https://example.com/endpoint1",
        "routingKeys": ["did:example:somemediator#somekey1"],
        "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
    }

    peer_did_algo_0 = create_peer_did_numalgo_0(inception_key=signing_keys[0])
    peer_did_algo_2 = create_peer_did_numalgo_2(
        encryption_keys=encryption_keys, signing_keys=signing_keys, service=service
    )

    print("peer_did_algo_0:", peer_did_algo_0)
    print("==================================")
    print("peer_did_algo_2:", peer_did_algo_2)
    print("==================================")

    did_doc_algo_0 = resolve_peer_did(peer_did_algo_0)
    did_doc_algo_2 = resolve_peer_did(peer_did_algo_2)
    print("did_doc_algo_0 as JSON:", did_doc_algo_0.to_json())
    print("==================================")
    print("did_doc_algo_2 as JSON:", did_doc_algo_2.to_json())


if __name__ == "__main__":
    demo()

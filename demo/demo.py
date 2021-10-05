from peerdid.did_doc import DIDDocPeerDID
from peerdid.peer_did import (
    create_peer_did_numalgo_0,
    create_peer_did_numalgo_2,
    resolve_peer_did,
)
from peerdid.types import (
    VerificationMaterialAuthentication,
    VerificationMaterialAgreement,
    VerificationMethodTypeAgreement,
    VerificationMethodTypeAuthentication,
    VerificationMaterialFormat,
)


def demo():
    encryption_keys = [
        VerificationMaterialAgreement(
            type=VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
            format=VerificationMaterialFormat.BASE58,
            value="DmgBSHMqaZiYqwNMEJJuxWzsGGC8jUYADrfSdBrC6L8s",
        )
    ]
    signing_keys = [
        VerificationMaterialAuthentication(
            type=VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
            format=VerificationMaterialFormat.BASE58,
            value="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
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

    print("peer_did_algo_0:" + peer_did_algo_0)
    print("==================================")
    print("peer_did_algo_2:" + peer_did_algo_2)
    print("==================================")

    did_doc_algo_0_json = resolve_peer_did(peer_did=peer_did_algo_0)
    did_doc_algo_2_json = resolve_peer_did(peer_did=peer_did_algo_2)
    print("did_doc_algo_0 as JSON:" + did_doc_algo_0_json)
    print("==================================")
    print("did_doc_algo_2 as JSON:" + did_doc_algo_2_json)

    did_doc_algo_0 = DIDDocPeerDID.from_json(did_doc_algo_0_json)
    did_doc_algo_2 = DIDDocPeerDID.from_json(did_doc_algo_2_json)
    print("did_doc_algo_0 as object:" + str(did_doc_algo_0.to_dict()))
    print("==================================")
    print("did_doc_algo_2 as object:" + str(did_doc_algo_2.to_dict()))


if __name__ == "__main__":
    demo()

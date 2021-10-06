import json
from typing import List, Optional

from peerdid.core.did_doc_types import (
    VerificationMethodPeerDID,
    Service,
    DIDCommServicePeerDID,
)
from peerdid.errors import MalformedPeerDIDDocError
from peerdid.types import JSON


class DIDDocPeerDID:
    def __init__(
        self,
        did: str,
        authentication: List[VerificationMethodPeerDID],
        key_agreement: Optional[List[VerificationMethodPeerDID]] = None,
        service: Optional[List[Service]] = None,
    ):
        self.authentication = authentication
        self.did = did
        self.key_agreement = key_agreement
        self.service = service

    @property
    def auth_kids(self):
        return [v.id for v in self.authentication]

    @property
    def agreement_kids(self):
        return [v.id for v in self.key_agreement]

    def to_dict(self) -> dict:
        res = {
            "id": self.did,
            "authentication": [a.to_dict() for a in self.authentication],
        }
        if self.key_agreement is not None:
            res["keyAgreement"] = [ka.to_dict() for ka in self.key_agreement]
        if self.service is not None:
            res["service"] = self.service
        return res

    def to_json(self) -> JSON:
        return json.dumps(self.to_dict(), indent=4)

    @classmethod
    def from_json(cls, value: JSON):
        """
        Creates a new instance of DIDDocPeerDID from the given DID Doc JSON.
        :param value: DID doc as JSON
        :raises MalformedPeerDIDDocError: if the JSON can not be converted to a valid DID Doc object
        :return: a new instance of DIDDocPeerDID
        """
        try:
            did_doc_dict = json.loads(value)
        except Exception as e:
            raise MalformedPeerDIDDocError("Invalid JSON") from e

        if "id" not in did_doc_dict:
            raise MalformedPeerDIDDocError("No 'id' field")

        return cls(
            did=did_doc_dict["id"],
            authentication=[
                VerificationMethodPeerDID.from_dict(v)
                for v in did_doc_dict.get("authentication", [])
            ],
            key_agreement=[
                VerificationMethodPeerDID.from_dict(v)
                for v in did_doc_dict.get("keyAgreement", [])
            ],
            service=(
                [
                    DIDCommServicePeerDID.from_dict(v)
                    for v in did_doc_dict.get("service")
                ]
                if isinstance(did_doc_dict.get("service"), list)
                else did_doc_dict.get("service")
            ),
        )

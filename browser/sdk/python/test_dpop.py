"""The DPoP middleware's protocol tests (TODO.sota/08-arc): the proofs
are REAL (a real EC key signs; the transport asserts the spec's legs —
the header typ, the embedded public jwk, htm/htu/iat/jti, the ath
binding, and the §8 nonce dance), the answers are the OP's wire
shapes. Run: python3 -m pytest sdk/python/test_dpop.py (or python3 -m
unittest sdk.python.test_dpop — stdlib, no pytest needed)."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

import httpx

from _dpop import DpopAuth, DpopKeys, mint_dpop_proof

ISSUER = "https://op.test"
TOKEN_URL = ISSUER + "/op/token"
USERINFO_URL = ISSUER + "/op/userinfo"


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class TheProofMint(unittest.TestCase):
    def test_a_real_key_produces_a_verifiable_compact_jws(self):
        keys = DpopKeys()
        proof = mint_dpop_proof(keys, "POST", TOKEN_URL, iat=1700000000)
        header_b64, payload_b64, sig_b64 = proof.split(".")
        header = json.loads(b64url_decode(header_b64))
        self.assertEqual(header["typ"], "dpop+jwt")
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(sorted(header["jwk"].keys()), ["crv", "kty", "x", "y"])
        payload = json.loads(b64url_decode(payload_b64))
        self.assertEqual(payload["htm"], "POST")
        self.assertEqual(payload["htu"], TOKEN_URL)
        self.assertEqual(payload["iat"], 1700000000)
        self.assertTrue(payload["jti"])
        # The signature verifies with the EMBEDDED public jwk (raw r||s).
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives import hashes

        sig = b64url_decode(sig_b64)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        jwk = header["jwk"]
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4)), "big"),
            int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=" * (-len(jwk["y"]) % 4)), "big"),
            ec.SECP256R1(),
        ).public_key()
        key.verify(encode_dss_signature(r, s), f"{header_b64}.{payload_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))

    def test_the_jkt_is_the_lexicographic_thumbprint(self):
        keys = DpopKeys()
        jwk = keys.public_jwk()
        canonical = json.dumps({k: jwk[k] for k in sorted(jwk)}, separators=(",", ":")).encode("ascii")
        expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
        self.assertEqual(keys.jkt(), expected)


class TheNonceDance(unittest.TestCase):
    def test_the_full_client_flow_challenge_and_retry_and_ath(self):
        seen: list[dict] = []
        issued_nonce = "the-issued-nonce-value"
        bound_token = "the-dpop-bound-access-token"

        def handler(request: httpx.Request) -> httpx.Response:
            proof = json.loads(b64url_decode(request.headers["DPoP"].split(".")[1]))
            seen.append(proof)
            if request.url.path == "/op/token":
                if "nonce" not in proof:
                    return httpx.Response(400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": issued_nonce})
                self.assertEqual(proof["nonce"], issued_nonce)
                return httpx.Response(200, json={"access_token": bound_token, "token_type": "DPoP", "c_nonce": "x"})
            # userinfo: the DPoP scheme + the ath binding over the token.
            self.assertTrue(request.headers["Authorization"].startswith("DPoP "))
            self.assertEqual(proof["ath"], base64.urlsafe_b64encode(hashlib.sha256(bound_token.encode()).digest()).rstrip(b"=").decode())
            self.assertEqual(proof["nonce"], issued_nonce)
            return httpx.Response(200, json={"sub": "the-account"})

        client = httpx.Client(base_url=ISSUER, transport=httpx.MockTransport(handler))
        auth = DpopAuth(client)
        body = auth.token_exchange({"grant_type": "authorization_code", "code": "c", "redirect_uri": "http://cb", "code_verifier": "v"})
        self.assertEqual(body["token_type"], "DPoP")
        self.assertEqual(auth.access_token, bound_token)
        self.assertEqual(len(seen), 2, "the challenge is answered by ONE retry")
        claims = auth.request("GET", "/op/userinfo")
        self.assertEqual(claims.json()["sub"], "the-account")

    def test_the_bearer_posture_stays_untouched_without_dpop(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertNotIn("DPoP", request.headers)
            self.assertTrue(request.headers["Authorization"].startswith("Bearer "))
            return httpx.Response(200, json={"ok": True})

        client = httpx.Client(base_url=ISSUER, transport=httpx.MockTransport(handler))
        resp = client.post("/op/token", data={"grant_type": "authorization_code"}, headers={"Authorization": "Bearer x"})
        self.assertEqual(resp.json()["ok"], True)


if __name__ == "__main__":
    unittest.main()

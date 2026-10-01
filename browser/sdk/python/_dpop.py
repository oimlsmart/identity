"""TODO.sota/08-arc — the Python SDK's DPoP middleware (RFC 9449).

The holder-side half of the OP's sender-constrained tokens: the key
pair, the proof mint (compact ES256 JWS: typ dpop+jwt, the public jwk
in the header, { htm, htu, iat, jti, ath?, nonce? }), the RFC 7638
thumbprint, and the `DpopAuth` session — the token exchange (the proof
rides it; a DPoP-bound token comes back), the authenticated calls
(the DPoP scheme + the ath proof), and the §8 nonce dance (a
use_dpop_nonce challenge is answered by ONE retry carrying the issued
DPoP-Nonce value).

The cryptography package is an OPTIONAL extra (pip install
oiml-smart-identity[dpop]) — the base SDK's requirements are
untouched; importing this module without it raises the honest error.
"""
from __future__ import annotations

import base64
import json
import time
import uuid

try:
    import cryptography
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes
except ImportError as _e:  # pragma: no cover - the extra's honest error
    raise ImportError(
        "the DPoP support needs the 'cryptography' package — "
        "pip install oiml-smart-identity[dpop]"
    ) from _e

import httpx


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


class DpopKeys:
    """The client's DPoP key pair (an EC P-256 pair — the OP's house
    algorithm). Generate once, reuse for the session's whole life: the
    binding IS the key."""

    def __init__(self, private_key: "ec.EllipticCurvePrivateKey | None" = None):
        self._private = private_key or ec.generate_private_key(ec.SECP256R1())

    @property
    def private_key(self) -> "ec.EllipticCurvePrivateKey":
        return self._private

    def public_jwk(self) -> dict:
        """The PUBLIC JWK (kty/crv/x/y — never the private scalar)."""
        numbers = self._private.public_key().public_numbers()
        size = (numbers.x.bit_length() + 7) // 8 or 32
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }

    def jkt(self) -> str:
        """The key's thumbprint (the RFC 7638 members, lexicographic,
        SHA-256, base64url) — what the minted token binds to."""
        jwk = self.public_jwk()
        canonical = json.dumps({k: jwk[k] for k in sorted(jwk)}, separators=(",", ":"))
        digest = hashes.Hash(hashes.SHA256())
        digest.update(canonical.encode("ascii"))
        return _b64url(digest.finalize())


def mint_dpop_proof(
    keys: DpopKeys,
    method: str,
    url: str,
    access_token: str | None = None,
    nonce: str | None = None,
    iat: int | None = None,
) -> str:
    """The proof JWT (RFC 9449 §4): header { typ: dpop+jwt, alg: ES256,
    jwk }, payload { htm, htu, iat, jti, ath?, nonce? }; the ES256
    signature is the raw r||s (64 bytes) the spec pins."""
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": keys.public_jwk()}
    payload: dict = {
        "htm": method.upper(),
        "htu": url,
        "iat": iat if iat is not None else int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    if access_token is not None:
        payload["ath"] = _b64url(__import__("hashlib").sha256(access_token.encode("ascii")).digest())
    if nonce is not None:
        payload["nonce"] = nonce
    encoder = json.dumps(header, separators=(",", ":")), json.dumps(payload, separators=(",", ":"))
    unsigned = ".".join(_b64url(part.encode("ascii")) for part in encoder)
    der = keys.private_key.sign(unsigned.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{unsigned}.{_b64url(raw)}"


class DpopAuth:
    """The DPoP session over an IdentityClient: the token exchange (the
    proof rides it — the minted token binds to THESE keys), the
    authenticated calls (the DPoP scheme + the ath proof), and the §8
    nonce dance (one retry per challenge)."""

    def __init__(self, client: httpx.Client, keys: DpopKeys | None = None):
        self._client = client
        self.keys = keys or DpopKeys()
        self.access_token: str | None = None
        self.token_type: str | None = None
        self._nonce: str | None = None

    def _headers(self, method: str, url: str, access_token: str | None = None) -> dict:
        proof = mint_dpop_proof(self.keys, method, url, access_token=access_token, nonce=self._nonce)
        headers = {"DPoP": proof}
        if access_token is not None:
            headers["Authorization"] = f"DPoP {access_token}"
        return headers

    @staticmethod
    def _challenged(resp: httpx.Response) -> bool:
        return resp.status_code in (400, 401) and resp.json().get("error") == "use_dpop_nonce"

    def _absorb_nonce(self, resp: httpx.Response) -> None:
        issued = resp.headers.get("DPoP-Nonce")
        if issued:
            self._nonce = issued

    def token_exchange(self, data: dict) -> dict:
        """POST /op/token with the proof. A DPoP-bound answer stores the
        token for the authenticated calls; a challenge retries once with
        the issued nonce."""
        url = str(self._client.base_url).rstrip("/") + "/op/token"
        resp = self._client.post("/op/token", data=data, headers=self._headers("POST", url))
        if self._challenged(resp):
            self._absorb_nonce(resp)
            resp = self._client.post("/op/token", data=data, headers=self._headers("POST", url))
        resp.raise_for_status()
        body = resp.json()
        if str(body.get("token_type", "")).lower() == "dpop":
            self.access_token = body.get("access_token")
            self.token_type = "DPoP"
        return body

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """An authenticated call with the stored DPoP-bound token; the
        nonce dance rides every call."""
        if not self.access_token:
            raise RuntimeError("no DPoP-bound token — call token_exchange() first")
        absolute = url if url.startswith("http") else str(self._client.base_url).rstrip("/") + url
        resp = self._client.request(method, url, headers=self._headers(method.upper(), absolute, self.access_token), **kwargs)
        if self._challenged(resp):
            self._absorb_nonce(resp)
            resp = self._client.request(method, url, headers=self._headers(method.upper(), absolute, self.access_token), **kwargs)
        return resp

"""The typed models (auto-generated)."""
from dataclasses import dataclass
from typing import Optional, List, Any

@dataclass
class AccountProfile:
    id: str
    email: str
    name: str
    role: str

@dataclass
class DiscoveryDocument:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: Optional[str] = None
    jwks_uri: str
    id_token_signing_alg_values_supported: Optional[List[Any]] = None
    scopes_supported: Optional[List[Any]] = None

@dataclass
class Error:
    error: str

@dataclass
class JoinRequest:
    id: str
    name: str
    email: str
    orgId: Optional[str] = None
    requestedRole: Optional[str] = None
    status: str
    createdAt: str

@dataclass
class JwkSet:
    keys: List[Any]

@dataclass
class Organization:
    id: str
    name: str
    shortName: Optional[str] = None
    kind: str
    country: str
    roles: List[Any]

@dataclass
class SessionUser:
    id: str
    email: str
    name: str
    role: str
    orgId: Optional[str] = None
    avatarUrl: Optional[str] = None
    provider: Optional[str] = None

@dataclass
class TokenRow:
    id: str
    name: str
    prefix: str
    scopes: List[Any]
    permissions: List[Any]
    orgContext: Optional[str] = None
    createdAt: str
    expiresAt: str
    lastUsedAt: Optional[str] = None
    revokedAt: Optional[str] = None
    state: str

@dataclass
class TokensPayload:
    tokens: List[Any]
    services: List[Any]

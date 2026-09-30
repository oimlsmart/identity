"""The HTTP client (auto-generated from the OpenAPI spec).

Usage:
    from oiml_smart_identity import IdentityClient
    with IdentityClient() as client:
        health = client.apiHealth()
"""
import httpx


class IdentityClient:
    """The typed client for the OIML SMART Identity service."""

    def __init__(self, base_url: str = "https://id.oimlsmart.org", timeout: float = 30.0):
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        resp = self._client.request(method, path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def getDiscovery(self, **kwargs) -> dict:
        """The OIDC discovery document"""
        return self._request("GET", "/.well-known/openid-configuration", **kwargs)

    def getSecurityTxt(self, **kwargs) -> dict:
        """The vulnerability disclosure pointer (RFC 9116)"""
        return self._request("GET", "/.well-known/security.txt", **kwargs)

    def getWebfinger(self, **kwargs) -> dict:
        """The federation discovery front door (RFC 7033)"""
        return self._request("GET", "/.well-known/webfinger", **kwargs)

    def getSession(self, **kwargs) -> dict:
        """The session\'s user (or 401)"""
        return self._request("GET", "/api/auth/session", **kwargs)

    def getConfig(self, **kwargs) -> dict:
        """The instance\'s public posture (the branding, the provider flags)"""
        return self._request("GET", "/api/config", **kwargs)

    def getHealth(self, **kwargs) -> dict:
        """The liveness probe"""
        return self._request("GET", "/api/health", **kwargs)

    def getAccount(self, **kwargs) -> dict:
        """The account profile"""
        return self._request("GET", "/api/op/account", **kwargs)

    def listKnownDevices(self, **kwargs) -> dict:
        """The account\'s recognized devices (the risk signals)"""
        return self._request("GET", "/api/op/account/devices", **kwargs)

    def updateAccount(self, **kwargs) -> dict:
        """Update the profile (the name; the password change)"""
        return self._request("POST", "/api/op/account/profile", **kwargs)

    def listTokens(self, **kwargs) -> dict:
        """The registry + the picker\'s catalog"""
        return self._request("GET", "/api/op/account/tokens", **kwargs)

    def mintToken(self, **kwargs) -> dict:
        """Mint a token (the plaintext answers ONCE)"""
        return self._request("POST", "/api/op/account/tokens", **kwargs)

    def getTokenPermissionsCatalog(self, **kwargs) -> dict:
        """The mint picker\'s permissions catalog for one scoped service (TODO.openapi/03)"""
        return self._request("GET", "/api/op/account/tokens/catalog", **kwargs)

    def manageToken(self, **kwargs) -> dict:
        """The management act — rename, edit the scopes, edit the permissions (issue #115 + TODO.openapi/03)"""
        return self._request("PATCH", "/api/op/account/tokens/{id}", **kwargs)

    def revokeToken(self, **kwargs) -> dict:
        """Revoke the token (the row stays for the audit)"""
        return self._request("DELETE", "/api/op/account/tokens/{id}", **kwargs)

    def listWebhookSubscriptions(self, **kwargs) -> dict:
        """The account\'s LIVE event subscriptions"""
        return self._request("GET", "/api/op/account/webhooks", **kwargs)

    def createWebhookSubscription(self, **kwargs) -> dict:
        """Subscribe an endpoint (the secret answers ONCE)"""
        return self._request("POST", "/api/op/account/webhooks", **kwargs)

    def listWebhookDeliveries(self, **kwargs) -> dict:
        """The account\'s delivery log (newest first)"""
        return self._request("GET", "/api/op/account/webhooks/deliveries", **kwargs)

    def revokeWebhookSubscription(self, **kwargs) -> dict:
        """Unsubscribe (the owner\'s guarded deactivation)"""
        return self._request("DELETE", "/api/op/account/webhooks/{id}", **kwargs)

    def fileJoinRequest(self, **kwargs) -> dict:
        """File the account request (public, rate-bounded)"""
        return self._request("POST", "/api/op/join-requests", **kwargs)

    def listOrganizations(self, **kwargs) -> dict:
        """The join-flow register (public)"""
        return self._request("GET", "/api/op/organizations", **kwargs)

    def selfRegisterCatalog(self, **kwargs) -> dict:
        """The member-domains projection (the pickers)"""
        return self._request("GET", "/api/op/self-register/catalog", **kwargs)

    def selfRegisterComplete(self, **kwargs) -> dict:
        """Complete the verified enrollment (the flow\'s only creation)"""
        return self._request("POST", "/api/op/self-register/complete", **kwargs)

    def selfRegisterSecondProof(self, **kwargs) -> dict:
        """The second verification\'s provider handoff (the setup step)"""
        return self._request("GET", "/api/op/self-register/second-proof", **kwargs)

    def selfRegisterStart(self, **kwargs) -> dict:
        """Start the member self-enrollment (public, the eligibility reads)"""
        return self._request("POST", "/api/op/self-register/start", **kwargs)

    def selfRegisterVerify(self, **kwargs) -> dict:
        """Prove the emailed registration token (the setup page\'s on-load)"""
        return self._request("POST", "/api/op/self-register/verify", **kwargs)

    def accountStepUp(self, **kwargs) -> dict:
        """Mint the fresh-proof stamp (TODO.sota/06)"""
        return self._request("POST", "/api/op/step-up", **kwargs)

    def redeliverDeadWebhooks(self, **kwargs) -> dict:
        """The dead-letter redelivery pass (the scheduled workflow\'s caller)"""
        return self._request("POST", "/api/op/webhooks/redeliver", **kwargs)

    def getOpenApi(self, **kwargs) -> dict:
        """This document (the OpenAPI 3.1 specification)"""
        return self._request("GET", "/api/openapi.json", **kwargs)

    def getJwks(self, **kwargs) -> dict:
        """The OP\'s public key set"""
        return self._request("GET", "/jwks.json", **kwargs)

    def deviceAuthorization(self, **kwargs) -> dict:
        """The device authorization (RFC 8628 §3.1–3.2)"""
        return self._request("POST", "/op/device/authorization", **kwargs)

    def introspectToken(self, **kwargs) -> dict:
        """The token-standing read (RFC 7662)"""
        return self._request("POST", "/op/introspect", **kwargs)

    def getOrgKeys(self, **kwargs) -> dict:
        """An organization\'s public signing keys"""
        return self._request("GET", "/op/keys/{file}", **kwargs)

    def pushAuthorizationRequest(self, **kwargs) -> dict:
        """The pushed authorization request (RFC 9126)"""
        return self._request("POST", "/op/par", **kwargs)

    def revokeToken(self, **kwargs) -> dict:
        """The revocation (RFC 7009)"""
        return self._request("POST", "/op/revoke", **kwargs)

    def getSessionCheck(self, **kwargs) -> dict:
        """The session-management poll iframe"""
        return self._request("GET", "/op/session/check", **kwargs)

    def getSessionState(self, **kwargs) -> dict:
        """The live session_state digest (the poll\'s recomputation)"""
        return self._request("GET", "/op/session/state", **kwargs)

    def exchangeToken(self, **kwargs) -> dict:
        """The token endpoint — the grants, incl. the PAT exchange"""
        return self._request("POST", "/op/token", **kwargs)

    def getUserinfo(self, **kwargs) -> dict:
        """The userinfo"""
        return self._request("GET", "/op/userinfo", **kwargs)

    def getRobotsTxt(self, **kwargs) -> dict:
        """The crawler front door"""
        return self._request("GET", "/robots.txt", **kwargs)

    def scimListGroups(self, **kwargs) -> dict:
        """The group list (RFC 7644 §4.2)"""
        return self._request("GET", "/scim/v2/Groups", **kwargs)

    def scimCreateGroup(self, **kwargs) -> dict:
        """Create the group"""
        return self._request("POST", "/scim/v2/Groups", **kwargs)

    def scimGetGroup(self, **kwargs) -> dict:
        """The group projection"""
        return self._request("GET", "/scim/v2/Groups/{id}", **kwargs)

    def scimReplaceGroup(self, **kwargs) -> dict:
        """Replace wholesale (displayName + members)"""
        return self._request("PUT", "/scim/v2/Groups/{id}", **kwargs)

    def scimPatchGroup(self, **kwargs) -> dict:
        """The incremental update (RFC 7644 §3.5.2)"""
        return self._request("PATCH", "/scim/v2/Groups/{id}", **kwargs)

    def scimDeleteGroup(self, **kwargs) -> dict:
        """Delete the group (the tombstone keeps the history)"""
        return self._request("DELETE", "/scim/v2/Groups/{id}", **kwargs)

    def scimListUsers(self, **kwargs) -> dict:
        """The provisioning list (RFC 7644 §3.4.2)"""
        return self._request("GET", "/scim/v2/Users", **kwargs)

    def scimCreateUser(self, **kwargs) -> dict:
        """Provision the invited account (RFC 7644 §3.3)"""
        return self._request("POST", "/scim/v2/Users", **kwargs)

    def scimGetUser(self, **kwargs) -> dict:
        """The projection (RFC 7644 §3.4.1)"""
        return self._request("GET", "/scim/v2/Users/{id}", **kwargs)

    def scimPatchUser(self, **kwargs) -> dict:
        """The update — the active replace (RFC 7644 §3.5.2)"""
        return self._request("PATCH", "/scim/v2/Users/{id}", **kwargs)

    def scimDeleteUser(self, **kwargs) -> dict:
        """Deactivate — never the erase (RFC 7644 §3.6)"""
        return self._request("DELETE", "/scim/v2/Users/{id}", **kwargs)


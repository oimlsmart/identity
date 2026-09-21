// ═══════════════════════════════════════════════════════════════════
// The identity service's OpenAPI 3.1 specification — EDITION 1.
//
// This object IS the contract: the router serves it at
// GET /api/openapi.json (worker-safe: pure data, no file reads), and
// the gate (id-openapi-contract.test.ts) proves it against the LIVE
// Hono route table in BOTH directions — every documented operation
// exists on the app, and every app route outside the declared
// edition-1 exclusions is documented. A route that drifts fails CI
// with its name.
//
// EDITION 1 covers the surfaces a consumer integrates against first:
//   - the public OIDC machine surface (discovery, JWKS, the org keys,
//     the token endpoint with the RFC 8693 PAT exchange, introspect,
//     revoke, userinfo);
//   - the instance's public facts (health, config) and the join
//     intake (the organizations register, the join-request filing);
//   - the session-authenticated self-service API (the session read,
//     the account profile, the personal access tokens' full
//     lifecycle incl. the issue-#115 management acts).
//
// EDITION 2 (declared, not yet here): the administration surface
// (dashboard, registry, memberships, accounts, clients, providers,
// org-keys, endorsements) and the interactive OIDC legs (authorize,
// end-session) that belong to browser flows, not API clients.
// ═══════════════════════════════════════════════════════════════════

export const OPENAPI_SPEC = {
  openapi: '3.1.0',
  info: {
    title: 'OIML SMART Identity API',
    version: '1.0.0-edition1',
    summary: 'The OpenID Connect Provider and account API of the OIML SMART register.',
    description:
      'The identity service (id.oimlsmart.org) is the register\'s OpenID Connect Provider. '
      + 'This edition documents the machine-facing surface: the OIDC endpoints a relying party integrates, '
      + 'the public join intake, and the session-authenticated self-service API every account owns. '
      + 'The interactive browser legs (authorize, end-session) follow the OIDC/Browser flows — link them from the discovery document — '
      + 'and the administration surface lands in edition 2.',
  },
  servers: [
    { url: 'https://id.oimlsmart.org', description: 'Production' },
  ],
  tags: [
    { name: 'OIDC', description: 'The OpenID Connect surface every relying party integrates: discovery, the key set, the token endpoint (incl. the RFC 8693 personal-access-token exchange), introspection, revocation, userinfo.' },
    { name: 'Instance', description: 'The instance\'s public facts and posture.' },
    { name: 'Join', description: 'The public account-request intake: the organizations register and the join-request filing.' },
    { name: 'Session', description: 'The session-authenticated account surface (the `oiml-session` cookie a console sign-in sets).' },
    { name: 'Tokens', description: 'The personal access tokens a account mints, manages and revokes — the machine credential for the register\'s services.' },
    { name: 'Webhooks', description: 'The account\'s outbound event subscriptions — HMAC-signed deliveries (TODO.modern/08).' },
    { name: 'SCIM', description: 'The SCIM 2.0 provisioning surface (RFC 7644) — the enterprise lifecycle on the existing account model (TODO.modern/05; the SCIM_BEARER_TOKEN arms it).' },
  ],
  components: {
    securitySchemes: {
      scimBearer: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'SCIM_BEARER_TOKEN',
        description: 'The dedicated SCIM connector token (a Worker secret; unset = the surface answers 404 entirely).',
      },
      redeliveryBearer: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'WEBHOOK_REDELIVERY_TOKEN',
        description: 'The dead-letter redelivery pass\'s caller token (a Worker secret; unset = the endpoint answers 404 entirely).',
      },
      sessionCookie: {
        type: 'apiKey',
        in: 'cookie',
        name: 'oiml-session',
        description: 'The console session (a sign-in sets it; 7-day life; same-origin).',
      },
      bearerToken: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'The OP-issued access token (the RFC 8693 exchange\'s answer).',
      },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: { error: { type: 'string', description: 'The human-readable refusal.' } },
        required: ['error'],
        additionalProperties: false,
      },
      Organization: {
        type: 'object',
        description: 'A register entry the join flow admits (an active participant or OIML member org).',
        properties: {
          id: { type: 'string', example: 'ms-al' },
          name: { type: 'string', example: 'Albania' },
          shortName: { type: 'string', example: 'AL' },
          kind: { type: 'string', example: 'member-state' },
          country: { type: 'string', example: 'Albania' },
          roles: { type: 'array', items: { type: 'string' }, example: ['viewer'] },
        },
        required: ['id', 'name', 'kind', 'country', 'roles'],
      },
      JoinRequest: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'Dana Example' },
          email: { type: 'string', format: 'email', example: 'dana@example.org' },
          orgId: { type: 'string', example: 'ms-al' },
          requestedRole: { type: 'string', example: 'viewer' },
          status: { type: 'string', enum: ['pending'] },
          createdAt: { type: 'string', format: 'date-time' },
        },
        required: ['id', 'name', 'email', 'status', 'createdAt'],
      },
      SessionUser: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          email: { type: 'string', format: 'email' },
          name: { type: 'string' },
          role: { type: 'string', example: 'viewer' },
          orgId: { type: ['string', 'null'] },
          avatarUrl: { type: ['string', 'null'] },
          provider: { type: 'string', example: 'password' },
        },
        required: ['id', 'email', 'name', 'role'],
      },
      AccountProfile: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          email: { type: 'string', format: 'email' },
          name: { type: 'string' },
          role: { type: 'string' },
        },
        required: ['id', 'email', 'name', 'role'],
      },
      TokenRow: {
        type: 'object',
        description: 'A personal access token\'s metadata — never the plaintext (that answers exactly once, at mint).',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'the lab CLI' },
          prefix: { type: 'string', example: 'ospt_9xYz12', description: 'The display prefix (the first 13 characters).' },
          scopes: { type: 'array', items: { type: 'string' }, example: ['hub-instance:write'] },
          permissions: {
            type: 'array',
            items: { type: 'string' },
            description: 'The pinned permissions-catalog ids (TODO.openapi/03) — the TARGET INSTANCE\'s own `<group>.<resource>.<verb>` ids, validated at mint against the instance\'s served catalog and echoed verbatim at introspection. The OP never holds a copy of the catalog.',
            example: ['tl-workbench.runs.read'],
          },
          orgContext: { type: ['string', 'null'] },
          createdAt: { type: 'string', format: 'date-time' },
          expiresAt: { type: 'string', format: 'date-time' },
          lastUsedAt: { type: ['string', 'null'], format: 'date-time' },
          revokedAt: { type: ['string', 'null'], format: 'date-time' },
          state: { type: 'string', enum: ['active', 'expired', 'revoked'] },
        },
        required: ['id', 'name', 'prefix', 'scopes', 'permissions', 'createdAt', 'expiresAt', 'state'],
      },
      TokensPayload: {
        type: 'object',
        properties: {
          tokens: { type: 'array', items: { $ref: '#/components/schemas/TokenRow' } },
          services: {
            type: 'array',
            description: 'The picker\'s catalog: the services the account may mint for, each with the widest action class its standing admits.',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string', example: 'hub-instance' },
                name: { type: 'string', example: 'OIML SMART platform hub' },
                maxAction: { type: 'string', enum: ['read', 'write', 'admin'] },
              },
              required: ['id', 'name', 'maxAction'],
            },
          },
        },
        required: ['tokens', 'services'],
      },
      DiscoveryDocument: {
        type: 'object',
        description: 'The OP\'s OIDC discovery document (the OIDC Discovery spec\'s shape).',
        properties: {
          issuer: { type: 'string', format: 'uri' },
          authorization_endpoint: { type: 'string', format: 'uri' },
          token_endpoint: { type: 'string', format: 'uri' },
          userinfo_endpoint: { type: 'string', format: 'uri' },
          jwks_uri: { type: 'string', format: 'uri' },
          id_token_signing_alg_values_supported: { type: 'array', items: { type: 'string' } },
          scopes_supported: { type: 'array', items: { type: 'string' } },
        },
        required: ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'],
      },
      JwkSet: {
        type: 'object',
        properties: {
          keys: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                kty: { type: 'string', example: 'EC' },
                crv: { type: 'string', example: 'P-256' },
                kid: { type: 'string' },
                alg: { type: 'string', example: 'ES256' },
                use: { type: 'string', example: 'sig' },
              },
            },
          },
        },
        required: ['keys'],
      },
    },
  },
  paths: {
    '/.well-known/openid-configuration': {
      get: {
        tags: ['OIDC'], operationId: 'getDiscovery', summary: 'The OIDC discovery document',
        security: [],
        responses: {
          200: {
            description: 'The discovery document.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/DiscoveryDocument' } } },
          },
        },
      },
    },
    '/jwks.json': {
      get: {
        tags: ['OIDC'], operationId: 'getJwks', summary: 'The OP\'s public key set',
        security: [],
        responses: {
          200: {
            description: 'The registered key table (the JWK Set).',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/JwkSet' } } },
          },
        },
      },
    },
    '/op/keys/{file}': {
      get: {
        tags: ['OIDC'], operationId: 'getOrgKeys', summary: 'An organization\'s public signing keys',
        description: 'The org-account signing keys\' public halves — the registry custody stamps ride along. Anonymous, replayable, short max-age.',
        security: [],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'The org\'s JWK Set.', content: { 'application/json': { schema: { $ref: '#/components/schemas/JwkSet' } } } },
          404: { description: 'No such organization.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/op/token': {
      post: {
        tags: ['OIDC'], operationId: 'exchangeToken', summary: 'The token endpoint — the grants, incl. the PAT exchange',
        description:
          'The OIDC token endpoint. The machine grant is the RFC 8693 token exchange: '
          + '`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with '
          + '`subject_token_type=urn:oimlsmart:params:oauth:token-type:pat` and the personal access token as '
          + '`subject_token` — answering a short-lived, scope-narrowed OP JWT. '
          + 'The token\'s scopes are re-judged against the holder\'s LIVE standing at every exchange.',
        security: [],
        requestBody: {
          required: true,
          content: {
            'application/x-www-form-urlencoded': {
              schema: {
                type: 'object',
                properties: {
                  grant_type: { type: 'string', example: 'urn:ietf:params:oauth:grant-type:token-exchange' },
                  subject_token_type: { type: 'string', example: 'urn:oimlsmart:params:oauth:token-type:pat' },
                  subject_token: { type: 'string', example: 'ospt_…' },
                  scope: { type: 'string', description: 'A per-exchange narrowing (never a widening).', example: 'openid profile' },
                },
                required: ['grant_type'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'The exchanged access token (an OP JWT; verify against the JWKS).',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    access_token: { type: 'string' },
                    issued_token_type: { type: 'string' },
                    token_type: { type: 'string', example: 'N_A' },
                    expires_in: { type: 'integer' },
                    scope: { type: 'string' },
                  },
                  required: ['access_token'],
                },
              },
            },
          },
          400: { description: 'The ONE refusal: invalid_grant (unknown / expired / revoked / wrong-standing — never a distinction).', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/op/introspect': {
      post: {
        tags: ['OIDC'], operationId: 'introspectToken', summary: 'The token-standing read (RFC 7662)',
        description:
          'Answers active + the claim set for a live OP-issued access token, and { active: false } for everything else. '
          + 'The token classes: the opaque access tokens (the table read), the self-contained machine JWTs (the signature + the named client\'s live standing), '
          + 'and the RAW personal access tokens (TODO.openapi/03 — the platform\'s per-request enforcement read: a live PAT answers active with '
          + 'iss/sub/scope/permissions/service_roles/org/cone/pat/token_type=access_token/exp, all of it the LIVE judgment; revoked, expired, or standing-lost reads inactive). '
          + 'Never an error for an unknown token.',
        security: [{ bearerToken: [] }, { sessionCookie: [] }],
        requestBody: { required: true, content: { 'application/x-www-form-urlencoded': { schema: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] } } } },
        responses: { 200: { description: 'The token\'s standing (active or not — never an error for an unknown token).' } },
      },
    },
    '/op/revoke': {
      post: {
        tags: ['OIDC'], operationId: 'revokeToken', summary: 'The revocation (RFC 7009)',
        security: [{ bearerToken: [] }, { sessionCookie: [] }],
        requestBody: { required: true, content: { 'application/x-www-form-urlencoded': { schema: { type: 'object', properties: { token: { type: 'string' } }, required: ['token'] } } } },
        responses: { 200: { description: 'The uniform 200 (an unknown token revokes nothing, silently — the RFC\'s posture).' } },
      },
    },
    '/op/userinfo': {
      get: {
        tags: ['OIDC'], operationId: 'getUserinfo', summary: 'The userinfo',
        security: [{ bearerToken: [] }],
        responses: {
          200: { description: 'The subject\'s claims (sub, and the scopes\' claims).' },
          401: { description: 'No or invalid token.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/.well-known/webfinger': {
      get: {
        tags: ['OIDC'], operationId: 'getWebfinger', summary: 'The federation discovery front door (RFC 7033)',
        description:
          'An RP holding an email address discovers the issuer with zero configuration: '
          + '`resource=acct:<local>@<this host>` (or the mailto form) answers the JRD with the '
          + '`http://openid.net/specs/connect/1.0/issuer` link. The DOMAIN decides — any local part answers '
          + '(the mailbox is never probed; enumeration-safe by construction); a foreign domain answers 404 '
          + '(never a proxy, never an open resolver).',
        security: [],
        parameters: [{ name: 'resource', in: 'query', required: true, schema: { type: 'string' }, example: 'acct:ada@id.oimlsmart.org' }],
        responses: {
          200: { description: 'The JRD (application/jrd+json), edge-cached 5 minutes.', content: { 'application/jrd+json': { schema: { type: 'object', properties: { subject: { type: 'string' }, links: { type: 'array', items: { type: 'object' } } }, required: ['subject', 'links'] } } } },
          400: { description: 'The resource parameter is absent.' },
          404: { description: 'The resource names another domain.' },
        },
      },
    },
    '/.well-known/security.txt': {
      get: {
        tags: ['OIDC'], operationId: 'getSecurityTxt', summary: 'The vulnerability disclosure pointer (RFC 9116)',
        description:
          'The disclosure contact (the repository\'s private security advisories — the real, monitored channel), the expiry, the preferred languages, and the policy pointer. Refreshed at the yearly deploy review.',
        security: [],
        responses: {
          200: { description: 'The security.txt document (text/plain).', content: { 'text/plain': { schema: { type: 'string' } } } },
        },
      },
    },
    '/op/par': {
      post: {
        tags: ['OIDC'], operationId: 'pushAuthorizationRequest', summary: 'The pushed authorization request (RFC 9126)',
        description:
          'The FAPI-class posture: the authorize parameter set posted to the back channel (the token endpoint\'s own client authentication — Basic or post), '
          + 'the browser redirect carrying only the request_uri. The pushed parameters REPLACE the query\'s at the authorize (any other query parameter is '
          + 'ignored, never merged); the request_uri is SINGLE-USE, lives 90 seconds, and is client-bound (a query client_id must match the owner). The '
          + 'redirect wall applies AT PUSH TIME — an unregistered redirect_uri refuses before anything is stored.',
        security: [],
        requestBody: {
          required: true,
          content: {
            'application/x-www-form-urlencoded': {
              schema: {
                type: 'object',
                properties: {
                  response_type: { type: 'string', enum: ['code'] },
                  redirect_uri: { type: 'string', format: 'uri' },
                  scope: { type: 'string' },
                  state: { type: 'string' },
                  nonce: { type: 'string' },
                  code_challenge: { type: 'string' },
                  code_challenge_method: { type: 'string', enum: ['S256'] },
                  prompt: { type: 'string' },
                  max_age: { type: 'string', pattern: '^\\d+$' },
                },
                required: ['response_type', 'redirect_uri', 'scope', 'code_challenge', 'code_challenge_method'],
              },
            },
          },
        },
        responses: {
          201: {
            description: 'The pushed request\'s reference.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    request_uri: { type: 'string', pattern: '^urn:ietf:params:oauth:request_uri:' },
                    expires_in: { type: 'integer', example: 90 },
                  },
                  required: ['request_uri', 'expires_in'],
                },
              },
            },
          },
          400: { description: 'An unregistered redirect_uri, or a machine-class client.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'The client authentication refused.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/op/session/check': {
      get: {
        tags: ['OIDC'], operationId: 'getSessionCheck', summary: 'The session-management poll iframe',
        description:
          'The OIDC Session Management iframe (discoverable via check_session_iframe). The relying party embeds it, '
          + 'posts `client_id=…&session_state=…` at it, and it answers `unchanged`/`changed` via postMessage — '
          + 'the recomputation runs server-side per poll against the live session; any failure answers changed (fail-closed).',
        security: [],
        parameters: [{ name: 'client_id', in: 'query', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'The iframe page (HTML, frameable by any RP origin).', content: { 'text/html': { schema: { type: 'string' } } } },
          400: { description: 'The request names no client_id.', content: { 'text/html': { schema: { type: 'string' } } } },
        },
      },
    },
    '/op/session/state': {
      get: {
        tags: ['OIDC'], operationId: 'getSessionState', summary: 'The live session_state digest (the poll\'s recomputation)',
        description:
          'The session_state for (client_id, origin, the request\'s live session) — the value the check iframe compares '
          + 'the relying party\'s against. The authorize answer (authorization code + state) carries the same digest as '
          + '`session_state`. 401 = the session is gone = the honest changed.',
        security: [{ sessionCookie: [] }],
        parameters: [
          { name: 'client_id', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'origin', in: 'query', required: true, schema: { type: 'string', format: 'uri' } },
        ],
        responses: {
          200: {
            description: 'The digest.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { session_state: { type: 'string', description: 'base64url of SHA-256(client_id + " " + origin + " " + session token)' } },
                  required: ['session_state'],
                },
              },
            },
          },
          400: { description: 'Missing client_id or origin.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'No live session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/health': {
      get: {
        tags: ['Instance'], operationId: 'getHealth', summary: 'The liveness probe', security: [],
        responses: { 200: { description: 'The instance answers.' } },
      },
    },
    '/api/config': {
      get: {
        tags: ['Instance'], operationId: 'getConfig', summary: 'The instance\'s public posture (the branding, the provider flags)', security: [],
        responses: { 200: { description: 'The posture object.' } },
      },
    },
    '/api/openapi.json': {
      get: {
        tags: ['Instance'], operationId: 'getOpenApi', summary: 'This document (the OpenAPI 3.1 specification)',
        description: 'The machine-consumable contract this reference renders — the drift-gated source of truth (every documented operation exists on the app; every app route outside the declared exclusions is documented).',
        security: [],
        responses: {
          200: {
            description: 'The OpenAPI 3.1 document.',
            content: { 'application/json': { schema: { type: 'object' } } },
          },
        },
      },
    },
    '/api/op/organizations': {
      get: {
        tags: ['Join'], operationId: 'listOrganizations', summary: 'The join-flow register (public)',
        description: 'The registered participant orgs plus the active OIML member orgs, each with the roles its kind bounds — the join page\'s selector feed. Public scheme data; edge-cached (5-minute freshness).',
        security: [],
        responses: {
          200: {
            description: 'The register.',
            content: { 'application/json': { schema: { type: 'array', items: { $ref: '#/components/schemas/Organization' } } } },
          },
        },
      },
    },
    '/api/op/join-requests': {
      post: {
        tags: ['Join'], operationId: 'fileJoinRequest', summary: 'File the account request (public, rate-bounded)',
        description: 'The public submit: name, work email, the org (from the register) + the role asked for — or the not-listed path (a free-text org name, lands with BIML). One PENDING request per email; no account exists before the enrollment ceremony proves the mailbox.',
        security: [],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'Dana Example' },
                  email: { type: 'string', format: 'email', example: 'dana@example.org' },
                  org_id: { type: 'string', example: 'ms-al' },
                  requested_role: { type: 'string', example: 'viewer' },
                  note: { type: 'string' },
                },
                required: ['name', 'email'],
              },
              examples: {
                registryPath: { summary: 'The registry path', value: { name: 'Dana Example', email: 'dana@example.org', org_id: 'ms-al', requested_role: 'viewer' } },
                notListedPath: { summary: 'The not-listed path (BIML verifies participation)', value: { name: 'Dana Example', email: 'dana@example.org', org_name_text: 'Dana Instruments Co' } },
              },
            },
          },
        },
        responses: {
          201: { description: 'The request files (pending).', content: { 'application/json': { schema: { $ref: '#/components/schemas/JoinRequest' } } } },
          400: { description: 'Malformed, or the org/role refuses.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          409: { description: 'A request from this email is already waiting.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          429: { description: 'The rate bound (the anonymous intake\'s row-count bound).', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/auth/session': {
      get: {
        tags: ['Session'], operationId: 'getSession', summary: 'The session\'s user (or 401)',
        security: [{ sessionCookie: [] }],
        responses: {
          200: { description: 'The signed-in user.', content: { 'application/json': { schema: { $ref: '#/components/schemas/SessionUser' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account': {
      get: {
        tags: ['Session'], operationId: 'getAccount', summary: 'The account profile',
        security: [{ sessionCookie: [] }],
        responses: {
          200: { description: 'The profile.', content: { 'application/json': { schema: { $ref: '#/components/schemas/AccountProfile' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account/profile': {
      post: {
        tags: ['Session'], operationId: 'updateAccount', summary: 'Update the profile (the name; the password change)',
        security: [{ sessionCookie: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, currentPassword: { type: 'string' }, newPassword: { type: 'string' } } } } } },
        responses: {
          200: { description: 'The updated profile.', content: { 'application/json': { schema: { $ref: '#/components/schemas/AccountProfile' } } } },
          400: { description: 'The change refuses (the policy, the current password).', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account/devices': {
      get: {
        tags: ['Account'], operationId: 'listKnownDevices', summary: 'The account\'s recognized devices (the risk signals)',
        description:
          'The known-device record (TODO.modern/06): one row per (account, SHA-256(UA + IP)) with the first/last sighting and countries. '
          + 'The IP is MASKED (the IPv4\'s last octet folds to *; a non-IPv4 address answers null — never a raw identifier). The sign-in '
          + 'audit\'s newDevice/countryChanged advisories derive from the same record.',
        security: [{ sessionCookie: [] }],
        responses: {
          200: { description: 'The devices, newest sighting first.' },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/scim/v2/Users': {
      get: {
        tags: ['SCIM'], operationId: 'scimListUsers', summary: 'The provisioning list (RFC 7644 §3.4.2)',
        description:
          'Pagination (startIndex, count ≤ 200) + the ONE supported filter: `filter=userName eq "<email>"` — anything else refuses '
          + '`400 scimType=invalid_filter` (never a silent mis-answer). Erased accounts never appear.',
        security: [{ scimBearer: [] }],
        parameters: [
          { name: 'filter', in: 'query', schema: { type: 'string' }, example: 'userName eq "person@example.org"' },
          { name: 'startIndex', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
          { name: 'count', in: 'query', schema: { type: 'integer', minimum: 0, maximum: 200, default: 100 } },
        ],
        responses: {
          200: { description: 'The ListResponse (totalResults, Resources).', content: { 'application/json': { schema: { type: 'object', properties: { schemas: { type: 'array', items: { type: 'string' } }, totalResults: { type: 'integer' }, startIndex: { type: 'integer' }, itemsPerPage: { type: 'integer' }, Resources: { type: 'array', items: { type: 'object' } } }, required: ['totalResults', 'Resources'] } } } },
          400: { description: 'An unsupported filter (scimType=invalid_filter).' },
          401: { description: 'The SCIM bearer token is required.' },
        },
      },
      post: {
        tags: ['SCIM'], operationId: 'scimCreateUser', summary: 'Provision the invited account (RFC 7644 §3.3)',
        description:
          'userName IS the account\'s email. The create maps onto the EXISTING account model: the account row (role viewer) + the '
          + 'one-time enrollment setup link (emailed when a provider is configured — best-effort, never blocking; the console\'s resend '
          + 'stands behind it). A duplicate userName refuses 409.',
        security: [{ scimBearer: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  schemas: { type: 'array', items: { type: 'string' } },
                  userName: { type: 'string', format: 'email' },
                  name: { type: 'object', properties: { givenName: { type: 'string' }, familyName: { type: 'string' } } },
                  active: { type: 'boolean' },
                },
                required: ['userName'],
              },
            },
          },
        },
        responses: {
          201: { description: 'The provisioned user (Location rides).' },
          400: { description: 'userName missing or not an address.' },
          401: { description: 'The SCIM bearer token is required.' },
          409: { description: 'An account already exists for the address.' },
        },
      },
    },
    '/scim/v2/Users/{id}': {
      get: {
        tags: ['SCIM'], operationId: 'scimGetUser', summary: 'The projection (RFC 7644 §3.4.1)',
        security: [{ scimBearer: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'The user resource.' },
          404: { description: 'No such user (the RFC Error schema).' },
          401: { description: 'The SCIM bearer token is required.' },
        },
      },
      patch: {
        tags: ['SCIM'], operationId: 'scimPatchUser', summary: 'The update — the active replace (RFC 7644 §3.5.2)',
        description:
          'The supported act: `replace active` (pathful or the pathless value form). `active=false` is the HONEST disable — every '
          + 'session of the account dies with it; the row stays. Anything else refuses `400 scimType=invalidPath`.',
        security: [{ scimBearer: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  schemas: { type: 'array', items: { type: 'string' } },
                  Operations: { type: 'array', items: { type: 'object', properties: { op: { type: 'string', enum: ['replace'] }, path: { type: 'string', enum: ['active'] }, value: {} } } },
                },
                required: ['Operations'],
              },
            },
          },
        },
        responses: {
          200: { description: 'The updated user.' },
          400: { description: 'An unsupported operation (scimType=invalidPath).' },
          404: { description: 'No such user.' },
          401: { description: 'The SCIM bearer token is required.' },
        },
      },
      delete: {
        tags: ['SCIM'], operationId: 'scimDeleteUser', summary: 'Deactivate — never the erase (RFC 7644 §3.6)',
        description:
          'The deprovision: active=false + the sessions die. The account row NEVER erases (the audit + the history keep it; the erase is the console\'s own sovereign act).',
        security: [{ scimBearer: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          204: { description: 'Deactivated.' },
          404: { description: 'No such user.' },
          401: { description: 'The SCIM bearer token is required.' },
        },
      },
    },
    '/api/op/account/webhooks': {
      get: {
        tags: ['Webhooks'], operationId: 'listWebhookSubscriptions', summary: 'The account\'s LIVE event subscriptions',
        description: 'The account\'s outbound-webhook subscriptions, active only (revoked rows leave the registry; the delivery history stays). The signing secret NEVER answers here — it was shown exactly once, at the mint.',
        security: [{ sessionCookie: [] }],
        responses: {
          200: {
            description: 'The live subscriptions.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    subscriptions: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          id: { type: 'string', format: 'uuid' },
                          url: { type: 'string', format: 'uri' },
                          events: { type: 'array', items: { type: 'string' } },
                          active: { type: 'boolean' },
                          createdAt: { type: 'string' },
                        },
                        required: ['id', 'url', 'events', 'active', 'createdAt'],
                      },
                    },
                  },
                  required: ['subscriptions'],
                },
              },
            },
          },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
      post: {
        tags: ['Webhooks'], operationId: 'createWebhookSubscription', summary: 'Subscribe an endpoint (the secret answers ONCE)',
        description:
          'The subscribe: an https public endpoint + the event set (a subset of the journal-action whitelist: account.password, account.session_revoked, account.pat_minted, account.pat_revoked, factor.totp_enrolled, factor.passkey_enrolled). '
          + 'The answer carries the SHARED signing secret exactly once — the subscriber verifies every delivery with it. Deliveries ride `Webhook-Signature: t=<ms>,v1=<hmac-sha256(secret, t + "." + body)>` (the Stripe posture; verify with a 300 s replay bound). The delivery is fire-and-forget and never blocks the act.',
        security: [{ sessionCookie: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  url: { type: 'string', format: 'uri', description: 'https, a public host — literal localhost/private-range hosts refuse.' },
                  events: { type: 'array', items: { type: 'string' }, minItems: 1 },
                },
                required: ['url', 'events'],
              },
            },
          },
        },
        responses: {
          201: { description: 'The subscription — the shared `secret` rides this answer ONCE.', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string', format: 'uuid' }, url: { type: 'string' }, events: { type: 'array', items: { type: 'string' } }, secret: { type: 'string' }, active: { type: 'boolean' }, createdAt: { type: 'string' } }, required: ['id', 'url', 'events', 'secret', 'active', 'createdAt'] } } } },
          400: { description: 'The URL is not an https public host, or the event set is empty or names non-events.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account/webhooks/deliveries': {
      get: {
        tags: ['Webhooks'], operationId: 'listWebhookDeliveries', summary: 'The account\'s delivery log (newest first)',
        description: 'The bounded ladder\'s outcomes: the attempt count, the last HTTP status, delivered or the dead letter. A delivered row records only the body\'s SHA-256 digest (the support conversation\'s dedup key); a DEAD letter additionally stores the envelope body itself — the act\'s own no-secrets projection — because the redelivery pass re-signs it verbatim.',
        security: [{ sessionCookie: [] }],
        responses: {
          200: { description: 'The newest 50 delivery records.' },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/webhooks/redeliver': {
      post: {
        tags: ['Webhooks'], operationId: 'redeliverDeadWebhooks', summary: 'The dead-letter redelivery pass (the scheduled workflow\'s caller)',
        description: 'ONE bounded pass over the open dead letters: older than 15 minutes, at most 100 per call, ONE redelivery attempt per letter ever (the pass stamps the letter whether the attempt landed or not — a persistently-down endpoint never storms). The stored envelope body re-signs with a fresh timestamp; the subscriber dedupes by the envelope id. A revoked subscription\'s letter and a body-less legacy letter retire without a fetch.',
        security: [{ redeliveryBearer: [] }],
        responses: {
          200: {
            description: 'The pass\'s tally.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    attempted: { type: 'integer' },
                    delivered: { type: 'integer' },
                    retired: { type: 'integer' },
                  },
                  required: ['attempted', 'delivered', 'retired'],
                },
              },
            },
          },
          401: { description: 'The wrong bearer.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          404: { description: 'The token is unset — the endpoint does not exist.' },
        },
      },
    },
    '/api/op/account/webhooks/{id}': {
      delete: {
        tags: ['Webhooks'], operationId: 'revokeWebhookSubscription', summary: 'Unsubscribe (the owner\'s guarded deactivation)',
        description: 'Deactivates the subscription — the row stays for the delivery history. Owner-guarded: another account\'s subscription answers 404.',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        responses: {
          200: { description: 'Revoked.' },
          404: { description: 'No such subscription on this account.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account/tokens': {
      get: {
        tags: ['Tokens'], operationId: 'listTokens', summary: 'The registry + the picker\'s catalog',
        security: [{ sessionCookie: [] }],
        responses: {
          200: { description: 'The account\'s tokens (metadata only — never the plaintext) + the services it may mint for.', content: { 'application/json': { schema: { $ref: '#/components/schemas/TokensPayload' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
      post: {
        tags: ['Tokens'], operationId: 'mintToken', summary: 'Mint a token (the plaintext answers ONCE)',
        description: 'The mint: the name + the scope picker + the expiration. The plaintext secret answers exactly once — this response — and the store holds only its SHA-256. The scopes must be a subset of the holder\'s standing under the session\'s org context. The optional permissions set is validated against the TARGET INSTANCES\' served permissions catalogs (fail closed — an instance that cannot answer, or an id outside the served catalogs, refuses the mint).',
        security: [{ sessionCookie: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', maxLength: 60, example: 'the lab CLI' },
                  scopes: { type: 'array', items: { type: 'string', pattern: '^[^:]+:(read|write|admin)$' }, example: ['hub-instance:read', 'hub-instance:write'] },
                  permissions: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'The optional permissions-catalog ids (the scoped instances\' own `<group>.<resource>.<verb>` ids — fetch each instance\'s catalog through GET /api/op/account/tokens/catalog?service=…). Empty/absent = no catalog permissions (the token exchanges exactly as before).',
                    example: ['tl-workbench.runs.read'],
                  },
                  expiresInDays: { type: 'integer', enum: [30, 60, 90, 180, 365], default: 90 },
                },
                required: ['name', 'scopes'],
              },
            },
          },
        },
        responses: {
          201: { description: 'The minted token — the plaintext rides this answer ONCE.', content: { 'application/json': { schema: { allOf: [{ $ref: '#/components/schemas/TokensPayload' }, { type: 'object' }] } } } },
          400: { description: 'Malformed name or scopes, or the permissions refuse (a non-array shape, an id outside the served catalogs, or the instance cannot answer — fail closed).', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          403: { description: 'Over-broad (not a subset of the holder\'s standing).', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account/tokens/catalog': {
      get: {
        tags: ['Tokens'], operationId: 'getTokenPermissionsCatalog', summary: 'The mint picker\'s permissions catalog for one scoped service (TODO.openapi/03)',
        description:
          'The TARGET INSTANCE\'s served permissions catalog, fetched server-side and projected to sorted arrays (the OP never holds a copy). '
          + 'The instance resolves from the registered client\'s own redirect-URI origin. The mint dialog renders groups → checkboxes from it. '
          + '502 = the instance cannot answer (the mint will refuse too — fail closed).',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'service', in: 'query', required: true, schema: { type: 'string' }, example: 'hub-instance' }],
        responses: {
          200: {
            description: 'The catalog projection.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    service: { type: 'string' },
                    baseUrl: { type: 'string', format: 'uri' },
                    catalog: {
                      type: 'object',
                      properties: {
                        version: { type: 'integer' },
                        verbs: { type: 'array', items: { type: 'string' } },
                        groups: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              id: { type: 'string' },
                              description: { type: 'string' },
                              permissions: {
                                type: 'array',
                                items: {
                                  type: 'object',
                                  properties: { id: { type: 'string' }, description: { type: 'string' } },
                                  required: ['id', 'description'],
                                },
                              },
                            },
                            required: ['id', 'description', 'permissions'],
                          },
                        },
                      },
                      required: ['version', 'verbs', 'groups'],
                    },
                  },
                  required: ['service', 'baseUrl', 'catalog'],
                },
              },
            },
          },
          400: { description: 'The service parameter is missing.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'No session.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          404: { description: 'No such service, or it registers no instance URL.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          502: { description: 'The instance does not answer with a permissions catalog.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
    '/api/op/account/tokens/{id}': {
      patch: {
        tags: ['Tokens'], operationId: 'manageToken', summary: 'The management act — rename, edit the scopes, edit the permissions (issue #115 + TODO.openapi/03)',
        description:
          'The managed-token act. The rename is presentation-only (from→to on the audit). The scope edit is the complete replacement set, the mint\'s validation exactly — safe both ways because the exchange re-judges standing on every use. Widening is audited (and mailed) distinctly. The permissions edit replaces the pinned catalog-id set, validated against the scoped instances\' served catalogs (fail closed); ADDING a permission is the widening-sensitive act (a stale session refuses with fresh_auth_required). A revoked or expired token refuses edits.',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', maxLength: 60 },
                  scopes: { type: 'array', items: { type: 'string', pattern: '^[^:]+:(read|write|admin)$' } },
                  permissions: { type: 'array', items: { type: 'string' }, description: 'The complete replacement permissions-catalog-id set ([] clears the set; the mint\'s fail-closed validation exactly).' },
                },
              },
            },
          },
        },
        responses: {
          200: { description: 'The updated row.', content: { 'application/json': { schema: { type: 'object', properties: { token: { $ref: '#/components/schemas/TokenRow' } }, required: ['token'] } } } },
          400: { description: 'Malformed.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          403: { description: 'Over-broad scopes.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          404: { description: 'Not this account\'s token.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          409: { description: 'Revoked or expired — mint a fresh one instead.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
      delete: {
        tags: ['Tokens'], operationId: 'revokeToken', summary: 'Revoke the token (the row stays for the audit)',
        security: [{ sessionCookie: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        responses: {
          200: { description: 'Revoked.' },
          404: { description: 'Not this account\'s token.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          409: { description: 'Already revoked.', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },
  },
} as const

export type IdentityOpenApiSpec = typeof OPENAPI_SPEC

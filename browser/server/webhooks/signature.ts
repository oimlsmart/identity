// ═══════════════════════════════════════════════════════════════════
// The webhook signature (TODO.modern/08) — the Stripe posture:
// `Webhook-Signature: t=<ms>,v1=<hex>` where v1 =
// HMAC-SHA256(secret, `${t}.${body}`). The timestamp bounds replay
// (the verifier's tolerance window); the digest binds the body. The
// CONSUMER verifies with the secret the subscription minted — the
// shared-key model (we sign, they verify; neither authenticates with
// it, so it stores plaintext — unlike the PAT credential, which is
// presented TO us and therefore stores only its hash).
//
// WORKER-SAFE: WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

const encoder = new TextEncoder()

async function hmacSha256Hex(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload))
  return [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function signWebhookPayload(secret: string, timestampMs: number, body: string): Promise<string> {
  return `t=${timestampMs},v1=${await hmacSha256Hex(secret, `${timestampMs}.${body}`)}`
}

export async function verifyWebhookSignature(input: {
  secret: string
  header: string
  body: string
  nowMs: number
  toleranceSec: number
}): Promise<boolean> {
  const match = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(input.header.trim())
  if (!match) return false
  const [, timestamp, claimed] = match
  if (Math.abs(input.nowMs - Number(timestamp)) > input.toleranceSec * 1000) return false
  const expected = await hmacSha256Hex(input.secret, `${timestamp}.${input.body}`)
  if (expected.length !== claimed!.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) !== claimed!.charCodeAt(i) ? 1 : 0
  }
  return diff === 0
}

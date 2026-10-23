// Web Push with nothing but WebCrypto: RFC 8291 payload encryption (aes128gcm, RFC 8188) and
// RFC 8292 VAPID. Runs unchanged in Deno (Supabase Edge Functions) and Node 20+ (for the test).

const enc = new TextEncoder()

export const b64u = (b: Uint8Array) => {
  let s = ''
  for (const x of b) s += String.fromCharCode(x)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const unb64u = (s: string) => {
  const p = s.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(p + '='.repeat((4 - (p.length % 4)) % 4)), (c) => c.charCodeAt(0))
}

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

async function hmac(key: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data))
}

export interface Subscription {
  endpoint: string
  p256dh: string
  auth: string
}

/** `fixed` pins the ephemeral key and salt - only for checking against the RFC 8291 test vector. */
export async function encrypt(payload: Uint8Array, p256dh: string, authSecret: string, fixed?: { asJwk: JsonWebKey; salt: Uint8Array }) {
  const uaPublic = unb64u(p256dh)
  const auth = unb64u(authSecret)
  let asPrivate: CryptoKey
  let asPublic: Uint8Array
  if (fixed) {
    asPrivate = await crypto.subtle.importKey('jwk', fixed.asJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    asPublic = concat(new Uint8Array([4]), unb64u(fixed.asJwk.x!), unb64u(fixed.asJwk.y!))
  } else {
    const kp = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
    asPrivate = kp.privateKey
    asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  }
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asPrivate, 256))

  // HKDF(auth, ecdh) -> IKM, then HKDF(salt, IKM) -> content key + nonce.
  const prkKey = await hmac(auth, ecdh)
  const ikm = (await hmac(prkKey, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic, new Uint8Array([1])))).slice(0, 32)
  const salt = fixed?.salt ?? crypto.getRandomValues(new Uint8Array(16))
  const prk = await hmac(salt, ikm)
  const cek = (await hmac(prk, concat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16)
  const nonce = (await hmac(prk, concat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12)

  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  // One record: payload + 0x02 delimiter (last record, no padding).
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(payload, new Uint8Array([2]))))

  const header = new Uint8Array(21)
  header.set(salt, 0)
  new DataView(header.buffer).setUint32(16, 4096)
  header[20] = asPublic.length
  return concat(header, asPublic, ct)
}

export interface Vapid {
  publicKey: string
  privateJwk: JsonWebKey
  subject: string
}

export async function vapidAuth(endpoint: string, v: Vapid) {
  const jwtHeader = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })))
  const claims = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: v.subject })))
  const key = await crypto.subtle.importKey('jwk', v.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${jwtHeader}.${claims}`)))
  return `vapid t=${jwtHeader}.${claims}.${b64u(sig)}, k=${v.publicKey}`
}

/** Returns the push service's HTTP status: 201 = accepted, 404/410 = subscription gone. */
export async function sendPush(sub: Subscription, payload: unknown, v: Vapid, ttl = 900) {
  const body = await encrypt(enc.encode(JSON.stringify(payload)), sub.p256dh, sub.auth)
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      TTL: String(ttl),
      Urgency: 'high',
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      Authorization: await vapidAuth(sub.endpoint, v),
    },
    body,
  })
  return { status: res.status, text: res.ok ? '' : await res.text() }
}

/** A fresh VAPID key pair (public key in the raw 65-byte form browsers expect). */
export async function newVapidKeys() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey)
  const publicKey = b64u(concat(new Uint8Array([4]), unb64u(jwk.x!), unb64u(jwk.y!)))
  return { publicKey, privateJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d } as JsonWebKey }
}

// Meridian push function (Supabase Edge Function "push", JWT verification OFF - see actions below).
//   { action: 'publicKey' }  -> the VAPID public key (generated on first use, private half never leaves the DB)
//   { action: 'tick' }       -> called by pg_cron every 30 s: sends due block / focus / morning notifications
//   { action: 'test' }       -> needs the caller's user JWT; sends a test notification to their devices
// Every send is de-duplicated through push_log, so overlapping ticks never double-notify.
import { createClient } from 'jsr:@supabase/supabase-js@2'
// ---- inlined from webpush.ts ----
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
// ---- end webpush.ts ----

const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } })
const SUBJECT = 'https://eldocabdo-alt.github.io/meridian/'
const APP_URL = SUBJECT
const MIN = 60_000
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { ...CORS, 'Content-Type': 'application/json' } })

let vapidCache: Vapid | null = null
async function vapid(): Promise<Vapid> {
  if (vapidCache) return vapidCache
  const read = async () => {
    const { data } = await admin.from('app_secrets').select('name,value').in('name', ['vapid_public', 'vapid_private_jwk'])
    return Object.fromEntries((data ?? []).map((r) => [r.name, r.value])) as Record<string, string>
  }
  let m = await read()
  if (!m.vapid_public || !m.vapid_private_jwk) {
    const k = await newVapidKeys()
    await admin.from('app_secrets').upsert(
      [
        { name: 'vapid_public', value: k.publicKey },
        { name: 'vapid_private_jwk', value: JSON.stringify(k.privateJwk) },
      ],
      { onConflict: 'name', ignoreDuplicates: true },
    )
    m = await read() // another tick may have won the race; use whatever is stored
  }
  vapidCache = { publicKey: m.vapid_public, privateJwk: JSON.parse(m.vapid_private_jwk), subject: SUBJECT }
  return vapidCache
}

interface Payload {
  title: string
  body: string
  tag: string
  url?: string
}

/** Sends to every device of the user; `key` (if given) makes it once-only. Returns devices reached. */
async function notify(userId: string, p: Payload, key: string | null) {
  if (key) {
    const { error } = await admin.from('push_log').insert({ user_id: userId, key })
    if (error) return 0 // already sent
  }
  const { data: subs } = await admin.from('push_subscriptions').select('endpoint,p256dh,auth').eq('user_id', userId)
  const v = await vapid()
  let ok = 0
  for (const s of subs ?? []) {
    try {
      const r = await sendPush(s, { ...p, url: p.url ?? APP_URL }, v)
      if (r.status === 404 || r.status === 410) await admin.from('push_subscriptions').delete().eq('endpoint', s.endpoint)
      else if (r.status >= 200 && r.status < 300) {
        ok++
        await admin.from('push_subscriptions').update({ last_ok: new Date().toISOString() }).eq('endpoint', s.endpoint)
      } else console.error('push rejected', r.status, r.text.slice(0, 200))
    } catch (e) {
      console.error('push failed', String(e))
    }
  }
  return ok
}

const fmt = (t: number, tz: string, h24: boolean) =>
  new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: !h24, timeZone: tz }).format(t)
const localDate = (t: number, tz: string) => new Intl.DateTimeFormat('en-CA', { timeZone: tz }).format(t) // yyyy-mm-dd
const localMinutes = (t: number, tz: string) => {
  const [h, m] = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: tz }).format(t).split(':').map(Number)
  return (h % 24) * 60 + m
}

async function tick() {
  const now = Date.now()
  const { data: subs } = await admin.from('push_subscriptions').select('user_id')
  const users = [...new Set((subs ?? []).map((s) => s.user_id as string))]
  let sent = 0
  for (const uid of users) {
    const { data: rows } = await admin.from('items').select('kind,id,data').eq('user_id', uid).eq('deleted', false).in('kind', ['settings', 'focus'])
    const s = (rows?.find((r) => r.kind === 'settings')?.data ?? {}) as Record<string, unknown>
    const tz = (s.tz as string) || 'Africa/Cairo'
    const h24 = s.clock24 !== false
    const lead = typeof s.notifyLead === 'number' ? s.notifyLead : 5
    const notifyFocus = s.notifyFocus !== false

    // Blocks: from 1 hour back to 31 minutes ahead covers every lead time; epoch-ms strings compare in order.
    const { data: blocks } = await admin
      .from('items')
      .select('id,data')
      .eq('user_id', uid)
      .eq('kind', 'block')
      .eq('deleted', false)
      .gte('data->>start', String(now - 60 * MIN))
      .lte('data->>start', String(now + 31 * MIN))
    if (lead >= 0)
      for (const r of blocks ?? []) {
        const b = r.data as { title?: string; start: number; end: number; done?: boolean }
        const at = b.start - lead * MIN
        if (b.done || at > now || at < now - 5 * MIN) continue
        sent += await notify(
          uid,
          {
            title: b.title || 'Untitled block',
            body: lead ? `Starts in ${lead} min · ${fmt(b.start, tz, h24)}–${fmt(b.end, tz, h24)}` : `Starting now · until ${fmt(b.end, tz, h24)}`,
            tag: 'block-' + r.id,
          },
          `b:${r.id}:${b.start}:${lead}`,
        )
      }

    // Focus / break ending (a paused session never fires).
    const f = rows?.find((r) => r.kind === 'focus')?.data as
      | { phase: 'focus' | 'break'; title: string; startedAt: number; pausedTotal: number; plannedMs: number; pausedAt?: number; cycle: number; timer?: boolean; stopwatch?: boolean }
      | undefined
    if (notifyFocus && f && !f.pausedAt && !f.stopwatch) {
      const end = f.startedAt + f.pausedTotal + f.plannedMs
      if (end <= now && end > now - 5 * MIN) {
        const cycles = (s.cyclesBeforeLong as number) || 3
        const brk = f.cycle % cycles === 0 ? (s.longBreak as number) || 25 : (s.shortBreak as number) || 10
        sent += await notify(
          uid,
          f.timer
            ? { title: 'Timer done', body: f.title, tag: 'focus' } // a free timer has no break
            : f.phase === 'focus'
            ? { title: 'Focus complete', body: `${f.title} · take a ${brk}-minute break`, tag: 'focus' }
            : { title: 'Break over', body: `Ready for cycle ${f.cycle + 1}? ${f.title}`, tag: 'focus' },
          `f:${f.startedAt}:${f.phase}`,
        )
      }
    }

    // Morning nudge at "HH:MM" local time, once per local day, within a 10-minute window.
    const nudge = typeof s.morningNudge === 'string' && /^\d\d:\d\d$/.test(s.morningNudge) ? s.morningNudge : null
    if (nudge) {
      const [h, m] = nudge.split(':').map(Number)
      const mins = localMinutes(now, tz)
      if (mins >= h * 60 + m && mins < h * 60 + m + 10) {
        const today = localDate(now, tz)
        const { data: dayBlocks } = await admin
          .from('items')
          .select('data')
          .eq('user_id', uid)
          .eq('kind', 'block')
          .eq('deleted', false)
          .gte('data->>start', String(now - 24 * 60 * MIN))
          .lte('data->>start', String(now + 24 * 60 * MIN))
        const todays = (dayBlocks ?? []).map((r) => r.data as { start: number }).filter((b) => localDate(b.start, tz) === today).sort((a, b) => a.start - b.start)
        sent += await notify(
          uid,
          {
            title: 'Good morning',
            body: todays.length
              ? `${todays.length} block${todays.length > 1 ? 's' : ''} today · first at ${fmt(todays[0].start, tz, h24)}`
              : 'Nothing planned yet. Two minutes now shapes the whole day.',
            tag: 'morning',
          },
          `m:${today}`,
        )
      }
    }
  }
  await pruneLog(now)
  return await tickExtras(now, users, sent)
}

/** Evening wrap-up and Friday review reminders, one pass per tick (same once-only dedupe as the others). */
async function tickExtras(now: number, users: string[], sentSoFar: number) {
  let sent = sentSoFar
  for (const uid of users) {
    const { data: rows } = await admin.from('items').select('data').eq('user_id', uid).eq('kind', 'settings').eq('deleted', false).limit(1)
    const s = (rows?.[0]?.data ?? {}) as Record<string, unknown>
    const tz = (s.tz as string) || 'Africa/Cairo'
    const today = localDate(now, tz)
    const mins = localMinutes(now, tz)
    const inWindow = (hhmm: string) => {
      const [h, m] = hhmm.split(':').map(Number)
      return mins >= h * 60 + m && mins < h * 60 + m + 10
    }
    const getLog = async (id: string) => {
      const { data } = await admin.from('items').select('data').eq('user_id', uid).eq('kind', 'daylog').eq('id', id).eq('deleted', false).maybeSingle()
      return (data?.data ?? {}) as { wrapped?: boolean; reviewed?: boolean }
    }

    // Evening wrap-up: only if the day had blocks and he has not wrapped it up yet.
    const wrap = typeof s.wrapUpTime === 'string' && /^\d\d:\d\d$/.test(s.wrapUpTime) ? s.wrapUpTime : null
    if (wrap && inWindow(wrap) && !(await getLog(today)).wrapped) {
      const { data: dayBlocks } = await admin
        .from('items')
        .select('data')
        .eq('user_id', uid)
        .eq('kind', 'block')
        .eq('deleted', false)
        .gte('data->>start', String(now - 24 * 60 * MIN))
        .lte('data->>start', String(now + 24 * 60 * MIN))
      const todays = (dayBlocks ?? []).map((r) => r.data as { start: number; end: number; done?: boolean }).filter((b) => localDate(b.start, tz) === today)
      if (todays.length) {
        const left = todays.filter((b) => !b.done && b.end <= now).length
        sent += await notify(
          uid,
          { title: 'Wrap up your day', body: left ? `${left} block${left > 1 ? 's' : ''} unfinished · tap to move or drop them` : 'Everything is done · rate the day and close it', tag: 'wrap' },
          `w:${today}`,
        )
      }
    }

    // The evening plan the laptop prepared ("auto-<day>" request, answered by Claude): tell him once it is ready.
    const { data: plans } = await admin.from('items').select('id,data').eq('user_id', uid).eq('kind', 'aireq').eq('deleted', false).like('id', 'auto-%').eq('data->>status', 'done')
    for (const r of plans ?? []) {
      const p = r.data as { finishedAt?: number; reply?: string; actions?: { type: string }[]; applied?: number[]; meta?: { day?: string } }
      const blocks = (p.actions ?? []).filter((a) => a.type !== 'add_task').length
      if (!blocks || p.applied?.length || !p.finishedAt || p.finishedAt < now - 6 * 60 * MIN) continue
      sent += await notify(
        uid,
        { title: p.meta?.day === today ? "Today's plan is ready" : 'Tomorrow is planned', body: `${blocks} block${blocks > 1 ? 's' : ''} proposed · tap to review and accept`, tag: 'dayplan' },
        `p:${r.id}`,
      )
    }

    // Friday review reminder, 14:30 (after Jumu'ah), once, unless he already reviewed or skipped this week.
    const weekday = new Intl.DateTimeFormat('en-US', { weekday: 'short', timeZone: tz }).format(now)
    if (weekday === 'Fri' && inWindow('14:30') && !(await getLog('wk-' + today)).reviewed) {
      sent += await notify(uid, { title: 'Weekly review', body: 'See how the week went and let Claude plan the next one.', tag: 'review' }, `r:${today}`)
    }
  }
  return { users: users.length, sent }
}

async function pruneLog(now: number) {
  if (Math.random() < 0.02) await admin.from('push_log').delete().lt('sent_at', new Date(now - 3 * 24 * 60 * MIN).toISOString())
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS })
  const { action } = await req.json().catch(() => ({ action: null }))
  try {
    if (action === 'publicKey') return json({ key: (await vapid()).publicKey })
    if (action === 'tick') return json(await tick())
    if (action === 'test') {
      const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? ''
      const { data } = await admin.auth.getUser(token)
      if (!data.user) return json({ error: 'Sign in first.' }, 401)
      const n = await notify(data.user.id, { title: 'Meridian', body: 'Notifications are working on this device.', tag: 'test' }, null)
      return json({ sent: n })
    }
    return json({ error: 'unknown action' }, 400)
  } catch (e) {
    console.error(e)
    return json({ error: String(e) }, 500)
  }
})

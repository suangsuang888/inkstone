/**
 * Telegram Mini App (WebApp) initData verification, per
 * https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 *
 * Pure functions (WebCrypto only) so they can be unit-tested without a
 * Worker runtime. No secret is stored here; the bot token is passed in by
 * the caller (a Worker secret at runtime).
 *
 * Validation rule (Telegram):
 *   secret = HMAC-SHA256(key = "WebAppData", message = bot token)
 *   data_check_string = all received fields except `hash`, sorted by key,
 *     joined as `key=<value>` with "\n"
 *   hash = HMAC-SHA256(data_check_string, key = secret)
 * The received `hash` must match in constant time, and `auth_date` must
 * be recent (24h by default).
 */

export interface TelegramInitDataUser {
  id: number
  first_name?: string
  last_name?: string
  username?: string
  language_code?: string
  is_premium?: boolean
  allows_write_to_pm?: boolean
}

export type TelegramInitDataError = 'malformed' | 'invalid_signature' | 'expired'

export type TelegramInitDataResult =
  | { ok: true; user: TelegramInitDataUser; authDate: number }
  | { ok: false; error: TelegramInitDataError }

/** initData older than this is rejected (Telegram recommends 24h). */
export const TELEGRAM_INIT_DATA_MAX_AGE_SEC = 24 * 60 * 60

/** Small allowance for a client clock running slightly ahead. */
const MAX_FUTURE_SKEW_SEC = 300

export interface ParsedTelegramInitData {
  /** All fields except `hash`, as decoded key/value pairs. */
  params: Array<[string, string]>
  hash: string
  user: TelegramInitDataUser
  authDate: number
}

/**
 * Parse the raw initData query string. Returns null when a required field
 * is missing or malformed (`hash`, `user` JSON with an integer `id`,
 * integer `auth_date`).
 */
export function parseTelegramInitData(initData: string): ParsedTelegramInitData | null {
  if (!initData) return null
  let search: URLSearchParams
  try {
    search = new URLSearchParams(initData)
  } catch {
    return null
  }
  const hash = search.get('hash')
  const userRaw = search.get('user')
  const authDateRaw = search.get('auth_date')
  if (!hash || !userRaw || !authDateRaw) return null
  const authDate = Number(authDateRaw)
  if (!Number.isInteger(authDate)) return null
  let user: unknown
  try {
    user = JSON.parse(userRaw)
  } catch {
    return null
  }
  if (
    !user ||
    typeof user !== 'object' ||
    typeof (user as { id?: unknown }).id !== 'number' ||
    !Number.isInteger((user as { id: number }).id)
  ) {
    return null
  }
  const params: Array<[string, string]> = []
  for (const [key, value] of search.entries()) {
    if (key !== 'hash') params.push([key, value])
  }
  return { params, hash, user: user as TelegramInitDataUser, authDate }
}

/** Build the data_check_string: fields sorted by key, `key=value`, joined with "\n". */
export function buildDataCheckString(params: Array<[string, string]>): string {
  return params
    .slice()
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')
}

async function hmacSha256(keyBytes: Uint8Array, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))
  return new Uint8Array(signature)
}

/** secret = HMAC-SHA256(key = "WebAppData", message = bot token). */
export async function computeTelegramSecret(botToken: string): Promise<Uint8Array> {
  return hmacSha256(new TextEncoder().encode('WebAppData'), botToken)
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

/**
 * Verify Telegram WebApp initData against the bot token. `opts.now` is
 * seconds since epoch (defaults to now); `opts.maxAgeSec` defaults to 24h.
 */
export async function verifyTelegramInitData(
  initData: string,
  botToken: string,
  opts: { now?: number; maxAgeSec?: number } = {},
): Promise<TelegramInitDataResult> {
  const parsed = parseTelegramInitData(initData)
  if (!parsed) return { ok: false, error: 'malformed' }

  const secret = await computeTelegramSecret(botToken)
  const expected = await hmacSha256(secret, buildDataCheckString(parsed.params))
  const received = hexToBytes(parsed.hash)
  if (!received || !constantTimeEqual(expected, received)) {
    return { ok: false, error: 'invalid_signature' }
  }

  const nowSec = opts.now ?? Math.floor(Date.now() / 1000)
  const maxAgeSec = opts.maxAgeSec ?? TELEGRAM_INIT_DATA_MAX_AGE_SEC
  if (parsed.authDate > nowSec + MAX_FUTURE_SKEW_SEC || nowSec - parsed.authDate > maxAgeSec) {
    return { ok: false, error: 'expired' }
  }

  return { ok: true, user: parsed.user, authDate: parsed.authDate }
}

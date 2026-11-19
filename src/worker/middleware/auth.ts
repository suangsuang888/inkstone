import type { Context } from 'hono'
import { createMiddleware } from 'hono/factory'
import { getCookie, setCookie } from 'hono/cookie'
import {
  CLIENT_HEADER,
  LEGACY_SESSION_COOKIE,
  SESSION_COOKIE,
  SESSION_RENEW_BEFORE_MS,
  SESSION_TTL_MS,
} from '@shared/constants'
import { destroySession, hashToken, isSessionToken, renewSession } from '../lib/session-store'
import { ApiError } from '../lib/errors'
import type { AppBindings, Variables } from '../env'

interface UserRow {
  id: string
  username: string
  login: string
  name: string
  avatar_url: string
  role: 'owner' | 'member'
  settings: string
  created_at: number
}

export const USER_COLUMNS = `id, username, login, name, avatar_url, role, settings, created_at`

const USER_COLUMNS_ALIASED = USER_COLUMNS.split(', ').map((column) => `u.${column}`).join(', ')

export function rowToUser(row: UserRow): Variables['user'] {
  return {
    id: row.id,
    username: row.username,
    login: row.login,
    name: row.name,
    avatarUrl: row.avatar_url,

    role: row.role === 'owner' ? 'owner' : 'member',
    createdAt: row.created_at,
    settingsRaw: row.settings,
  }
}


interface SessionUserRow extends UserRow {
  session_id: string
  expires_at: number
  last_seen_at: number
}

interface SessionLookup {
  row: SessionUserRow
  shouldRenew: boolean
}

/**
 * Look a session up by its raw token: format check, hashed-id lookup,
 * expiry check. A row whose user is gone is destroyed (stale session).
 * Returns null when the token does not identify a live session.
 */
async function lookupSession(db: D1Database, token: string): Promise<SessionLookup | null> {
  if (!isSessionToken(token)) return null
  const row = await db
    .prepare(
      `SELECT ${USER_COLUMNS_ALIASED}, u.last_seen_at, s.id AS session_id, s.expires_at
         FROM sessions s LEFT JOIN users u ON u.id = s.user_id
        WHERE s.id = ?1 AND s.expires_at > ?2`,
    )
    .bind(await hashToken(token), Date.now())
    .first<SessionUserRow>()
  if (!row?.session_id) return null
  if (!row.id) {
    await destroySession(db, token)
    return null
  }
  return { row, shouldRenew: row.expires_at - Date.now() < SESSION_RENEW_BEFORE_MS }
}

/**
 * Attach a looked-up session to the request: context vars, renewal,
 * last_seen. `refreshCookie` writes the session cookie back (only for
 * cookie-based auth, when the session was renewed or came from the
 * legacy cookie name).
 */
async function applySession(
  c: Context<AppBindings>,
  token: string,
  lookup: SessionLookup,
  refreshCookie: boolean,
): Promise<void> {
  const { row, shouldRenew } = lookup
  c.set('user', rowToUser(row))
  c.set('userId', row.id)
  c.set('sessionId', row.session_id)
  if (shouldRenew) {
    await renewSession(c.env.DB, row.session_id)
  }
  if (refreshCookie) {
    writeSessionCookie(c, token)
  }
  const now = Date.now()
  if (row.last_seen_at < now - 5 * 60 * 1000) c.executionCtx?.waitUntil(
    c.env.DB.prepare(`UPDATE users SET last_seen_at = ?1 WHERE id = ?2 AND last_seen_at < ?3`)
      .bind(now, row.id, now - 5 * 60 * 1000)
      .run()
      .catch(() => {}),
  )
}

/** Parse an `Authorization: Bearer <token>` header, or null. */
function bearerToken(header: string | undefined): string | null {
  if (!header) return null
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  return match ? match[1]!.trim() : null
}

export const loadSession = createMiddleware<AppBindings>(async (c, next) => {
  const cookieNames = sessionCookieNames(c.req.url)
  const candidates = cookieNames
    .map((name) => ({ name, token: getCookie(c, name) }))
    .filter((candidate): candidate is { name: string; token: string } => Boolean(candidate.token))
  const seenTokens = new Set<string>()
  let authenticated = false

  for (const { name, token } of candidates) {
    if (seenTokens.has(token)) continue
    seenTokens.add(token)
    const lookup = await lookupSession(c.env.DB, token)
    if (!lookup) continue
    // Refresh the cookie when the session was renewed, or when the token
    // came from the legacy cookie name (migrates it to the current name).
    await applySession(c, token, lookup, lookup.shouldRenew || name === LEGACY_SESSION_COOKIE)
    if (new URL(c.req.url).protocol === 'https:' && getCookie(c, LEGACY_SESSION_COOKIE)) {
      clearLegacySessionCookie(c)
    }
    authenticated = true
    break
  }

  if (!authenticated) {
    // Bearer fallback: the Telegram Mini App (Android WebView) drops the
    // session cookie, so the client sends the session token as an
    // Authorization header instead. A missing or invalid token is simply
    // anonymous, never an error.
    const bearer = bearerToken(c.req.header('Authorization'))
    if (bearer && !seenTokens.has(bearer)) {
      const lookup = await lookupSession(c.env.DB, bearer)
      if (lookup) {
        await applySession(c, bearer, lookup, false)
        authenticated = true
      }
    }
  }

  if (candidates.length && !authenticated) clearSessionCookie(c)

  await next()
})

export const requireAuth = createMiddleware<AppBindings>(async (c, next) => {
  if (!c.get('userId')) throw ApiError.unauthenticated()
  await next()
})

export const requireClientHeader = createMiddleware<AppBindings>(async (c, next) => {
  const method = c.req.method.toUpperCase()
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    if (c.req.header(CLIENT_HEADER) !== '1') {
      throw new ApiError(403, 'forbidden', 'Missing client identification header. Refresh and try again')
    }
  }
  await next()
})

export function sessionCookieString(requestUrl: string, token: string): string {
  const secure = new URL(requestUrl).protocol === 'https:'
  const parts = [
    `${secure ? SESSION_COOKIE : LEGACY_SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    // The Mini App runs inside Telegram Web's iframe (cross-site), where
    // browsers drop SameSite=Lax third-party cookies, so a login there
    // never sticks. SameSite=None + Partitioned (CHIPS) keeps the session
    // usable in that iframe. Local http dev keeps Lax (None needs Secure).
    secure ? 'SameSite=None' : 'SameSite=Lax',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ]
  if (secure) parts.push('Secure', 'Partitioned')
  return parts.join('; ')
}

export function writeSessionCookie(c: Context<AppBindings>, token: string): void {
  c.header('Set-Cookie', sessionCookieString(c.req.url, token), { append: true })
}

export function clearSessionCookie(c: Context<AppBindings>): void {
  const secure = new URL(c.req.url).protocol === 'https:'
  const names = secure ? [SESSION_COOKIE, LEGACY_SESSION_COOKIE] : [LEGACY_SESSION_COOKIE]
  for (const name of names) {
    setCookie(c, name, '', {
      path: '/',
      httpOnly: true,
      maxAge: 0,
      // Clear must match the attributes the cookie was set with.
      sameSite: secure ? 'None' : 'Lax',
      secure,
      ...(secure ? { partitioned: true } : {}),
    })
  }
}

function clearLegacySessionCookie(c: Context<AppBindings>): void {
  const secure = new URL(c.req.url).protocol === 'https:'
  setCookie(c, LEGACY_SESSION_COOKIE, '', {
    path: '/',
    httpOnly: true,
    maxAge: 0,
    sameSite: secure ? 'None' : 'Lax',
    secure,
    ...(secure ? { partitioned: true } : {}),
  })
}

export function sessionCookieNames(requestUrl: string): string[] {
  return new URL(requestUrl).protocol === 'https:'
    ? [SESSION_COOKIE, LEGACY_SESSION_COOKIE]
    : [LEGACY_SESSION_COOKIE, SESSION_COOKIE]
}

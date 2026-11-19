// @vitest-environment node
import { webcrypto } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { Hono } from 'hono'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { AppBindings } from '../src/worker/env'
import { loadSession } from '../src/worker/middleware/auth'
import { hashToken } from '../src/worker/lib/session-store'

// Bearer auth exists because the Telegram Mini App (Android WebView)
// drops the session cookie: the client sends the session token as an
// `Authorization: Bearer` header instead. Fixed fake tokens for tests
// only. Not real credentials.
const BEARER_TOKEN = 'b'.repeat(64)
const COOKIE_TOKEN = 'c'.repeat(64)

let sqlite: DatabaseSync
let db: D1Database

beforeEach(async () => {
  vi.stubGlobal('crypto', webcrypto)
  sqlite = new DatabaseSync(':memory:')
  sqlite.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, username TEXT, login TEXT, name TEXT,
      avatar_url TEXT, role TEXT, settings TEXT, created_at INTEGER,
      last_seen_at INTEGER
    );
    CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT, expires_at INTEGER, created_at INTEGER);
    INSERT INTO users VALUES ('user', 'suangsuang', 'suangsuang', 'suangsuang', '', 'owner', '{}', 1, 0);
  `)
  const insert = sqlite.prepare('INSERT INTO sessions VALUES (?, ?, ?, ?)')
  insert.run(await hashToken(BEARER_TOKEN), 'user', Date.now() + 60_000, Date.now())
  insert.run(await hashToken(COOKIE_TOKEN), 'user', Date.now() + 60_000, Date.now())

  db = {
    prepare(sql: string) {
      const statement = sqlite.prepare(sql)
      let values: unknown[] = []
      const args = () => /\?\d+/.test(sql)
        ? [Object.fromEntries(values.map((value, index) => [String(index + 1), value]))]
        : values
      const prepared = {
        bind(...bound: unknown[]) { values = bound; return prepared },
        async first() { return statement.get(...args() as never[]) ?? null },
        async run() {
          return { meta: { changes: Number(statement.run(...args() as never[]).changes) } }
        },
      }
      return prepared
    },
    async batch(statements: D1PreparedStatement[]) {
      sqlite.exec('BEGIN')
      try {
        const results = []
        for (const statement of statements) results.push(await statement.run())
        sqlite.exec('COMMIT')
        return results
      } catch (error) {
        sqlite.exec('ROLLBACK')
        throw error
      }
    },
  } as unknown as D1Database
})

afterEach(() => {
  sqlite.close()
  vi.unstubAllGlobals()
})

function app() {
  const hono = new Hono<AppBindings>()
  hono.use(loadSession)
  hono.get('/me', (c) => c.json({ userId: c.get('userId') ?? null }))
  return hono
}

// Hono's Context.executionCtx getter throws without one, and loadSession
// uses it for the last_seen update, so every request gets a mock.
const executionCtx = {
  waitUntil(promise: Promise<unknown>) {
    void promise.catch(() => {})
  },
  passThroughOnException() {},
} as ExecutionContext

async function me(headers: Record<string, string> = {}) {
  return app().request('/me', { headers }, { DB: db } as AppBindings['Bindings'], executionCtx)
}

it('authenticates a valid Bearer session token', async () => {
  const res = await me({ Authorization: `Bearer ${BEARER_TOKEN}` })
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({ userId: 'user' })
})

it('treats a missing or invalid Bearer token as anonymous, not an error', async () => {
  const missing = await me()
  expect(missing.status).toBe(200)
  expect(await missing.json()).toEqual({ userId: null })

  const wrong = await me({ Authorization: `Bearer ${'d'.repeat(64)}` })
  expect(wrong.status).toBe(200)
  expect(await wrong.json()).toEqual({ userId: null })

  const malformed = await me({ Authorization: 'Bearer not-a-token' })
  expect(malformed.status).toBe(200)
  expect(await malformed.json()).toEqual({ userId: null })
})

it('still authenticates via the session cookie', async () => {
  const res = await me({ Cookie: `inkstone_session=${COOKIE_TOKEN}` })
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({ userId: 'user' })
})

it('renews a near-expiry session found via Bearer', async () => {
  const before = sqlite.prepare('SELECT expires_at AS e FROM sessions WHERE id = ?')
    .get(await hashToken(BEARER_TOKEN)) as { e: number }
  const res = await me({ Authorization: `Bearer ${BEARER_TOKEN}` })
  expect(res.status).toBe(200)
  const after = sqlite.prepare('SELECT expires_at AS e FROM sessions WHERE id = ?')
    .get(await hashToken(BEARER_TOKEN)) as { e: number }
  expect(after.e).toBeGreaterThan(before.e)
})

it('does not write a session cookie for Bearer auth', async () => {
  const res = await me({ Authorization: `Bearer ${BEARER_TOKEN}` })
  expect(res.status).toBe(200)
  expect(res.headers.get('set-cookie')).toBeNull()
})

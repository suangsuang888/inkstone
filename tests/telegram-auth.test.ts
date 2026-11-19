import { describe, expect, it } from 'vitest'
import {
  buildDataCheckString,
  bytesToHex,
  constantTimeEqual,
  hexToBytes,
  verifyTelegramInitData,
} from '../src/worker/lib/telegram-auth'

// Fixed fake bot token for tests only. Not a real credential.
const BOT_TOKEN = '123456:TEST-FAKE-TOKEN-DO-NOT-USE'
const ADMIN_ID = 5736222709
const NOW = 1794000000 // fixed "now" (seconds) so the tests are deterministic

async function hmac(keyBytes: Uint8Array, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)))
}

/** Build a valid initData query string, computing the signature independently. */
async function makeInitData(input: {
  user?: Record<string, unknown>
  authDate?: number
  extra?: Record<string, string>
  paramOrder?: string[]
}): Promise<string> {
  const user = input.user ?? { id: ADMIN_ID, first_name: 'Test', username: 'testuser' }
  const authDate = input.authDate ?? NOW
  const fields: Record<string, string> = {
    query_id: 'test-query-id',
    user: JSON.stringify(user),
    auth_date: String(authDate),
    ...(input.extra ?? {}),
  }
  const keys = input.paramOrder ?? Object.keys(fields)
  const dataCheckString = keys
    .slice()
    .sort()
    .map((key) => `${key}=${fields[key]}`)
    .join('\n')
  const secret = await hmac(new TextEncoder().encode('WebAppData'), BOT_TOKEN)
  const hash = bytesToHex(await hmac(secret, dataCheckString))
  const params = new URLSearchParams({ ...fields, hash })
  return params.toString()
}

describe('verifyTelegramInitData', () => {
  it('accepts a correctly signed initData and returns the user', async () => {
    const initData = await makeInitData({})
    const result = await verifyTelegramInitData(initData, BOT_TOKEN, { now: NOW })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.user.id).toBe(ADMIN_ID)
      expect(result.authDate).toBe(NOW)
    }
  })

  it('accepts fields in any order (data_check_string is sorted)', async () => {
    const initData = await makeInitData({ paramOrder: ['auth_date', 'user', 'query_id'] })
    const result = await verifyTelegramInitData(initData, BOT_TOKEN, { now: NOW })
    expect(result.ok).toBe(true)
  })

  it('rejects a tampered user id', async () => {
    const initData = await makeInitData({})
    const tampered = initData.replace(
      encodeURIComponent(JSON.stringify({ id: ADMIN_ID, first_name: 'Test', username: 'testuser' })),
      encodeURIComponent(JSON.stringify({ id: 999999999, first_name: 'Test', username: 'testuser' })),
    )
    expect(tampered).not.toBe(initData)
    const result = await verifyTelegramInitData(tampered, BOT_TOKEN, { now: NOW })
    expect(result).toEqual({ ok: false, error: 'invalid_signature' })
  })

  it('rejects an expired auth_date', async () => {
    const initData = await makeInitData({ authDate: NOW - 25 * 60 * 60 })
    const result = await verifyTelegramInitData(initData, BOT_TOKEN, { now: NOW })
    expect(result).toEqual({ ok: false, error: 'expired' })
  })

  it('rejects a wrong hash', async () => {
    const initData = await makeInitData({})
    const wrongHash = initData.replace(/hash=[0-9a-f]{64}/, (m) =>
      m.slice(0, 5) + (m[5] === 'a' ? 'b' : 'a') + m.slice(6),
    )
    expect(wrongHash).not.toBe(initData)
    const result = await verifyTelegramInitData(wrongHash, BOT_TOKEN, { now: NOW })
    expect(result).toEqual({ ok: false, error: 'invalid_signature' })
  })

  it('rejects malformed initData', async () => {
    expect(await verifyTelegramInitData('', BOT_TOKEN, { now: NOW })).toEqual({
      ok: false,
      error: 'malformed',
    })
    const noHash = await makeInitData({})
    expect(
      await verifyTelegramInitData(noHash.replace(/&hash=[0-9a-f]+/, ''), BOT_TOKEN, { now: NOW }),
    ).toEqual({ ok: false, error: 'malformed' })
    const noUser = new URLSearchParams({ query_id: 'x', auth_date: String(NOW), hash: '00' }).toString()
    expect(await verifyTelegramInitData(noUser, BOT_TOKEN, { now: NOW })).toEqual({
      ok: false,
      error: 'malformed',
    })
    const badUser = new URLSearchParams({
      query_id: 'x',
      user: JSON.stringify({ first_name: 'NoId' }),
      auth_date: String(NOW),
      hash: '00',
    }).toString()
    expect(await verifyTelegramInitData(badUser, BOT_TOKEN, { now: NOW })).toEqual({
      ok: false,
      error: 'malformed',
    })
  })
})

describe('telegram-auth helpers', () => {
  it('buildDataCheckString sorts keys and joins with newlines', () => {
    expect(
      buildDataCheckString([
        ['user', '{"id":1}'],
        ['auth_date', '123'],
        ['query_id', 'q'],
      ]),
    ).toBe('auth_date=123\nquery_id=q\nuser={"id":1}')
  })

  it('hexToBytes and bytesToHex round-trip', () => {
    const bytes = new Uint8Array([0, 15, 255, 128])
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes)
    expect(hexToBytes('zz')).toBeNull()
    expect(hexToBytes('abc')).toBeNull()
  })

  it('constantTimeEqual compares by value and length', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true)
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false)
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false)
  })
})

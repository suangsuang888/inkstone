import { describe, expect, it } from 'vitest'
import {
  escapeXml,
  filenameToTitle,
  formatHttpDate,
  noteFilename,
  parseDavPath,
  parseDestination,
  sanitizeTitle,
  shiftSqlPlaceholders,
} from '../src/worker/routes/dav'

describe('parseDavPath', () => {
  it('maps the root forms to no segments', () => {
    expect(parseDavPath('/dav')).toEqual([])
    expect(parseDavPath('/dav/')).toEqual([])
  })

  it('splits nested paths into decoded segments', () => {
    expect(parseDavPath('/dav/notes/hello.md')).toEqual(['notes', 'hello.md'])
    expect(parseDavPath('/dav/%E7%AC%94%E8%AE%B0/%E4%B8%AD%E6%96%87.md')).toEqual(['笔记', '中文.md'])
    expect(parseDavPath('/dav/notes/')).toEqual(['notes'])
  })

  it('rejects paths outside the dav mount', () => {
    expect(parseDavPath('/api/notes')).toBeNull()
    expect(parseDavPath('/davx/notes')).toBeNull()
    expect(parseDavPath('dav/notes')).toBeNull()
  })

  it('rejects empty, dot, and undecodable segments', () => {
    expect(parseDavPath('/dav//notes')).toBeNull()
    expect(parseDavPath('/dav/./notes')).toBeNull()
    expect(parseDavPath('/dav/../notes')).toBeNull()
    expect(parseDavPath('/dav/%2E%2E/notes')).toBeNull()
    expect(parseDavPath('/dav/%')).toBeNull()
    expect(parseDavPath('/dav/%zz')).toBeNull()
  })

  it('keeps an encoded slash inside one segment as part of the name', () => {
    expect(parseDavPath('/dav/notes/a%2Fb.md')).toEqual(['notes', 'a/b.md'])
  })
})

describe('noteFilename and filenameToTitle', () => {
  it('maps titles to .md file names and back', () => {
    expect(noteFilename('hello')).toBe('hello.md')
    expect(noteFilename('a／b')).toBe('a／b.md')
    expect(filenameToTitle('hello.md')).toBe('hello')
    expect(filenameToTitle('a.md.md')).toBe('a.md')
  })

  it('rejects titles that cannot be a single file', () => {
    expect(noteFilename('a/b')).toBeNull()
    expect(noteFilename('')).toBeNull()
    expect(filenameToTitle('hello.txt')).toBeNull()
    expect(filenameToTitle('hello')).toBeNull()
    expect(filenameToTitle('.md')).toBeNull()
  })
})

describe('sanitizeTitle', () => {
  it('replaces slashes with the fullwidth slash', () => {
    expect(sanitizeTitle('a/b/c')).toBe('a／b／c')
    expect(sanitizeTitle('plain')).toBe('plain')
    expect(sanitizeTitle('a／b')).toBe('a／b')
  })
})

describe('escapeXml', () => {
  it('escapes the five XML metacharacters', () => {
    expect(escapeXml('<a href="x">&\'y\'</a>')).toBe(
      '&lt;a href=&quot;x&quot;&gt;&amp;&apos;y&apos;&lt;/a&gt;',
    )
    expect(escapeXml('plain')).toBe('plain')
  })
})

describe('formatHttpDate', () => {
  it('formats timestamps as RFC 1123 dates', () => {
    expect(formatHttpDate(0)).toBe('Thu, 01 Jan 1970 00:00:00 GMT')
    expect(formatHttpDate(1790000000000)).toBe(new Date(1790000000000).toUTCString())
  })
})

describe('shiftSqlPlaceholders', () => {
  it('shifts numbered placeholders by the given offset', () => {
    expect(shiftSqlPlaceholders('WHERE id = ?1 AND rev = ?3', 7)).toBe(
      'WHERE id = ?8 AND rev = ?10',
    )
    expect(shiftSqlPlaceholders('no placeholders', 3)).toBe('no placeholders')
  })
})

describe('parseDestination', () => {
  const requestUrl = 'http://localhost:7712/dav/notes/hello.md'

  it('parses same-origin destinations under the dav mount', () => {
    expect(parseDestination('http://localhost:7712/dav/notes/renamed.md', requestUrl)).toEqual([
      'notes',
      'renamed.md',
    ])
    expect(parseDestination('http://localhost:7712/dav/', requestUrl)).toEqual([])
    expect(parseDestination('http://localhost:7712/dav/notes/a%2Fb.md', requestUrl)).toEqual([
      'notes',
      'a/b.md',
    ])
  })

  it('flags destinations on another origin', () => {
    expect(parseDestination('http://example.com/dav/notes.md', requestUrl)).toBe('foreign')
    expect(parseDestination('https://localhost:7712/dav/notes.md', requestUrl)).toBe('foreign')
  })

  it('rejects missing, relative, and non-dav destinations', () => {
    expect(parseDestination(null, requestUrl)).toBeNull()
    expect(parseDestination('', requestUrl)).toBeNull()
    expect(parseDestination('/dav/notes.md', requestUrl)).toBeNull()
    expect(parseDestination('http://localhost:7712/api/notes', requestUrl)).toBeNull()
  })
})

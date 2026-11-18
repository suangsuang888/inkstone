import { describe, expect, it } from 'vitest'
import {
  attachmentLinkLine,
  davNoteTitleForFile,
  davReportedMime,
  fileStem,
  parseDavAttachmentLines,
  renameAttachmentLink,
  withAttachmentLink,
  withoutAttachmentLink,
} from '../src/worker/routes/dav'

const ID_A = '01m7pf5gabjypx84bbvb4b9ygc'
const ID_B = '01m7pfd772rmrtc0h1e63p6pap'

describe('fileStem', () => {
  it('strips only the last extension', () => {
    expect(fileStem('backup.zip')).toBe('backup')
    expect(fileStem('archive.tar.gz')).toBe('archive.tar')
    expect(fileStem('backup')).toBe('backup')
  })

  it('rejects hidden files without a stem', () => {
    expect(fileStem('.zip')).toBeNull()
    expect(fileStem('')).toBeNull()
  })
})

describe('davNoteTitleForFile', () => {
  it('maps a file stem to its host note title', () => {
    expect(davNoteTitleForFile('backup.zip')).toBe('backup')
    expect(davNoteTitleForFile('backup')).toBe('backup')
  })

  it('maps slashes to fullwidth slashes like note titles do', () => {
    expect(davNoteTitleForFile('a/b.zip')).toBe('a／b')
  })

  it('rejects files without a usable stem', () => {
    expect(davNoteTitleForFile('.zip')).toBeNull()
  })
})

describe('attachment link lines', () => {
  it('round-trips a link line through the parser', () => {
    const content = attachmentLinkLine('backup.zip', ID_A)
    expect(content).toBe(`[backup.zip](/api/files/${ID_A})`)
    expect(parseDavAttachmentLines(content)).toEqual([{ filename: 'backup.zip', id: ID_A }])
  })

  it('parses several link lines and skips blank lines', () => {
    const content = [
      attachmentLinkLine('backup.zip', ID_A),
      '',
      attachmentLinkLine('backup.tar', ID_B),
    ].join('\n')
    expect(parseDavAttachmentLines(content)).toEqual([
      { filename: 'backup.zip', id: ID_A },
      { filename: 'backup.tar', id: ID_B },
    ])
  })

  it('returns an empty list for empty content', () => {
    expect(parseDavAttachmentLines('')).toEqual([])
  })

  it('returns null for user-written content', () => {
    expect(parseDavAttachmentLines('my notes\n[backup.zip](/api/files/' + ID_A + ')')).toBeNull()
    expect(parseDavAttachmentLines('just text')).toBeNull()
  })

  it('appends a link to empty and to user content', () => {
    expect(withAttachmentLink('', 'backup.zip', ID_A)).toBe(
      `[backup.zip](/api/files/${ID_A})`,
    )
    expect(withAttachmentLink('hello', 'backup.zip', ID_A)).toBe(
      `hello\n[backup.zip](/api/files/${ID_A})`,
    )
  })

  it('replaces the link line for the same file name', () => {
    const before = withAttachmentLink('', 'backup.zip', ID_A)
    expect(withAttachmentLink(before, 'backup.zip', ID_B)).toBe(
      `[backup.zip](/api/files/${ID_B})`,
    )
  })

  it('keeps other files link lines when appending', () => {
    const before = withAttachmentLink('', 'backup.zip', ID_A)
    const after = withAttachmentLink(before, 'backup.tar', ID_B)
    expect(after).toBe(
      `[backup.zip](/api/files/${ID_A})\n[backup.tar](/api/files/${ID_B})`,
    )
  })

  it('removes only the named link line', () => {
    const content = [
      attachmentLinkLine('backup.zip', ID_A),
      attachmentLinkLine('backup.tar', ID_B),
    ].join('\n')
    expect(withoutAttachmentLink(content, 'backup.zip')).toBe(
      `[backup.tar](/api/files/${ID_B})`,
    )
    expect(withoutAttachmentLink(content, 'other.zip')).toBe(content)
  })

  it('renames a link line keeping the attachment id', () => {
    const content = attachmentLinkLine('backup.zip', ID_A)
    expect(renameAttachmentLink(content, 'backup.zip', 'backup2.zip', ID_A)).toBe(
      `[backup2.zip](/api/files/${ID_A})`,
    )
    expect(renameAttachmentLink(content, 'other.zip', 'other2.zip', ID_A)).toBe(content)
  })
})

describe('davReportedMime', () => {
  it('keeps a precise client-provided type', () => {
    expect(davReportedMime('backup.zip', 'application/zip')).toBe('application/zip')
    expect(davReportedMime('a.bin', 'application/x-custom')).toBe('application/x-custom')
  })

  it('derives the type from the extension when the header is generic', () => {
    expect(davReportedMime('backup.zip', 'application/octet-stream')).toBe('application/zip')
    expect(davReportedMime('backup.zip', undefined)).toBe('application/zip')
    expect(davReportedMime('doc.pdf', undefined)).toBe('application/pdf')
    expect(davReportedMime('notes.txt', '')).toBe('text/plain')
  })

  it('falls back to octet-stream for unknown extensions', () => {
    expect(davReportedMime('data.xyz', undefined)).toBe('application/octet-stream')
  })
})

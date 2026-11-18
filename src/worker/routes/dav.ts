import { Hono, type Context } from 'hono'
import { LIMITS } from '@shared/constants'
import { countText, deriveExcerpt } from '@shared/markdown-utils'
import { truncateText, utf8ByteLength } from '@shared/text-utils'
import type { AppBindings } from '../env'
import { drainAttachmentCleanup } from '../attachments/cleanup'
import {
  deleteAttachmentObjects,
  putAttachmentObject,
  readAttachmentObject,
  readAttachmentObjectStream,
} from '../attachments/backend'
import {
  attachmentCleanupTarget,
  attachmentObjectKey,
  type AttachmentObjectStorage,
} from '../attachments/keys'
import {
  persistAttachmentWithinQuota,
  sanitizeAttachmentFilename,
} from '../attachments/storage'
import { initializeDatabase } from '../db/schema'
import { NOTE_COLUMNS_FULL, splitTags, type FolderRow, type NoteRow } from '../db/rows'
import {
  buildNoteDerivedStatements,
  FTS_QUEUE_CONFLICT_SQL,
  LINK_TARGET_SUBQUERY,
} from '../db/writes'
import { sha256Hex } from '../lib/encoding'
import { ApiError } from '../lib/errors'
import { newId } from '../lib/id'
import { isInlineSafe } from '../lib/image'
import { broadcastCursor, scheduleFtsDrain } from '../lib/notify'
import {
  dummyVerify,
  isPasswordHash,
  normalizeUsername,
  PASSWORD_MAX_LENGTH,
  USERNAME_PATTERN,
  verifyPassword,
} from '../lib/password'
import { assertContentSize } from '../lib/request'
import { aiDeleteNeededSql, enqueueNoteIndex } from '../mcp/ai-search'
import { SNAPSHOT_DIFF_THRESHOLD, SNAPSHOT_INTERVAL_MS } from './notes'

export const davRoutes = new Hono<AppBindings>()

davRoutes.use('*', async (c, next) => {
  c.set('database', await initializeDatabase(c.env))
  await next()
})

davRoutes.use('*', async (c, next) => {
  const userId = await authenticateDav(c)
  if (!userId) {
    return c.text('Unauthorized', 401, { 'WWW-Authenticate': 'Basic realm="Inkstone WebDAV"' })
  }
  c.set('userId', userId)
  await next()
})

davRoutes.all('/', handleDav)
davRoutes.all('/*', handleDav)

const DAV_ALLOW = 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, COPY, MOVE'
const FOLDER_COLUMNS = `f.id, f.parent_id, f.name, f.icon, f.color, f.position, f.created_at, f.updated_at`

export function parseDavPath(pathname: string): string[] | null {
  if (pathname === '/dav' || pathname === '/dav/') return []
  if (!pathname.startsWith('/dav/')) return null
  const parts = pathname.slice(5).split('/')
  if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop()
  if (parts.length === 0) return []
  const segments: string[] = []
  for (const part of parts) {
    if (part === '') return null
    let decoded: string
    try {
      decoded = decodeURIComponent(part)
    } catch {
      return null
    }
    if (decoded === '' || decoded === '.' || decoded === '..' || decoded.includes('\0')) {
      return null
    }
    segments.push(decoded)
  }
  return segments
}

export function noteFilename(title: string): string | null {
  if (!title || title.includes('/')) return null
  return `${title}.md`
}

export function filenameToTitle(filename: string): string | null {
  if (!filename.endsWith('.md')) return null
  const title = filename.slice(0, -3)
  return title ? title : null
}

export function sanitizeTitle(title: string): string {
  return title.replaceAll('/', '／')
}

export function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}

export function formatHttpDate(timestamp: number): string {
  return new Date(timestamp).toUTCString()
}

export function shiftSqlPlaceholders(sql: string, offset: number): string {
  return sql.replace(/\?(\d+)/g, (_match, value: string) => `?${Number(value) + offset}`)
}

export function parseDestination(
  destination: string | null,
  requestUrl: string,
): string[] | 'foreign' | null {
  if (!destination) return null
  let url: URL
  try {
    url = new URL(destination)
  } catch {
    return null
  }
  if (url.origin !== new URL(requestUrl).origin) return 'foreign'
  return parseDavPath(url.pathname)
}

export interface DavAttachmentRow {
  id: string
  note_id: string | null
  filename: string
  mime: string
  size: number
  storage: AttachmentObjectStorage
  created_at: number
}

type DavTarget =
  | { kind: 'root' }
  | { kind: 'folder'; folder: FolderRow }
  | { kind: 'note'; note: NoteRow }
  | { kind: 'attachment'; note: NoteRow; attachment: DavAttachmentRow }
  | { kind: 'absent'; parentId: string | null; leaf: string }
  | { kind: 'broken' }

interface PropfindEntry {
  href: string
  displayName: string
  isCollection: boolean
  contentLength: number | null
  lastModified: number
  contentType?: string
}

/** File name without its last extension ("backup.zip" -> "backup", "backup" -> "backup"). */
export function fileStem(filename: string): string | null {
  const dot = filename.lastIndexOf('.')
  if (dot === 0) return null
  if (dot === -1) return filename ? filename : null
  const stem = filename.slice(0, dot)
  return stem ? stem : null
}

/** Note title a DAV attachment file maps to (same folder, stem as title). */
export function davNoteTitleForFile(filename: string): string | null {
  const stem = fileStem(filename)
  if (stem === null) return null
  const title = truncateText(sanitizeTitle(stem).trim(), LIMITS.titleMaxLength)
  return title ? title : null
}

export function attachmentLinkLine(filename: string, attachmentId: string): string {
  return `[${filename}](/api/files/${attachmentId})`
}

const DAV_ATTACHMENT_LINE_RE = /^\[(.+)\]\(\/api\/files\/([0-9a-hjkmnp-tv-z]{26})\)$/

export interface DavAttachmentLink {
  filename: string
  id: string
}

/**
 * Parses a note body that consists only of attachment link lines.
 * Returns null when any non-empty line is not such a link, i.e. the note
 * carries user-written content and is not a DAV-managed attachment index.
 */
export function parseDavAttachmentLines(
  content: string,
): DavAttachmentLink[] | null {
  const lines: DavAttachmentLink[] = []
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const match = DAV_ATTACHMENT_LINE_RE.exec(trimmed)
    if (!match) return null
    lines.push({ filename: match[1]!, id: match[2]! })
  }
  return lines
}

/** Replace the link line for `filename`, or append it when it is missing. */
export function withAttachmentLink(
  content: string,
  filename: string,
  attachmentId: string,
): string {
  const line = attachmentLinkLine(filename, attachmentId)
  if (!content.trim()) return line
  const lines = content.replace(/\n+$/, '').split('\n')
  let replaced = false
  const updated = lines.map((current) => {
    const match = DAV_ATTACHMENT_LINE_RE.exec(current.trim())
    if (match && match[1] === filename) {
      replaced = true
      return line
    }
    return current
  })
  if (!replaced) updated.push(line)
  return updated.join('\n')
}

/** Remove the link line for `filename` from a note body. */
export function withoutAttachmentLink(content: string, filename: string): string {
  return content
    .split('\n')
    .filter((line) => {
      const match = DAV_ATTACHMENT_LINE_RE.exec(line.trim())
      return !(match && match[1] === filename)
    })
    .join('\n')
    .replace(/\n+$/, '')
}

/**
 * Reported MIME for a DAV attachment upload. WebDAV clients often send no
 * Content-Type or a generic application/octet-stream; derive a precise type
 * from the extension when the header carries no better information, so the
 * stored attachment keeps its real type (e.g. application/zip).
 */
export function davReportedMime(filename: string, header: string | undefined): string {
  const reported = (header ?? '').trim().toLowerCase().split(';', 1)[0]
  if (reported && reported !== 'application/octet-stream') return reported
  const extension = filename.slice(filename.lastIndexOf('.') + 1).toLowerCase()
  const byExtension: Record<string, string> = {
    zip: 'application/zip',
    pdf: 'application/pdf',
    json: 'application/json',
    txt: 'text/plain',
    md: 'text/markdown',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    webp: 'image/webp',
    avif: 'image/avif',
    svg: 'image/svg+xml',
  }
  return byExtension[extension] ?? 'application/octet-stream'
}

function encodeContentDispositionFilename(filename: string): string {
  return encodeURIComponent(filename).replace(/['()*]/g, (character) => {
    return `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  })
}

interface FolderGraphRow {
  id: string
  parent_id: string | null
  name: string
}

async function handleDav(c: Context<AppBindings>): Promise<Response> {
  switch (c.req.method.toUpperCase()) {
    case 'OPTIONS':
      return new Response(null, { status: 200, headers: { Allow: DAV_ALLOW, DAV: '1' } })
    case 'PROPFIND':
      return handlePropfind(c)
    case 'GET':
      return handleGet(c, false)
    case 'HEAD':
      return handleGet(c, true)
    case 'PUT':
      return handlePut(c)
    case 'DELETE':
      return handleDelete(c)
    case 'MKCOL':
      return handleMkcol(c)
    case 'MOVE':
      return handleMoveCopy(c, 'MOVE')
    case 'COPY':
      return handleMoveCopy(c, 'COPY')
    default:
      return methodNotAllowed()
  }
}

function methodNotAllowed(): Response {
  return new Response('Method Not Allowed', { status: 405, headers: { Allow: DAV_ALLOW } })
}

function preconditionFailed(): Response {
  return new Response('Precondition Failed', { status: 412 })
}

function davSegments(c: Context<AppBindings>): string[] {
  const segments = parseDavPath(new URL(c.req.url).pathname)
  if (segments === null) throw ApiError.badRequest('Invalid WebDAV path')
  return segments
}

function davHref(segments: string[], isCollection: boolean): string {
  const path = `/dav${segments.map((segment) => `/${encodeURIComponent(segment)}`).join('')}`
  return isCollection ? `${path}/` : path
}

function titleFromFilename(filename: string): string {
  const title = filenameToTitle(filename)
  if (title === null) throw ApiError.badRequest('Invalid file name')
  return title
}

function resolveDavTitle(filename: string): string {
  const title = truncateText(sanitizeTitle(titleFromFilename(filename)).trim(), LIMITS.titleMaxLength)
  if (!title) throw ApiError.badRequest('Note title cannot be empty')
  return title
}

async function authenticateDav(c: Context<AppBindings>): Promise<string | null> {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Basic ')) return null
  let decoded: string
  try {
    const bytes = Uint8Array.from(atob(header.slice(6).trim()), (ch) => ch.charCodeAt(0))
    decoded = new TextDecoder().decode(bytes)
  } catch {
    return null
  }
  const separator = decoded.indexOf(':')
  if (separator <= 0) return null
  const username = normalizeUsername(decoded.slice(0, separator))
  const password = decoded.slice(separator + 1)
  if (!USERNAME_PATTERN.test(username) || password.length > PASSWORD_MAX_LENGTH) {
    await dummyVerify()
    return null
  }
  const row = await c.env.DB.prepare(
    `SELECT id, password_hash FROM users WHERE username = ?1`,
  )
    .bind(username)
    .first<{ id: string; password_hash: string }>()
  if (!row || !isPasswordHash(row.password_hash)) {
    await dummyVerify()
    return null
  }
  return (await verifyPassword(password, row.password_hash)) ? row.id : null
}

async function loadFolderByName(
  db: D1Database,
  userId: string,
  parentId: string | null,
  name: string,
): Promise<FolderRow | null> {
  const row = await db
    .prepare(
      `SELECT ${FOLDER_COLUMNS} FROM folders f
        WHERE f.user_id = ?1 AND f.parent_id IS ?2 AND f.name = ?3 AND f.deleted_at IS NULL`,
    )
    .bind(userId, parentId, name)
    .first<FolderRow>()
  return row ?? null
}

async function loadNoteByTitle(
  db: D1Database,
  userId: string,
  folderId: string | null,
  title: string,
): Promise<NoteRow | null> {
  const row = await db
    .prepare(
      `SELECT ${NOTE_COLUMNS_FULL} FROM notes n
        WHERE n.user_id = ?1 AND n.folder_id IS ?2 AND n.title = ?3 AND n.deleted_at IS NULL
        ORDER BY n.created_at ASC, n.id ASC LIMIT 1`,
    )
    .bind(userId, folderId, title)
    .first<NoteRow>()
  if (row) return row
  if (!title.includes('／')) return null
  return (
    (await db
      .prepare(
        `SELECT ${NOTE_COLUMNS_FULL} FROM notes n
          WHERE n.user_id = ?1 AND n.folder_id IS ?2 AND n.title = ?3 AND n.deleted_at IS NULL
          ORDER BY n.created_at ASC, n.id ASC LIMIT 1`,
      )
      .bind(userId, folderId, title.replaceAll('／', '/'))
      .first<NoteRow>()) ?? null
  )
}

async function resolveTarget(
  db: D1Database,
  userId: string,
  segments: string[],
): Promise<DavTarget> {
  if (segments.length === 0) return { kind: 'root' }
  let parentId: string | null = null
  for (let index = 0; index < segments.length - 1; index++) {
    const segment = segments[index]!
    if (segment.endsWith('.md')) return { kind: 'broken' }
    const folder = await loadFolderByName(db, userId, parentId, segment)
    if (!folder) return { kind: 'broken' }
    parentId = folder.id
  }
  const leaf = segments[segments.length - 1]!
  if (leaf.endsWith('.md')) {
    const title = filenameToTitle(leaf)
    if (title === null) throw ApiError.badRequest('Invalid file name')
    const note = await loadNoteByTitle(db, userId, parentId, title)
    if (note) return { kind: 'note', note }
    return { kind: 'absent', parentId, leaf }
  }
  const folder = await loadFolderByName(db, userId, parentId, leaf)
  if (folder) return { kind: 'folder', folder }
  const attachment = await loadDavAttachment(db, userId, parentId, leaf)
  if (attachment) {
    return { kind: 'attachment', note: attachment.note, attachment: attachment.attachment }
  }
  return { kind: 'absent', parentId, leaf }
}

async function loadAttachmentByFilename(
  db: D1Database,
  userId: string,
  noteId: string,
  filename: string,
): Promise<DavAttachmentRow | null> {
  const row = await db
    .prepare(
      `SELECT id, note_id, filename, mime, size, storage, created_at FROM attachments
        WHERE user_id = ?1 AND note_id = ?2 AND filename = ?3
        ORDER BY created_at DESC, id DESC LIMIT 1`,
    )
    .bind(userId, noteId, filename)
    .first<DavAttachmentRow>()
  return row ?? null
}

async function loadNoteAttachments(
  db: D1Database,
  userId: string,
  noteId: string,
): Promise<DavAttachmentRow[]> {
  const { results } = await db
    .prepare(
      `SELECT id, note_id, filename, mime, size, storage, created_at FROM attachments
        WHERE user_id = ?1 AND note_id = ?2 ORDER BY created_at ASC, id ASC`,
    )
    .bind(userId, noteId)
    .all<DavAttachmentRow>()
  return results
}

async function reloadNote(
  db: D1Database,
  userId: string,
  noteId: string,
): Promise<NoteRow | null> {
  const row = await db
    .prepare(
      `SELECT ${NOTE_COLUMNS_FULL} FROM notes n
        WHERE n.user_id = ?1 AND n.id = ?2 AND n.deleted_at IS NULL`,
    )
    .bind(userId, noteId)
    .first<NoteRow>()
  return row ?? null
}

/** Find the DAV attachment for a non-.md leaf, if its host note and file exist. */
async function loadDavAttachment(
  db: D1Database,
  userId: string,
  parentId: string | null,
  leaf: string,
): Promise<{ note: NoteRow; attachment: DavAttachmentRow } | null> {
  const title = davNoteTitleForFile(leaf)
  if (title === null) return null
  const note = await loadNoteByTitle(db, userId, parentId, title)
  if (!note) return null
  const attachment = await loadAttachmentByFilename(
    db,
    userId,
    note.id,
    sanitizeAttachmentFilename(leaf),
  )
  if (!attachment) return null
  return { note, attachment }
}

/**
 * Delete an attachment row and queue its stored object for cleanup, mirroring
 * the /api/files delete flow. The object itself is removed by the drain that
 * follows; failures to drain are retried later by the maintenance cron.
 */
async function deleteAttachmentRow(
  env: AppBindings['Bindings'],
  userId: string,
  row: DavAttachmentRow,
): Promise<void> {
  const key = attachmentObjectKey({
    user_id: userId,
    id: row.id,
    mime: row.mime,
    filename: row.filename,
  })
  const db = env.DB
  const results = await db.batch([
    db.prepare(
      `INSERT OR IGNORE INTO attachment_cleanup (object_key, user_id, created_at)
       SELECT ?1, user_id, ?2 FROM attachments WHERE id = ?3 AND user_id = ?4`,
    ).bind(attachmentCleanupTarget(row.storage, key), Date.now(), row.id, userId),
    db.prepare(
      `DELETE FROM import_mappings
        WHERE user_id = ?1 AND entity = 'attachment' AND target_id = ?2`,
    ).bind(userId, row.id),
    db.prepare(`DELETE FROM attachments WHERE id = ?1 AND user_id = ?2`).bind(row.id, userId),
  ])
  if (!results.at(-1)?.meta.changes) throw ApiError.notFound('Attachment not found')
  await drainAttachmentCleanup(env, userId).catch((error) => {
    console.warn('[inkstone] DAV attachment cleanup will retry later:', error)
  })
}

/**
 * Rename an attachment file. The stored object key is derived from the file
 * extension, so when the extension changes the object is copied to its new
 * key first and the old key deleted; same-extension renames keep the object.
 */
async function renameAttachmentFile(
  env: AppBindings['Bindings'],
  userId: string,
  row: DavAttachmentRow,
  newFilename: string,
): Promise<DavAttachmentRow> {
  const oldKey = attachmentObjectKey({
    user_id: userId,
    id: row.id,
    mime: row.mime,
    filename: row.filename,
  })
  const newKey = attachmentObjectKey({
    user_id: userId,
    id: row.id,
    mime: row.mime,
    filename: newFilename,
  })
  if (oldKey !== newKey) {
    const bytes = await readAttachmentObject(env, row.storage, oldKey)
    if (bytes === null) throw ApiError.notFound('Attachment data is missing')
    await putAttachmentObject(env, row.storage, newKey, bytes, {
      userId,
      objectId: row.id,
      kind: 'attachment',
      filename: newFilename,
      mime: row.mime,
      sha256: await sha256Hex(bytes),
    })
    await deleteAttachmentObjects(env, row.storage, [oldKey])
  }
  const updated = await env.DB.prepare(
    `UPDATE attachments SET filename = ?1 WHERE id = ?2 AND user_id = ?3`,
  )
    .bind(newFilename, row.id, userId)
    .run()
  if (!updated.meta.changes) throw ApiError.notFound('Attachment not found')
  return { ...row, filename: newFilename }
}

async function loadFolderGraph(db: D1Database, userId: string): Promise<FolderGraphRow[]> {
  const { results } = await db
    .prepare(
      `SELECT id, parent_id, name FROM folders WHERE user_id = ?1 AND deleted_at IS NULL`,
    )
    .bind(userId)
    .all<FolderGraphRow>()
  return results
}

function graphDepth(graph: FolderGraphRow[], id: string | null): number {
  const parents = new Map(graph.map((row) => [row.id, row.parent_id]))
  let depth = 0
  let cursor = id
  const seen = new Set<string>()
  while (cursor && !seen.has(cursor)) {
    seen.add(cursor)
    depth++
    cursor = parents.get(cursor) ?? null
  }
  return depth
}

function graphSubtreeHeight(graph: FolderGraphRow[], rootId: string): number {
  const children = new Map<string, string[]>()
  for (const row of graph) {
    const key = row.parent_id ?? ''
    const list = children.get(key) ?? []
    list.push(row.id)
    children.set(key, list)
  }
  let height = 1
  const stack: Array<[string, number]> = [[rootId, 1]]
  const seen = new Set<string>()
  while (stack.length) {
    const [id, depth] = stack.pop()!
    if (seen.has(id)) continue
    seen.add(id)
    height = Math.max(height, depth)
    for (const child of children.get(id) ?? []) stack.push([child, depth + 1])
  }
  return height
}

function graphContainsDescendant(
  graph: FolderGraphRow[],
  ancestorId: string,
  folderId: string | null,
): boolean {
  const parents = new Map(graph.map((row) => [row.id, row.parent_id]))
  let cursor = folderId
  const seen = new Set<string>()
  while (cursor && !seen.has(cursor)) {
    if (cursor === ancestorId) return true
    seen.add(cursor)
    cursor = parents.get(cursor) ?? null
  }
  return false
}

function parseDepth(raw: string | undefined): 0 | 1 {
  if (raw === undefined) return 1
  const value = raw.trim().toLowerCase()
  if (value === '0') return 0
  if (value === '1' || value === 'infinity') return 1
  throw ApiError.badRequest('Unsupported Depth header')
}

function buildMultistatus(entries: PropfindEntry[]): string {
  const responses = entries
    .map((entry) => {
      const props = entry.isCollection
        ? `<D:displayname>${escapeXml(entry.displayName)}</D:displayname>` +
          `<D:getlastmodified>${formatHttpDate(entry.lastModified)}</D:getlastmodified>` +
          `<D:resourcetype><D:collection/></D:resourcetype>`
        : `<D:displayname>${escapeXml(entry.displayName)}</D:displayname>` +
          `<D:getcontentlength>${entry.contentLength ?? 0}</D:getcontentlength>` +
          `<D:getcontenttype>${escapeXml(entry.contentType ?? 'text/markdown')}</D:getcontenttype>` +
          `<D:getlastmodified>${formatHttpDate(entry.lastModified)}</D:getlastmodified>` +
          `<D:resourcetype/>`
      return (
        `<D:response><D:href>${escapeXml(entry.href)}</D:href>` +
        `<D:propstat><D:prop>${props}</D:prop>` +
        `<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`
      )
    })
    .join('')
  return `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${responses}</D:multistatus>`
}

async function listChildren(
  c: Context<AppBindings>,
  folderId: string | null,
  parentSegments: string[],
): Promise<PropfindEntry[]> {
  const userId = c.get('userId')
  const db = c.env.DB
  const { results: folders } = await db
    .prepare(
      `SELECT ${FOLDER_COLUMNS} FROM folders f
        WHERE f.user_id = ?1 AND f.parent_id IS ?2 AND f.deleted_at IS NULL
        ORDER BY f.name COLLATE NOCASE ASC`,
    )
    .bind(userId, folderId)
    .all<FolderRow>()
  const { results: notes } = await db
    .prepare(
      `SELECT n.id, n.title, n.content, n.updated_at FROM notes n
        WHERE n.user_id = ?1 AND n.folder_id IS ?2 AND n.deleted_at IS NULL
        ORDER BY n.title COLLATE NOCASE ASC`,
    )
    .bind(userId, folderId)
    .all<{ id: string; title: string; content: string; updated_at: number }>()
  const entries: PropfindEntry[] = []
  for (const folder of folders) {
    if (folder.name.endsWith('.md')) continue
    entries.push({
      href: davHref([...parentSegments, folder.name], true),
      displayName: folder.name,
      isCollection: true,
      contentLength: null,
      lastModified: folder.updated_at,
    })
  }
  const seen = new Set<string>()
  for (const note of notes) {
    const filename = noteFilename(note.title) ?? `${sanitizeTitle(note.title)}.md`
    if (seen.has(filename)) continue
    seen.add(filename)
    entries.push({
      href: davHref([...parentSegments, filename], false),
      displayName: filename,
      isCollection: false,
      contentLength: utf8ByteLength(note.content),
      lastModified: note.updated_at,
    })
  }
  // Attachments are visible in DAV only when their file stem maps back to
  // their host note's title, so every listed file can be fetched by its path.
  const { results: attachments } = await db
    .prepare(
      `SELECT a.filename, a.mime, a.size, a.created_at, n.title AS note_title
         FROM attachments a JOIN notes n ON n.id = a.note_id
        WHERE a.user_id = ?1 AND n.user_id = ?1 AND n.folder_id IS ?2 AND n.deleted_at IS NULL
        ORDER BY a.filename COLLATE NOCASE ASC`,
    )
    .bind(userId, folderId)
    .all<{ filename: string; mime: string; size: number; created_at: number; note_title: string }>()
  for (const attachment of attachments) {
    if (davNoteTitleForFile(attachment.filename) !== attachment.note_title) continue
    if (seen.has(attachment.filename)) continue
    seen.add(attachment.filename)
    entries.push({
      href: davHref([...parentSegments, attachment.filename], false),
      displayName: attachment.filename,
      isCollection: false,
      contentLength: attachment.size,
      lastModified: attachment.created_at,
      contentType: attachment.mime,
    })
  }
  return entries
}

async function handlePropfind(c: Context<AppBindings>): Promise<Response> {
  const segments = davSegments(c)
  const depth = parseDepth(c.req.header('Depth'))
  const target = await resolveTarget(c.env.DB, c.get('userId'), segments)
  if (target.kind === 'broken' || target.kind === 'absent') {
    throw ApiError.notFound('Content not found')
  }
  const entries: PropfindEntry[] = []
  if (target.kind === 'root') {
    const children = await listChildren(c, null, [])
    entries.push({
      href: '/dav/',
      displayName: 'Inkstone',
      isCollection: true,
      contentLength: null,
      lastModified:
        children.reduce((max, child) => Math.max(max, child.lastModified), 0) || Date.now(),
    })
    if (depth === 1) entries.push(...children)
  } else if (target.kind === 'folder') {
    const children = await listChildren(c, target.folder.id, segments)
    entries.push({
      href: davHref(segments, true),
      displayName: target.folder.name,
      isCollection: true,
      contentLength: null,
      lastModified: target.folder.updated_at,
    })
    if (depth === 1) entries.push(...children)
  } else if (target.kind === 'attachment') {
    entries.push({
      href: davHref(segments, false),
      displayName: segments[segments.length - 1]!,
      isCollection: false,
      contentLength: target.attachment.size,
      lastModified: target.attachment.created_at,
      contentType: target.attachment.mime,
    })
  } else {
    entries.push({
      href: davHref(segments, false),
      displayName: segments[segments.length - 1]!,
      isCollection: false,
      contentLength: utf8ByteLength(target.note.content),
      lastModified: target.note.updated_at,
    })
  }
  return new Response(buildMultistatus(entries), {
    status: 207,
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  })
}

async function handleGet(c: Context<AppBindings>, headOnly: boolean): Promise<Response> {
  const segments = davSegments(c)
  const target = await resolveTarget(c.env.DB, c.get('userId'), segments)
  if (target.kind === 'attachment') {
    const row = target.attachment
    const headers = new Headers({
      'Content-Type': row.mime,
      'Content-Length': String(row.size),
      'Content-Disposition': `${isInlineSafe(row.mime) ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeContentDispositionFilename(row.filename)}`,
      'Cache-Control': 'private, no-store',
      'Last-Modified': formatHttpDate(row.created_at),
      'X-Content-Type-Options': 'nosniff',
    })
    if (headOnly) return new Response(null, { status: 200, headers })
    const object = await readAttachmentObjectStream(
      c.env,
      row.storage,
      attachmentObjectKey({ user_id: c.get('userId'), id: row.id, mime: row.mime, filename: row.filename }),
    )
    if (!object) throw ApiError.notFound('Attachment data is missing')
    return new Response(object.body as BodyInit, { status: 200, headers })
  }
  if (target.kind !== 'note') throw ApiError.notFound('Content not found')
  const content = target.note.content
  const headers = {
    'Content-Type': 'text/markdown; charset=utf-8',
    'Content-Length': String(utf8ByteLength(content)),
  }
  if (headOnly) return new Response(null, { status: 200, headers })
  return new Response(content, { status: 200, headers })
}

async function readDavBody(c: Context<AppBindings>): Promise<string> {
  const stream = c.req.raw?.body
  if (!stream) return ''
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > LIMITS.contentMaxBytes) {
        await reader.cancel()
        throw ApiError.tooLarge(`Note content exceeds the ${LIMITS.contentMaxBytes / 1_000_000} MB limit`)
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(bytes)
}

/** Read a raw request body as bytes, capped at the attachment size limit. */
async function readDavBytes(c: Context<AppBindings>): Promise<Uint8Array> {
  const stream = c.req.raw?.body
  if (!stream) return new Uint8Array(0)
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > LIMITS.attachmentMaxBytes) {
        await reader.cancel()
        throw ApiError.tooLarge('The file exceeds the 25 MB limit')
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

async function handlePut(c: Context<AppBindings>): Promise<Response> {
  const segments = davSegments(c)
  if (segments.length === 0) throw ApiError.conflict('Cannot write to a collection')
  const target = await resolveTarget(c.env.DB, c.get('userId'), segments)
  if (target.kind === 'folder') throw ApiError.conflict('Cannot write to a collection')
  if (target.kind === 'broken') throw ApiError.conflict('The parent folder does not exist')
  const leaf = segments[segments.length - 1]!
  if (leaf.endsWith('.md')) {
    const content = await readDavBody(c)
    assertContentSize(content)
    if (target.kind === 'note') {
      await updateNoteContent(c, target.note, content)
      return new Response(null, { status: 204 })
    }
    if (target.kind !== 'absent') throw ApiError.conflict('Cannot write to a collection')
    await insertNote(c, target.parentId, resolveDavTitle(leaf), content)
    return new Response(null, { status: 201 })
  }
  if (target.kind === 'note') throw ApiError.conflict('Cannot write to a collection')
  const bytes = await readDavBytes(c)
  if (target.kind === 'attachment') {
    await replaceDavAttachment(c, target.note, target.attachment, leaf, bytes)
    return new Response(null, { status: 204 })
  }
  if (target.kind !== 'absent') throw ApiError.conflict('Cannot write to a collection')
  await createDavAttachment(c, target.parentId, leaf, bytes)
  return new Response(null, { status: 201 })
}

/**
 * Store a new DAV attachment file. The file lives on a note titled with the
 * file stem in the same folder; the note is created when missing, and its
 * body holds a link to the attachment so the file survives orphan pruning.
 */
async function createDavAttachment(
  c: Context<AppBindings>,
  parentId: string | null,
  leaf: string,
  bytes: Uint8Array,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  const title = davNoteTitleForFile(leaf)
  if (title === null) throw ApiError.badRequest('Invalid file name')
  const filename = sanitizeAttachmentFilename(leaf)
  const reportedMime = davReportedMime(leaf, c.req.header('Content-Type'))
  const existing = await loadNoteByTitle(db, userId, parentId, title)
  if (!existing) {
    const attachmentId = newId()
    await insertNote(c, parentId, title, attachmentLinkLine(filename, attachmentId))
    const note = await loadNoteByTitle(db, userId, parentId, title)
    if (!note) throw ApiError.conflict('The note could not be created')
    try {
      await persistAttachmentWithinQuota(c.env, {
        id: attachmentId,
        userId,
        noteId: note.id,
        filename,
        reportedMime,
        bytes,
        createdAt: Date.now(),
      })
    } catch (error) {
      await trashNote(c, note).catch(() => {})
      throw error
    }
    return
  }
  const attachmentId = newId()
  const stored = await persistAttachmentWithinQuota(c.env, {
    id: attachmentId,
    userId,
    noteId: existing.id,
    filename,
    reportedMime,
    bytes,
    createdAt: Date.now(),
  })
  try {
    const fresh = await reloadNote(db, userId, existing.id)
    if (!fresh) throw ApiError.conflict('The note could not be created')
    await updateNoteContent(c, fresh, withAttachmentLink(fresh.content, filename, attachmentId))
  } catch (error) {
    await deleteAttachmentRow(c.env, userId, {
      id: stored.id,
      note_id: stored.noteId,
      filename: stored.filename,
      mime: stored.mime,
      size: stored.size,
      storage: stored.storage,
      created_at: stored.createdAt,
    }).catch(() => {})
    throw error
  }
}

/** Replace an existing DAV attachment file with new bytes (same path). */
async function replaceDavAttachment(
  c: Context<AppBindings>,
  note: NoteRow,
  oldRow: DavAttachmentRow,
  leaf: string,
  bytes: Uint8Array,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  const filename = sanitizeAttachmentFilename(leaf)
  const reportedMime = davReportedMime(leaf, c.req.header('Content-Type'))
  const attachmentId = newId()
  const stored = await persistAttachmentWithinQuota(c.env, {
    id: attachmentId,
    userId,
    noteId: note.id,
    filename,
    reportedMime,
    bytes,
    createdAt: Date.now(),
  })
  try {
    const fresh = await reloadNote(db, userId, note.id)
    if (!fresh) throw ApiError.conflict('The note could not be created')
    await updateNoteContent(c, fresh, withAttachmentLink(fresh.content, filename, attachmentId))
  } catch (error) {
    await deleteAttachmentRow(c.env, userId, {
      id: stored.id,
      note_id: stored.noteId,
      filename: stored.filename,
      mime: stored.mime,
      size: stored.size,
      storage: stored.storage,
      created_at: stored.createdAt,
    }).catch(() => {})
    throw error
  }
  await deleteAttachmentRow(c.env, userId, oldRow)
}

async function insertNote(
  c: Context<AppBindings>,
  folderId: string | null,
  title: string,
  content: string,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  const { ftsEnabled } = c.get('database')
  const now = Date.now()
  const id = newId()
  const hash = await sha256Hex(content)
  const { words, chars } = countText(content)
  const insert = db.prepare(
    `INSERT OR IGNORE INTO notes (id, user_id, folder_id, title, content, excerpt, rev, word_count, char_count,
       is_pinned, is_starred, is_archived, position, content_hash, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, 0, 0, 0, ?9, ?10, ?11, ?11)`,
  ).bind(id, userId, folderId, title, content, deriveExcerpt(content), words, chars, now, hash, now)
  const derived = buildNoteDerivedStatements({
    db,
    userId,
    noteId: id,
    title,
    content,
    ftsEnabled,
    expectedRev: 1,
    expectedContentHash: hash,
    expectedTitle: title,
    expectedUpdatedAt: now,
  }).statements
  const change = db.prepare(
    `INSERT INTO changes (user_id, entity, entity_id, op, at)
     SELECT ?1, 'note', ?2, 'upsert', ?3
      WHERE EXISTS (
        SELECT 1 FROM notes
         WHERE id = ?2 AND user_id = ?1 AND rev = 1
           AND content_hash = ?4 AND title = ?5 AND created_at = ?3 AND updated_at = ?3
      )`,
  ).bind(userId, id, now, hash, title)
  const [insertResult] = await db.batch([insert, ...derived, change])
  if (!insertResult?.meta.changes) throw ApiError.conflict('The note could not be created')
  await broadcastCursor(c)
  await enqueueNoteIndex(db, userId, id, 'embed')
  scheduleFtsDrain(c)
}

async function updateNoteContent(
  c: Context<AppBindings>,
  row: NoteRow,
  content: string,
): Promise<void> {
  if (content === row.content) return
  const db = c.env.DB
  const userId = c.get('userId')
  const { ftsEnabled } = c.get('database')
  const now = Math.max(Date.now(), row.updated_at + 1)
  const nextRev = row.rev + 1
  const hash = await sha256Hex(content)
  const { words, chars } = countText(content)
  const mutationGuard = `EXISTS (SELECT 1 FROM notes
    WHERE id = ?1 AND user_id = ?2 AND rev = ?3
      AND content_hash = ?4 AND title = ?5 AND updated_at = ?6)`
  const mutationValues = [row.id, userId, nextRev, hash, row.title, now] as const
  const update = db.prepare(
    `UPDATE notes SET content = ?1, content_hash = ?2, excerpt = ?3, word_count = ?4, char_count = ?5,
       updated_at = ?6, rev = ?7
       WHERE id = ?8 AND user_id = ?9 AND rev = ?10`,
  ).bind(content, hash, deriveExcerpt(content), words, chars, now, nextRev, row.id, userId, row.rev)
  const statements: D1PreparedStatement[] = [update]
  if (row.content) {
    const snapshotId = newId()
    const bigChange = Math.abs(content.length - row.content.length) >= SNAPSHOT_DIFF_THRESHOLD
    statements.push(
      db.prepare(
        `INSERT INTO note_versions (id, note_id, user_id, title, content, size, created_at)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
          WHERE ${shiftSqlPlaceholders(mutationGuard, 7)}
            AND (?14 = 1
                 OR NOT EXISTS (SELECT 1 FROM note_versions WHERE note_id = ?2)
                 OR ?15 - COALESCE((SELECT MAX(created_at) FROM note_versions WHERE note_id = ?2), 0) > ?16
                 OR ?17 = 1)`,
      ).bind(
        snapshotId,
        row.id,
        userId,
        row.title,
        row.content,
        utf8ByteLength(row.content),
        now,
        ...mutationValues,
        0,
        now,
        SNAPSHOT_INTERVAL_MS,
        bigChange ? 1 : 0,
      ),
      db.prepare(
        `DELETE FROM note_versions WHERE note_id = ?1
           AND EXISTS (SELECT 1 FROM note_versions WHERE id = ?9)
           AND ${shiftSqlPlaceholders(mutationGuard, 1)}
           AND id IN (
             SELECT id FROM note_versions WHERE note_id = ?1 ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?8)`,
      ).bind(row.id, ...mutationValues, LIMITS.versionsPerNote, snapshotId),
    )
  }
  const derived = buildNoteDerivedStatements({
    db,
    userId,
    noteId: row.id,
    title: row.title,
    content,
    ftsEnabled,
    expectedRev: nextRev,
    expectedContentHash: hash,
    expectedTitle: row.title,
    expectedUpdatedAt: now,
  })
  statements.push(...derived.statements)
  if (!sameTagSet(splitTags(row.tag_names), derived.tags)) {
    statements.push(
      db.prepare(
        `DELETE FROM tags WHERE user_id = ?1 AND is_manual = 0
           AND ${shiftSqlPlaceholders(mutationGuard, 1)}
           AND NOT EXISTS (SELECT 1 FROM note_tags WHERE tag_id = tags.id)`,
      ).bind(userId, ...mutationValues),
    )
  }
  statements.push(
    db.prepare(
      `INSERT INTO changes (user_id, entity, entity_id, op, at)
       SELECT ?1, 'note', ?2, 'upsert', ?3
        WHERE ${shiftSqlPlaceholders(mutationGuard, 3)}
       RETURNING seq`,
    ).bind(userId, row.id, now, ...mutationValues),
  )
  const results = await db.batch(statements)
  if (!results[0]?.meta.changes) {
    throw ApiError.conflict('This note was modified elsewhere')
  }
  const changeResult = results.at(-1) as D1Result<{ seq: number }> | undefined
  await broadcastCursor(c, changeResult?.results?.[0]?.seq)
  await enqueueNoteIndex(db, userId, row.id, 'embed')
  scheduleFtsDrain(c)
}

function sameTagSet(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false
  const set = new Set(left)
  return right.every((name) => set.has(name))
}

function trashNoteStatements(
  db: D1Database,
  userId: string,
  row: NoteRow,
  ftsEnabled: boolean,
): D1PreparedStatement[] {
  const now = Math.max(Date.now(), row.updated_at + 1)
  const nextRev = row.rev + 1
  const guard = `EXISTS (SELECT 1 FROM notes
    WHERE id = ?1 AND user_id = ?2 AND rev = ?3 AND deleted_at IS NOT NULL)`
  const guardValues = [row.id, userId, nextRev] as const
  const statements: D1PreparedStatement[] = [
    db.prepare(
      `UPDATE notes SET deleted_at = ?1, updated_at = ?1, rev = ?2
        WHERE id = ?3 AND user_id = ?4 AND rev = ?5 AND deleted_at IS NULL`,
    ).bind(now, nextRev, row.id, userId, row.rev),
    db.prepare(
      `DELETE FROM links WHERE source_note_id = ?1 AND ${shiftSqlPlaceholders(guard, 1)}`,
    ).bind(row.id, ...guardValues),
    db.prepare(
      `UPDATE links SET target_note_id = ${LINK_TARGET_SUBQUERY}
        WHERE target_note_id = ?1 AND user_id = ?2 AND ${shiftSqlPlaceholders(guard, 2)}`,
    ).bind(row.id, userId, ...guardValues),
  ]
  if (ftsEnabled) {
    statements.push(
      db.prepare(
        `INSERT INTO fts_index_queue (user_id, note_id, kind, created_at)
         SELECT ?1, ?2, 'delete', ?3 WHERE ${shiftSqlPlaceholders(guard, 3)}
         ${FTS_QUEUE_CONFLICT_SQL}`,
      ).bind(userId, row.id, now, ...guardValues),
    )
  }
  statements.push(
    db.prepare(
      `INSERT OR REPLACE INTO ai_index_queue (user_id, note_id, kind, created_at)
       SELECT ?1, ?2, 'delete', ?3 WHERE ${shiftSqlPlaceholders(guard, 3)}
         AND ${aiDeleteNeededSql('?1', '?2')}`,
    ).bind(userId, row.id, now, ...guardValues),
    db.prepare(
      `INSERT INTO changes (user_id, entity, entity_id, op, at)
       SELECT ?1, 'note', ?2, 'upsert', ?3 WHERE ${shiftSqlPlaceholders(guard, 3)}
       RETURNING seq`,
    ).bind(userId, row.id, now, ...guardValues),
  )
  return statements
}

async function trashNote(c: Context<AppBindings>, row: NoteRow): Promise<void> {
  const { ftsEnabled } = c.get('database')
  const statements = trashNoteStatements(c.env.DB, c.get('userId'), row, ftsEnabled)
  const results = await c.env.DB.batch(statements)
  if (!results[0]?.meta.changes) {
    throw ApiError.conflict('This note was modified elsewhere')
  }
  const changeResult = results.at(-1) as D1Result<{ seq: number }> | undefined
  await broadcastCursor(c, changeResult?.results?.[0]?.seq)
  scheduleFtsDrain(c)
}

async function countFolderContents(
  db: D1Database,
  userId: string,
  folderId: string,
): Promise<number> {
  const row = await db
    .prepare(
      `WITH RECURSIVE subtree(id) AS (
         SELECT id FROM folders WHERE id = ?1 AND user_id = ?2 AND deleted_at IS NULL
         UNION ALL
         SELECT f.id FROM folders f JOIN subtree s ON f.parent_id = s.id
          WHERE f.user_id = ?2 AND f.deleted_at IS NULL
       )
       SELECT
         (SELECT COUNT(*) FROM notes
           WHERE user_id = ?2 AND deleted_at IS NULL AND folder_id IN (SELECT id FROM subtree))
         + (SELECT COUNT(*) FROM subtree WHERE id <> ?1) AS total`,
    )
    .bind(folderId, userId)
    .first<{ total: number }>()
  return row?.total ?? 0
}

async function deleteFolderRow(c: Context<AppBindings>, folder: FolderRow): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  const now = Date.now()
  const results = await db.batch([
    db.prepare(
      `INSERT INTO changes (user_id, entity, entity_id, op, at)
       SELECT ?1, 'folder', ?2, 'delete', ?3
        WHERE EXISTS (SELECT 1 FROM folders WHERE id = ?2 AND user_id = ?1)`,
    ).bind(userId, folder.id, now),
    db.prepare(
      `DELETE FROM folders WHERE id = ?1 AND user_id = ?2 AND deleted_at IS NULL`,
    ).bind(folder.id, userId),
  ])
  if (!results[1]?.meta.changes) throw ApiError.conflict('The folder changed elsewhere')
  await broadcastCursor(c)
}

/** Replace the link line for one attachment with a renamed file name. */
export function renameAttachmentLink(
  content: string,
  oldFilename: string,
  newFilename: string,
  attachmentId: string,
): string {
  return content
    .split('\n')
    .map((line) => {
      const match = DAV_ATTACHMENT_LINE_RE.exec(line.trim())
      if (match && match[1] === oldFilename) {
        return attachmentLinkLine(newFilename, attachmentId)
      }
      return line
    })
    .join('\n')
}

/**
 * Delete a DAV attachment file. When its host note was created by DAV and
 * nothing remains in it (no link lines, no other attachments), the empty
 * note is trashed as well; user-written notes are kept, minus the link line.
 */
async function deleteDavAttachment(
  c: Context<AppBindings>,
  note: NoteRow,
  attachment: DavAttachmentRow,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  await deleteAttachmentRow(c.env, userId, attachment)
  const fresh = await reloadNote(db, userId, note.id)
  if (!fresh) return
  const newContent = withoutAttachmentLink(fresh.content, attachment.filename)
  const lines = parseDavAttachmentLines(fresh.content)
  const remaining = await loadNoteAttachments(db, userId, note.id)
  if (
    lines !== null &&
    remaining.length === 0 &&
    (parseDavAttachmentLines(newContent)?.length ?? -1) === 0
  ) {
    await trashNote(c, fresh)
    return
  }
  if (newContent !== fresh.content) {
    await updateNoteContent(c, fresh, newContent)
  }
}

async function handleDelete(c: Context<AppBindings>): Promise<Response> {
  const segments = davSegments(c)
  if (segments.length === 0) throw ApiError.forbidden('Cannot delete the root folder')
  const target = await resolveTarget(c.env.DB, c.get('userId'), segments)
  if (target.kind === 'note') {
    await trashNote(c, target.note)
    return new Response(null, { status: 204 })
  }
  if (target.kind === 'attachment') {
    await deleteDavAttachment(c, target.note, target.attachment)
    return new Response(null, { status: 204 })
  }
  if (target.kind === 'folder') {
    const count = await countFolderContents(c.env.DB, c.get('userId'), target.folder.id)
    if (count > 0) throw ApiError.conflict('The folder is not empty')
    await deleteFolderRow(c, target.folder)
    return new Response(null, { status: 204 })
  }
  throw ApiError.notFound('Content not found')
}

async function handleMkcol(c: Context<AppBindings>): Promise<Response> {
  const segments = davSegments(c)
  if (segments.length === 0) return methodNotAllowed()
  const target = await resolveTarget(c.env.DB, c.get('userId'), segments)
  if (target.kind === 'folder' || target.kind === 'note' || target.kind === 'attachment') {
    return methodNotAllowed()
  }
  if (target.kind === 'broken') throw ApiError.conflict('The parent folder does not exist')
  const leaf = segments[segments.length - 1]!
  if (leaf.endsWith('.md')) throw ApiError.badRequest('Folder names cannot end with .md')
  const name = leaf.trim()
  if (!name) throw ApiError.badRequest('Folder name cannot be empty')
  if (name.length > LIMITS.folderNameMaxLength) throw ApiError.badRequest('Folder name is too long')
  if (target.kind !== 'absent') throw ApiError.notFound('Content not found')
  const db = c.env.DB
  const userId = c.get('userId')
  const graph = await loadFolderGraph(db, userId)
  if (graphDepth(graph, target.parentId) >= LIMITS.folderDepthMax) {
    throw ApiError.badRequest(`Folder depth cannot exceed ${LIMITS.folderDepthMax} levels`)
  }
  if (
    graph.some(
      (row) =>
        row.parent_id === target.parentId && row.name.toLowerCase() === name.toLowerCase(),
    )
  ) {
    return methodNotAllowed()
  }
  await createFolder(c, target.parentId, name)
  return new Response(null, { status: 201 })
}

async function createFolder(
  c: Context<AppBindings>,
  parentId: string | null,
  name: string,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  const id = newId()
  const now = Date.now()
  const positionRow = await db
    .prepare(
      `SELECT MAX(position) AS max_position FROM folders
        WHERE user_id = ?1 AND parent_id IS ?2 AND deleted_at IS NULL`,
    )
    .bind(userId, parentId)
    .first<{ max_position: number | null }>()
  const position = (positionRow?.max_position ?? 0) + 1000
  const insert = db.prepare(
    `INSERT OR IGNORE INTO folders (id, user_id, parent_id, name, icon, color, position, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, ?6, ?6)`,
  ).bind(id, userId, parentId, name, position, now)
  const change = db.prepare(
    `INSERT INTO changes (user_id, entity, entity_id, op, at)
     SELECT ?1, 'folder', ?2, 'upsert', ?3
      WHERE EXISTS (SELECT 1 FROM folders WHERE id = ?2 AND user_id = ?1)`,
  ).bind(userId, id, now)
  const [created] = await db.batch([insert, change])
  if (!created?.meta.changes) {
    throw ApiError.conflict('The parent folder changed or a sibling already uses this name')
  }
  await broadcastCursor(c)
}

async function handleMoveCopy(c: Context<AppBindings>, method: 'MOVE' | 'COPY'): Promise<Response> {
  const segments = davSegments(c)
  if (segments.length === 0) throw ApiError.forbidden('Cannot move the root folder')
  const db = c.env.DB
  const userId = c.get('userId')
  const source = await resolveTarget(db, userId, segments)
  if (source.kind === 'broken' || source.kind === 'absent') {
    throw ApiError.notFound('Content not found')
  }
  if (source.kind === 'root') throw ApiError.badRequest('Invalid WebDAV path')
  const destination = c.req.header('Destination')
  if (!destination) throw ApiError.badRequest('Missing Destination header')
  const destSegments = parseDestination(destination, c.req.url)
  if (destSegments === 'foreign') {
    return new Response('Destination must be on the same server', { status: 502 })
  }
  if (destSegments === null) throw ApiError.badRequest('Invalid Destination header')
  if (destSegments.length === 0) throw ApiError.forbidden('Cannot move to the root folder')
  const overwrite = c.req.header('Overwrite')?.trim().toUpperCase() !== 'F'
  const dest = await resolveTarget(db, userId, destSegments)
  if (dest.kind === 'broken') throw ApiError.conflict('The destination parent folder does not exist')
  if (dest.kind === 'root') throw ApiError.badRequest('Invalid Destination header')
  if (source.kind === 'note') {
    const destLeaf = destSegments[destSegments.length - 1]!
    if (!destLeaf.endsWith('.md')) throw ApiError.conflict('Destination must be a note file')
    if (dest.kind === 'folder') throw ApiError.conflict('Destination is a folder')
    if (dest.kind === 'attachment') throw ApiError.conflict('Destination must be a note file')
    const title = resolveDavTitle(destLeaf)
    const destFolderId = dest.kind === 'note' ? dest.note.folder_id : dest.parentId
    let replaced = false
    if (dest.kind === 'note') {
      if (dest.note.id === source.note.id) return new Response(null, { status: 204 })
      if (!overwrite) return preconditionFailed()
      await trashNote(c, dest.note)
      replaced = true
    }
    if (method === 'MOVE') {
      await moveNote(c, source.note, destFolderId, title)
    } else {
      await insertNote(c, destFolderId, title, source.note.content)
    }
    return new Response(null, { status: replaced ? 204 : 201 })
  }
  if (source.kind === 'attachment') {
    if (method === 'COPY') throw ApiError.forbidden('Copying an attachment is not supported')
    return handleMoveAttachment(c, source, destSegments, dest, overwrite)
  }
  if (method === 'COPY') throw ApiError.forbidden('Copying a folder is not supported')
  const destLeaf = destSegments[destSegments.length - 1]!
  if (destLeaf.endsWith('.md')) throw ApiError.badRequest('Destination must be a folder')
  if (dest.kind === 'note') throw ApiError.conflict('Destination is a note')
  if (dest.kind === 'attachment') throw ApiError.conflict('Destination must be a folder')
  let replaced = false
  if (dest.kind === 'folder') {
    if (dest.folder.id === source.folder.id) return new Response(null, { status: 204 })
    if (!overwrite) return preconditionFailed()
    const count = await countFolderContents(db, userId, dest.folder.id)
    if (count > 0) throw ApiError.conflict('The destination folder is not empty')
    await deleteFolderRow(c, dest.folder)
    replaced = true
  }
  await moveFolder(c, source.folder, dest.kind === 'folder' ? dest.folder.parent_id : dest.parentId, destLeaf.trim())
  return new Response(null, { status: replaced ? 204 : 201 })
}

async function handleMoveAttachment(
  c: Context<AppBindings>,
  source: { note: NoteRow; attachment: DavAttachmentRow },
  destSegments: string[],
  dest: DavTarget,
  overwrite: boolean,
): Promise<Response> {
  const db = c.env.DB
  const userId = c.get('userId')
  const destLeaf = destSegments[destSegments.length - 1]!
  if (destLeaf.endsWith('.md')) throw ApiError.conflict('Destination must be a file')
  if (dest.kind === 'folder') throw ApiError.conflict('Destination is a folder')
  if (dest.kind === 'note') throw ApiError.conflict('Destination must be a file')
  if (dest.kind === 'broken') throw ApiError.conflict('The destination parent folder does not exist')
  if (dest.kind === 'root') throw ApiError.badRequest('Invalid Destination header')
  const destParentId = dest.kind === 'attachment' ? dest.note.folder_id : dest.parentId
  const srcNote = source.note
  const srcAtt = source.attachment
  const srcTitle = davNoteTitleForFile(srcAtt.filename)
  const destTitle = davNoteTitleForFile(destLeaf)
  if (srcTitle === null || destTitle === null) throw ApiError.badRequest('Invalid file name')
  const newFilename = sanitizeAttachmentFilename(destLeaf)
  const sameFolder = destParentId === srcNote.folder_id
  const sameStem = destTitle === srcTitle

  // Moving into a folder that already has a different note with the target
  // title would silently merge the file into that note; refuse instead.
  // The one exception is overwriting a DAV file whose host note will be
  // trashed together with it, leaving the title free.
  const clash = await loadNoteByTitle(db, userId, destParentId, destTitle)
  if (clash && clash.id !== srcNote.id) {
    let willVanish = false
    if (dest.kind === 'attachment' && dest.note.id === clash.id) {
      const clashLines = parseDavAttachmentLines(clash.content)
      const clashAttachments = await loadNoteAttachments(db, userId, clash.id)
      willVanish =
        clashLines !== null &&
        clashLines.length === 1 &&
        clashLines[0]?.filename === dest.attachment.filename &&
        clashAttachments.length === 1
    }
    if (!willVanish) {
      throw ApiError.conflict('A note with the destination title already exists')
    }
  }

  if (dest.kind === 'attachment') {
    if (dest.attachment.id === srcAtt.id) return new Response(null, { status: 204 })
    if (!overwrite) return preconditionFailed()
    await deleteDavAttachment(c, dest.note, dest.attachment)
  }

  const fresh = await reloadNote(db, userId, srcNote.id)
  if (!fresh) throw ApiError.notFound('Content not found')

  if (sameFolder && sameStem) {
    // Extension-only rename: the host note keeps its title and folder.
    if (newFilename !== srcAtt.filename) {
      await renameAttachmentFile(c.env, userId, srcAtt, newFilename)
      const note = await reloadNote(db, userId, srcNote.id)
      if (note) {
        await updateNoteContent(
          c,
          note,
          renameAttachmentLink(note.content, srcAtt.filename, newFilename, srcAtt.id),
        )
      }
    }
    return new Response(null, { status: 201 })
  }

  // Renaming the stem or moving across folders also renames/moves the host
  // note, so the file keeps its path mapping. That is only safe for notes
  // DAV created as attachment indexes; user-written notes are refused.
  if (parseDavAttachmentLines(fresh.content) === null) {
    throw ApiError.conflict('Cannot move this attachment because its note is not managed by WebDAV')
  }
  const srcStem = fileStem(srcAtt.filename)
  const newStem = fileStem(newFilename)
  const siblings = (await loadNoteAttachments(db, userId, srcNote.id)).filter(
    (row) => fileStem(row.filename) === srcStem,
  )
  let content = fresh.content
  for (const sibling of siblings) {
    const extension = sibling.filename.slice((fileStem(sibling.filename) ?? '').length)
    const siblingNew = sanitizeAttachmentFilename(`${newStem ?? ''}${extension}`)
    if (siblingNew === sibling.filename) continue
    await renameAttachmentFile(c.env, userId, sibling, siblingNew)
    content = renameAttachmentLink(content, sibling.filename, siblingNew, sibling.id)
  }
  const noteAfterRename = await reloadNote(db, userId, srcNote.id)
  if (!noteAfterRename) throw ApiError.notFound('Content not found')
  if (content !== noteAfterRename.content) {
    await updateNoteContent(c, noteAfterRename, content)
  }
  const noteAfterContent = await reloadNote(db, userId, srcNote.id)
  if (!noteAfterContent) throw ApiError.notFound('Content not found')
  await moveNote(c, noteAfterContent, destParentId, destTitle)
  return new Response(null, { status: 201 })
}

async function moveNote(
  c: Context<AppBindings>,
  row: NoteRow,
  folderId: string | null,
  title: string,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  const { ftsEnabled } = c.get('database')
  const titleChanged = title !== row.title
  const folderChanged = folderId !== row.folder_id
  if (!titleChanged && !folderChanged) return
  const now = Math.max(Date.now(), row.updated_at + 1)
  const nextRev = row.rev + 1
  const mutationGuard = `EXISTS (SELECT 1 FROM notes
    WHERE id = ?1 AND user_id = ?2 AND rev = ?3
      AND content_hash = ?4 AND title = ?5 AND updated_at = ?6)`
  const mutationValues = [row.id, userId, nextRev, row.content_hash, title, now] as const
  const update = db.prepare(
    `UPDATE notes SET title = ?1, folder_id = ?2, updated_at = ?3, rev = ?4
      WHERE id = ?5 AND user_id = ?6 AND rev = ?7`,
  ).bind(title, folderId, now, nextRev, row.id, userId, row.rev)
  const statements: D1PreparedStatement[] = [update]
  if (titleChanged) {
    const derived = buildNoteDerivedStatements({
      db,
      userId,
      noteId: row.id,
      title,
      content: row.content,
      ftsEnabled,
      titleChanged: true,
      previousTitle: row.title,
      expectedRev: nextRev,
      expectedContentHash: row.content_hash,
      expectedTitle: title,
      expectedUpdatedAt: now,
    })
    statements.push(...derived.statements)
  }
  statements.push(
    db.prepare(
      `INSERT INTO changes (user_id, entity, entity_id, op, at)
       SELECT ?1, 'note', ?2, 'upsert', ?3
        WHERE ${shiftSqlPlaceholders(mutationGuard, 3)}
       RETURNING seq`,
    ).bind(userId, row.id, now, ...mutationValues),
  )
  const results = await db.batch(statements)
  if (!results[0]?.meta.changes) {
    throw ApiError.conflict('This note was modified elsewhere')
  }
  const changeResult = results.at(-1) as D1Result<{ seq: number }> | undefined
  await broadcastCursor(c, changeResult?.results?.[0]?.seq)
  if (titleChanged) {
    await enqueueNoteIndex(db, userId, row.id, 'embed')
    scheduleFtsDrain(c)
  }
}

async function moveFolder(
  c: Context<AppBindings>,
  folder: FolderRow,
  destParentId: string | null,
  name: string,
): Promise<void> {
  const db = c.env.DB
  const userId = c.get('userId')
  if (!name) throw ApiError.badRequest('Folder name cannot be empty')
  if (name.length > LIMITS.folderNameMaxLength) throw ApiError.badRequest('Folder name is too long')
  const graph = await loadFolderGraph(db, userId)
  if (graphContainsDescendant(graph, folder.id, destParentId)) {
    throw ApiError.forbidden('A folder cannot be moved into its own descendant')
  }
  const depth = graphDepth(graph, destParentId) + graphSubtreeHeight(graph, folder.id)
  if (depth > LIMITS.folderDepthMax) {
    throw ApiError.badRequest(`Folder depth cannot exceed ${LIMITS.folderDepthMax} levels`)
  }
  if (
    graph.some(
      (row) =>
        row.id !== folder.id &&
        row.parent_id === destParentId &&
        row.name.toLowerCase() === name.toLowerCase(),
    )
  ) {
    throw ApiError.conflict('A sibling folder already uses this name')
  }
  const parentChanged = destParentId !== folder.parent_id
  const nameChanged = name !== folder.name
  if (!parentChanged && !nameChanged) return
  const now = Math.max(Date.now(), folder.updated_at + 1)
  let position = folder.position
  if (parentChanged) {
    const positionRow = await db
      .prepare(
        `SELECT MAX(position) AS max_position FROM folders
          WHERE user_id = ?1 AND parent_id IS ?2 AND deleted_at IS NULL`,
      )
      .bind(userId, destParentId)
      .first<{ max_position: number | null }>()
    position = (positionRow?.max_position ?? 0) + 1000
  }
  const update = db.prepare(
    `UPDATE folders SET parent_id = ?1, name = ?2, position = ?3, updated_at = ?4
      WHERE id = ?5 AND user_id = ?6 AND updated_at = ?7 AND deleted_at IS NULL`,
  ).bind(destParentId, name, position, now, folder.id, userId, folder.updated_at)
  const change = db.prepare(
    `INSERT INTO changes (user_id, entity, entity_id, op, at)
     SELECT ?1, 'folder', ?2, 'upsert', ?3
      WHERE EXISTS (SELECT 1 FROM folders WHERE id = ?2 AND user_id = ?1 AND updated_at = ?3)`,
  ).bind(userId, folder.id, now)
  const [updated] = await db.batch([update, change])
  if (!updated?.meta.changes) {
    throw ApiError.conflict('The folder changed elsewhere or a sibling already uses this name')
  }
  await broadcastCursor(c)
}

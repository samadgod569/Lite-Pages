/**
 * Fast Site – Cloudflare Worker (static assets + D1 file storage)
 *
 * Bindings needed:
 *   DB         D1 database  (table app_files, see schema below)
 *   ASSETS     static assets binding (already in your project)
 *   ADMIN_KEY  secret / variable – same key your backend sends
 *
 *   CREATE TABLE app_files (
 *     appid TEXT NOT NULL, file_path TEXT NOT NULL,
 *     file_content BLOB NOT NULL, info TEXT,
 *     PRIMARY KEY (appid, file_path)
 *   );
 *
 * How files are stored
 *   - A file is split in 1.5 MB chunks (D1 row limit is 2 MB).
 *   - Chunk 0 lives at  file_path = "<path>"            and holds the metadata in `info`:
 *         {"type":"file","size":N,"chunks":K,"chunkSize":1572864,"modified":"ISO"}
 *   - Chunk i>0 lives at file_path = "<path>\x1f<i padded to 5>"   info = {"type":"chunk","index":i}
 *     (\x1f can never appear in a real path, so no collisions)
 *   - Empty folders (mkdir) are rows with info = {"type":"dir"}; other folders are implicit.
 *
 * Auth (any one):  x-admin-key: <key>  |  Authorization: Bearer <key>  |  "adminKey" in JSON body (max 64 KB)
 *
 * Endpoints (all POST, JSON unless noted):
 *   /api/files/write      { appId, path, content, encoding? }
 *   /api/files/read       { appId, path, encoding? }
 *   /api/files/raw        { appId, path }                      file streamed back
 *   /api/files/list       { appId, path? }
 *   /api/files/delete     { appId, path }                      file or folder
 *   /api/files/delete-all { appId }
 *   /api/files/rename     { appId, path, newName }
 *   /api/files/move       { appId, from, to, overwrite? }
 *   /api/files/mkdir      { appId, path }
 *   /api/files/upload     multipart: appId, path?, extract?, file   (header auth only)
 *   /api/files/extract    { appId, path, to?, deleteArchive? }  .zip .tar .tar.gz .tgz
 *   GET /health
 */

// ---------------------------------------------------------------- limits
const MB = 1024 * 1024;
const CHUNK_SIZE = 1.5 * MB;          // 1,572,864 bytes per D1 row
const SEP = "\x1f";                   // separates path and chunk number
const MAX_FILE_BYTES = 20 * MB;       // one file (Workers have 128 MB RAM)
const MAX_UPLOAD_BYTES = 40 * MB;     // one multipart upload (archives may be bigger than a file)
const MAX_EXTRACT_BYTES = 100 * MB;   // everything inside one archive
const MAX_APP_BYTES = 500 * MB;       // whole app
const MAX_ENTRIES = 1000;             // entries inside one archive
const MAX_DEPTH = 20;                 // folder depth
const MAX_JSON_BYTES = Math.ceil(MAX_FILE_BYTES * 4 / 3) + 64 * 1024; // base64 of a max file
const SMALL_JSON_BYTES = 64 * 1024;   // body limit when the key is inside the body

// ---------------------------------------------------------------- helpers
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const APP_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
function checkAppId(appId) {
  if (typeof appId !== "string" || !APP_ID_RE.test(appId)) throw new HttpError(400, "Invalid appId");
  return appId;
}

function checkName(name) {
  if (typeof name !== "string" || !name || name === "." || name === ".." || name.length > 255 ||
      /[\x00-\x1f\x7f/\\]/.test(name)) {
    throw new HttpError(400, "Invalid file or folder name");
  }
  return name;
}

// "a/b/c.html" -> ["a","b","c.html"]
function segments(rel, { allowEmpty = false } = {}) {
  if (rel === undefined || rel === null) rel = "";
  if (typeof rel !== "string") throw new HttpError(400, "Path must be a string");
  if (rel.includes("\0") || rel.includes("\\")) throw new HttpError(400, "Invalid path");
  const parts = rel.split("/").filter(p => p !== "");
  if (!parts.length && !allowEmpty) throw new HttpError(400, "Path is required");
  if (parts.length > MAX_DEPTH) throw new HttpError(400, "Path is too deep");
  parts.forEach(checkName);
  return parts;
}

function archiveParts(name) {
  const parts = String(name).replace(/\\/g, "/").split("/").filter(p => p !== "" && p !== ".");
  if (parts.length > MAX_DEPTH) throw new HttpError(400, "Archive path is too deep: " + name);
  try { parts.forEach(checkName); }
  catch { throw new HttpError(400, "Archive contains an unsafe path: " + name); }
  return parts;
}

const nowIso = () => new Date().toISOString();
const enc = new TextEncoder();
const dec = new TextDecoder();

function parseInfo(s) {
  try { const v = JSON.parse(s); return v && typeof v === "object" ? v : {}; } catch { return {}; }
}

// D1 gives BLOBs back as number[] (or ArrayBuffer, depending on version)
function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  if (Array.isArray(v)) return Uint8Array.from(v);
  return new Uint8Array(0);
}

function b64ToBytes(s) {
  let bin;
  try { bin = atob(s); } catch { throw new HttpError(400, "content is not valid base64"); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(u8) {
  const parts = [];
  for (let i = 0; i < u8.length; i += 0x8000) parts.push(String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)));
  return btoa(parts.join(""));
}

const MIME = {
  html: "text/html; charset=utf-8", htm: "text/html; charset=utf-8", css: "text/css; charset=utf-8",
  js: "text/javascript; charset=utf-8", mjs: "text/javascript; charset=utf-8", json: "application/json; charset=utf-8",
  txt: "text/plain; charset=utf-8", md: "text/markdown; charset=utf-8", csv: "text/csv; charset=utf-8",
  xml: "application/xml; charset=utf-8", svg: "image/svg+xml", map: "application/json; charset=utf-8",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp",
  avif: "image/avif", ico: "image/x-icon", woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf",
  otf: "font/otf", mp4: "video/mp4", webm: "video/webm", mp3: "audio/mpeg", wav: "audio/wav",
  ogg: "audio/ogg", pdf: "application/pdf", wasm: "application/wasm", zip: "application/zip",
};
function mimeFor(p) {
  const name = p.slice(p.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return null; // no extension
  return MIME[name.slice(dot + 1).toLowerCase()] || "application/octet-stream";
}

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...extra } });
const ok = (data = {}) => json({ success: true, ...data });

// ---------------------------------------------------------------- D1 helpers
const chunkPath = (p, i) => (i === 0 ? p : p + SEP + String(i).padStart(5, "0"));

// What is at this path?  null | {kind:"dir"} | {kind:"file", info}
async function statPath(env, appId, p) {
  if (p === "") return { kind: "dir" };
  const row = await env.DB.prepare("SELECT info FROM app_files WHERE appid = ?1 AND file_path = ?2").bind(appId, p).first();
  if (row) {
    const info = parseInfo(row.info);
    return info.type === "dir" ? { kind: "dir" } : { kind: "file", info };
  }
  const sub = await env.DB.prepare(
    "SELECT 1 AS x FROM app_files WHERE appid = ?1 AND substr(file_path, 1, length(?2)) = ?2 LIMIT 1"
  ).bind(appId, p + "/").first();
  return sub ? { kind: "dir" } : null;
}

// None of the parent folders of `parts` may be a file.
async function checkAncestors(env, appId, parts) {
  if (parts.length < 2) return;
  const anc = [];
  for (let k = 1; k < parts.length; k++) anc.push(parts.slice(0, k).join("/"));
  const ph = anc.map((_, i) => "?" + (i + 2)).join(",");
  const row = await env.DB.prepare(
    `SELECT file_path FROM app_files WHERE appid = ?1 AND file_path IN (${ph}) AND json_extract(info, '$.type') = 'file' LIMIT 1`
  ).bind(appId, ...anc).first();
  if (row) throw new HttpError(409, "A parent path is a file: " + row.file_path);
}

async function usedBytes(env, appId) {
  const r = await env.DB.prepare(
    "SELECT COALESCE(SUM(json_extract(info, '$.size')), 0) AS n FROM app_files WHERE appid = ?1 AND json_extract(info, '$.type') = 'file'"
  ).bind(appId).first();
  return (r && r.n) || 0;
}

async function checkQuota(env, appId, extra) {
  if (extra <= 0) return;
  if ((await usedBytes(env, appId)) + extra > MAX_APP_BYTES) {
    throw new HttpError(413, "Storage limit reached for this app (" + MAX_APP_BYTES / MB + " MB)");
  }
}

// DELETE statement for a file (all its chunks)
const delFileStmt = (env, appId, p) =>
  env.DB.prepare("DELETE FROM app_files WHERE appid = ?1 AND (file_path = ?2 OR substr(file_path, 1, length(?3)) = ?3)")
    .bind(appId, p, p + SEP);

// DELETE statement for a file OR a whole folder (and every chunk inside)
const delTreeStmt = (env, appId, p) =>
  env.DB.prepare(
    `DELETE FROM app_files WHERE appid = ?1 AND (file_path = ?2
       OR substr(file_path, 1, length(?3)) = ?3 OR substr(file_path, 1, length(?4)) = ?4)`
  ).bind(appId, p, p + "/", p + SEP);

// Rename/move a file or folder (rows keep their chunks together)
const moveStmt = (env, appId, from, to) =>
  env.DB.prepare(
    `UPDATE app_files SET file_path = ?1 || substr(file_path, length(?2) + 1)
     WHERE appid = ?3 AND (file_path = ?2
       OR substr(file_path, 1, length(?4)) = ?4 OR substr(file_path, 1, length(?5)) = ?5)`
  ).bind(to, from, appId, from + "/", from + SEP);

// Statements that replace a file with `bytes`, split in 1.5 MB chunks
function fileStmts(env, appId, p, bytes, modified = nowIso()) {
  const n = Math.max(1, Math.ceil(bytes.length / CHUNK_SIZE));
  const ins = env.DB.prepare("INSERT INTO app_files (appid, file_path, file_content, info) VALUES (?1, ?2, ?3, ?4)");
  const stmts = [delFileStmt(env, appId, p)];
  for (let i = 0; i < n; i++) {
    const part = bytes.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    const buf = part.byteOffset === 0 && part.length === bytes.buffer.byteLength ? bytes.buffer : part.slice().buffer;
    const info = i === 0
      ? { type: "file", size: bytes.length, chunks: n, chunkSize: CHUNK_SIZE, modified }
      : { type: "chunk", index: i };
    stmts.push(ins.bind(appId, chunkPath(p, i), buf, JSON.stringify(info)));
  }
  return stmts;
}

const dirStmt = (env, appId, p, modified = nowIso()) =>
  env.DB.prepare("INSERT OR IGNORE INTO app_files (appid, file_path, file_content, info) VALUES (?1, ?2, ?3, ?4)")
    .bind(appId, p, new ArrayBuffer(0), JSON.stringify({ type: "dir", modified }));

async function getChunk(env, appId, p, i) {
  const row = await env.DB.prepare("SELECT file_content FROM app_files WHERE appid = ?1 AND file_path = ?2")
    .bind(appId, chunkPath(p, i)).first();
  if (!row) throw new HttpError(500, "File is corrupt (missing chunk " + i + ")");
  return toBytes(row.file_content);
}

// Whole file in memory (one chunk at a time, so the number[] copies stay small)
async function readFileBytes(env, appId, p, info) {
  const n = info.chunks || 1;
  const out = new Uint8Array(info.size || 0);
  let off = 0;
  for (let i = 0; i < n; i++) {
    const c = await getChunk(env, appId, p, i);
    if (off + c.length > out.length) throw new HttpError(500, "File is corrupt (size mismatch)");
    out.set(c, off);
    off += c.length;
  }
  if (off !== out.length) throw new HttpError(500, "File is corrupt (size mismatch)");
  return out;
}

// Validates and stores one file
async function writeOne(env, appId, parts, bytes) {
  if (bytes.length > MAX_FILE_BYTES) throw new HttpError(413, "File is too large");
  const p = parts.join("/");
  await checkAncestors(env, appId, parts);
  const st = await statPath(env, appId, p);
  if (st && st.kind === "dir") throw new HttpError(409, "A folder with that name already exists");
  await checkQuota(env, appId, bytes.length - (st ? st.info.size || 0 : 0));
  await env.DB.batch(fileStmts(env, appId, p, bytes));
  return p;
}

// ---------------------------------------------------------------- archives
function archiveKind(name) {
  const n = name.toLowerCase();
  if (n.endsWith(".zip")) return "zip";
  if (n.endsWith(".tar.gz") || n.endsWith(".tgz") || n.endsWith(".tar")) return "tar";
  return null;
}
const skipJunk = name => /(^|\/)(__MACOSX|\.DS_Store)(\/|$)/.test(name);

async function inflateRaw(raw, max) {
  try {
    const reader = new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
    const parts = [];
    let n = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      n += value.length;
      if (n > max) { await reader.cancel(); throw new HttpError(400, "A file inside the archive is corrupt"); }
      parts.push(value);
    }
    const out = new Uint8Array(n);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, "Could not read a file inside the zip (corrupt?)");
  }
}

// yields { parts, isDir, size, data? }.  data only when wantData is true.
async function* zipEntries(bytes, wantData) {
  const size = bytes.length;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bad = () => new HttpError(400, "Could not read the zip file");
  let p = -1;
  for (let i = size - 22; i >= Math.max(0, size - 65557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { p = i; break; }
  }
  if (p < 0) throw bad();
  const total = dv.getUint16(p + 10, true), cdSize = dv.getUint32(p + 12, true), cdOffset = dv.getUint32(p + 16, true);
  if (total === 0xFFFF || cdSize === 0xFFFFFFFF || cdOffset === 0xFFFFFFFF) throw new HttpError(400, "zip64 archives are not supported");
  if (cdOffset + cdSize > size) throw bad();
  if (total > MAX_ENTRIES) throw new HttpError(413, "Archive has too many files");

  let pos = cdOffset;
  for (let i = 0; i < total; i++) {
    if (pos + 46 > size || dv.getUint32(pos, true) !== 0x02014b50) throw bad();
    const flags = dv.getUint16(pos + 8, true), method = dv.getUint16(pos + 10, true);
    const csize = dv.getUint32(pos + 20, true), usize = dv.getUint32(pos + 24, true);
    const nlen = dv.getUint16(pos + 28, true), elen = dv.getUint16(pos + 30, true), clen = dv.getUint16(pos + 32, true);
    const attr = dv.getUint32(pos + 38, true), lho = dv.getUint32(pos + 42, true);
    const name = dec.decode(bytes.subarray(pos + 46, pos + 46 + nlen)).replace(/\\/g, "/");
    pos += 46 + nlen + elen + clen;

    if (skipJunk(name)) continue;
    if (((attr >>> 16) & 0o170000) === 0o120000) continue; // symlink: never extracted
    const parts = archiveParts(name);
    if (!parts.length) continue;
    if (name.endsWith("/")) { yield { parts, isDir: true, size: 0 }; continue; }

    if ((flags & 1) || (method !== 0 && method !== 8) || csize === 0xFFFFFFFF || usize === 0xFFFFFFFF || lho === 0xFFFFFFFF) {
      throw new HttpError(400, "Unsupported zip entry (encrypted or unusual compression): " + name);
    }
    if (usize > MAX_FILE_BYTES) throw new HttpError(413, "A file inside the archive is too large");

    let data;
    if (wantData) {
      if (lho + 30 > size || dv.getUint32(lho, true) !== 0x04034b50) throw bad();
      const start = lho + 30 + dv.getUint16(lho + 26, true) + dv.getUint16(lho + 28, true);
      if (start + csize > size) throw bad();
      const raw = bytes.subarray(start, start + csize);
      data = method === 8 ? await inflateRaw(raw, usize) : raw.slice();
      if (data.length !== usize) throw new HttpError(400, "\"" + name + "\" is corrupt");
    }
    yield { parts, isDir: false, size: usize, data };
  }
}

// Reads a byte stream in pieces without ever concatenating it all
class ByteReader {
  constructor(stream) { this.r = stream.getReader(); this.q = []; this.len = 0; this.eof = false; }
  async more() {
    const { value, done } = await this.r.read();
    if (done) { this.eof = true; return false; }
    if (value.length) { this.q.push(value); this.len += value.length; }
    return true;
  }
  async take(n) {
    while (this.len < n && !this.eof) await this.more();
    const m = Math.min(n, this.len);
    const out = new Uint8Array(m);
    let off = 0;
    while (off < m) {
      const head = this.q[0], need = m - off;
      if (head.length <= need) { out.set(head, off); off += head.length; this.q.shift(); }
      else { out.set(head.subarray(0, need), off); this.q[0] = head.subarray(need); off += need; }
    }
    this.len -= m;
    return out;
  }
  async skip(n) {
    while (n > 0) {
      if (!this.len && !(await this.more())) return;
      const head = this.q[0];
      if (head.length <= n) { n -= head.length; this.len -= head.length; this.q.shift(); }
      else { this.q[0] = head.subarray(n); this.len -= n; n = 0; }
    }
  }
}

async function* tarEntries(bytes, wantData) {
  try {
    let stream = new Blob([bytes]).stream();
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) stream = stream.pipeThrough(new DecompressionStream("gzip"));
    const rd = new ByteReader(stream);
    let longName = null, paxPath = null, seen = 0;

    for (;;) {
      const h = await rd.take(512);
      if (h.length < 512 || h.every(b => b === 0)) break;
      const str = (a, b) => { let e = a; while (e < b && h[e] !== 0) e++; return dec.decode(h.subarray(a, e)); };
      let name = str(0, 100);
      if (str(257, 262) === "ustar") { const pre = str(345, 500); if (pre) name = pre + "/" + name; }
      if (h[124] & 0x80) throw new HttpError(413, "A file inside the archive is too large");
      const size = parseInt(str(124, 136).trim() || "0", 8);
      if (!Number.isFinite(size) || size < 0) throw new Error("bad size");
      const type = String.fromCharCode(h[156] || 48);
      const pad = (512 - (size % 512)) % 512;

      if (type === "L" || type === "x" || type === "g") {
        if (size > 65536) throw new Error("bad header");
        const d = await rd.take(size);
        await rd.skip(pad);
        if (type === "L") longName = dec.decode(d).replace(/\0+$/, "");
        else if (type === "x") { const m = /(?:^|\n)\d+ path=([^\n]*)/.exec(dec.decode(d)); if (m) paxPath = m[1]; }
        continue;
      }
      if (longName) { name = longName; longName = null; }
      if (paxPath) { name = paxPath; paxPath = null; }
      if (++seen > MAX_ENTRIES) throw new HttpError(413, "Archive has too many files");

      if (type === "5") {
        await rd.skip(size + pad);
        if (skipJunk(name.replace(/\\/g, "/"))) continue;
        const parts = archiveParts(name);
        if (parts.length) yield { parts, isDir: true, size: 0 };
      } else if (type === "0" || type === "7") {
        if (size > MAX_FILE_BYTES) throw new HttpError(413, "A file inside the archive is too large");
        let data;
        if (wantData) {
          data = await rd.take(size);
          if (data.length !== size) throw new Error("truncated");
        } else {
          await rd.skip(size);
        }
        await rd.skip(pad);
        if (skipJunk(name.replace(/\\/g, "/"))) continue;
        const parts = archiveParts(name);
        if (parts.length) yield { parts, isDir: false, size, data };
      } else {
        await rd.skip(size + pad); // symlinks, hard links, devices: never extracted
      }
    }
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, "Could not read the tar file");
  }
}

// All paths already stored for the app (no file contents)
async function loadTree(env, appId) {
  const { results } = await env.DB.prepare(
    "SELECT file_path, json_extract(info, '$.type') AS t FROM app_files WHERE appid = ?1 AND instr(file_path, char(31)) = 0"
  ).bind(appId).all();
  const files = new Set(), dirs = new Set();
  for (const r of results) {
    const segs = r.file_path.split("/");
    const upto = r.t === "dir" ? segs.length : segs.length - 1;
    for (let k = 1; k <= upto; k++) dirs.add(segs.slice(0, k).join("/"));
    if (r.t !== "dir") files.add(r.file_path);
  }
  return { files, dirs };
}

// Checks the whole archive first, writes only if everything is fine.
async function extractInto(env, appId, bytes, kind, destParts) {
  const iterate = want => (kind === "zip" ? zipEntries(bytes, want) : tarEntries(bytes, want));

  // pass 1: validate + plan (no file data kept)
  const plan = [];
  let files = 0, total = 0;
  for await (const e of iterate(false)) {
    if (plan.length >= MAX_ENTRIES) throw new HttpError(413, "Archive has too many files");
    if (!e.isDir) {
      files++; total += e.size;
      if (total > MAX_EXTRACT_BYTES) throw new HttpError(413, "Archive is too large when unpacked");
    }
    plan.push({ path: [...destParts, ...e.parts].join("/"), isDir: e.isDir });
  }
  if (!plan.length) return { files: 0, bytes: 0 };
  await checkQuota(env, appId, total);

  const tree = await loadTree(env, appId);
  const newFiles = new Set(), newDirs = new Set();
  for (const e of plan) {
    const segs = e.path.split("/");
    for (let k = 1; k < segs.length; k++) {
      const anc = segs.slice(0, k).join("/");
      if (tree.files.has(anc) || newFiles.has(anc)) throw new HttpError(409, "Archive conflicts with an existing file: " + anc);
      newDirs.add(anc);
    }
    if (e.isDir) {
      if (tree.files.has(e.path) || newFiles.has(e.path)) throw new HttpError(409, "Archive conflicts with an existing file: " + e.path);
      newDirs.add(e.path);
    } else {
      if (tree.dirs.has(e.path) || newDirs.has(e.path)) throw new HttpError(409, "A folder named \"" + e.path + "\" already exists");
      newFiles.add(e.path);
    }
  }

  // pass 2: write in batches
  const modified = nowIso();
  let stmts = [], pending = 0;
  const flush = async () => { if (stmts.length) { await env.DB.batch(stmts); stmts = []; pending = 0; } };
  for await (const e of iterate(true)) {
    const p = [...destParts, ...e.parts].join("/");
    if (e.isDir) stmts.push(dirStmt(env, appId, p, modified));
    else { stmts.push(...fileStmts(env, appId, p, e.data, modified)); pending += e.data.length; }
    if (stmts.length >= 50 || pending >= 8 * MB) await flush();
  }
  await flush();
  return { files, bytes: total };
}

// ---------------------------------------------------------------- auth + body
async function sha256(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}
async function keyMatches(env, k) {
  if (typeof k !== "string" || !k) return false;
  const [a, b] = await Promise.all([sha256(k), sha256(String(env.ADMIN_KEY))]);
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
const denied = () => new HttpError(401, "Invalid or missing admin key");

function headerKey(request) {
  return request.headers.get("x-admin-key") || (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
}

async function readJson(request, limit) {
  const cl = Number(request.headers.get("content-length"));
  if (cl > limit) throw new HttpError(413, "Request body is too large");
  const text = await request.text();
  if (text.length > limit) throw new HttpError(413, "Request body is too large");
  if (!text.trim()) return {};
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? v : {};
  } catch { throw new HttpError(400, "Invalid JSON"); }
}

// ---------------------------------------------------------------- route handlers
const ROUTES = {};

// Store a page / file.  { appId, path (or fileName), content, encoding }
ROUTES["/api/files/write"] = async ({ env, body }) => {
  const { appId, content, encoding = "utf8" } = body;
  checkAppId(appId);
  if (typeof content !== "string") throw new HttpError(400, "content must be a string");
  if (encoding !== "utf8" && encoding !== "base64") throw new HttpError(400, "encoding must be utf8 or base64");
  const parts = segments(body.path ?? body.fileName);
  const bytes = encoding === "base64" ? b64ToBytes(content) : enc.encode(content);
  const p = await writeOne(env, appId, parts, bytes);
  return ok({ path: p, size: bytes.length });
};

ROUTES["/api/files/read"] = async ({ env, body }) => {
  const { appId, encoding = "utf8" } = body;
  checkAppId(appId);
  if (encoding !== "utf8" && encoding !== "base64") throw new HttpError(400, "encoding must be utf8 or base64");
  const p = segments(body.path ?? body.fileName).join("/");
  const st = await statPath(env, appId, p);
  if (!st) throw new HttpError(404, "File not found");
  if (st.kind === "dir") throw new HttpError(400, "That path is a folder");
  const size = st.info.size || 0;
  if (size > MAX_FILE_BYTES) throw new HttpError(413, "File is too large to read");
  const bytes = await readFileBytes(env, appId, p, st.info);
  return ok({ path: p, size, encoding, content: encoding === "base64" ? bytesToB64(bytes) : dec.decode(bytes) });
};

// The file itself, streamed chunk by chunk (only one chunk in RAM at a time)
ROUTES["/api/files/raw"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const p = segments(body.path ?? body.fileName).join("/");
  const st = await statPath(env, appId, p);
  if (!st) throw new HttpError(404, "File not found");
  if (st.kind === "dir") throw new HttpError(400, "That path is a folder");
  const n = st.info.chunks || 1;
  let first = await getChunk(env, appId, p, 0);
  let type = mimeFor(p);
  if (!type) {
    const head = dec.decode(first.subarray(0, 512));
    type = /^\s*<(!doctype html|html)/i.test(head) ? "text/html; charset=utf-8" : "application/octet-stream";
  }
  let i = 0;
  const stream = new ReadableStream({
    async pull(c) {
      try {
        const chunk = i === 0 ? first : await getChunk(env, appId, p, i);
        if (i === 0) first = null;
        i++;
        if (chunk.length) c.enqueue(chunk);
        if (i >= n) c.close();
      } catch (e) { c.error(e); }
    },
  });
  return new Response(stream, { headers: { "Content-Type": type } });
};

ROUTES["/api/files/list"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const parts = segments(body.path, { allowEmpty: true });
  const p = parts.join("/");
  const st = await statPath(env, appId, p);
  if (!st) throw new HttpError(404, "Folder not found");
  if (st.kind === "file") throw new HttpError(400, "That path is a file");
  const prefix = p ? p + "/" : "";
  const { results } = await env.DB.prepare(
    "SELECT file_path, info FROM app_files WHERE appid = ?1 AND instr(file_path, char(31)) = 0 AND substr(file_path, 1, length(?2)) = ?2"
  ).bind(appId, prefix).all();

  const latest = (a, b) => (!a ? b : !b ? a : a > b ? a : b);
  const map = new Map();
  const folder = (name, modified) => {
    const it = map.get(name) || { name, type: "folder", size: 0, modified: null };
    it.modified = latest(it.modified, modified);
    map.set(name, it);
  };
  for (const r of results) {
    const rel = r.file_path.slice(prefix.length);
    if (!rel) continue;
    const info = parseInfo(r.info);
    const slash = rel.indexOf("/");
    if (slash >= 0) folder(rel.slice(0, slash), info.modified || null);
    else if (info.type === "dir") folder(rel, info.modified || null);
    else map.set(rel, { name: rel, type: "file", size: info.size || 0, modified: info.modified || null });
  }
  const items = [...map.values()].sort((a, b) =>
    a.type === b.type ? a.name.localeCompare(b.name) : a.type === "folder" ? -1 : 1);
  return ok({ path: p, items });
};

// Delete a file or a whole folder
ROUTES["/api/files/delete"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const p = segments(body.path ?? body.fileName).join("/");
  if (!(await statPath(env, appId, p))) throw new HttpError(404, "File or folder not found");
  await delTreeStmt(env, appId, p).run();
  return ok();
};

// Wipe everything stored for an app. Safe to call twice.
ROUTES["/api/files/delete-all"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const r = await env.DB.prepare(
    "SELECT COUNT(*) AS files, COALESCE(SUM(json_extract(info, '$.size')), 0) AS bytes FROM app_files WHERE appid = ?1 AND json_extract(info, '$.type') = 'file'"
  ).bind(appId).first();
  await env.DB.prepare("DELETE FROM app_files WHERE appid = ?1").bind(appId).run();
  return ok({ files: (r && r.files) || 0, bytes: (r && r.bytes) || 0 });
};

// Rename inside the same folder.  { appId, path, newName }
ROUTES["/api/files/rename"] = async ({ env, body }) => {
  const { appId, newName } = body;
  checkAppId(appId);
  checkName(newName);
  const parts = segments(body.path);
  const from = parts.join("/");
  if (!(await statPath(env, appId, from))) throw new HttpError(404, "File or folder not found");
  const to = [...parts.slice(0, -1), newName].join("/");
  if (await statPath(env, appId, to)) throw new HttpError(409, "Something with that name already exists");
  await moveStmt(env, appId, from, to).run();
  return ok({ path: to });
};

// Move into another folder (name kept).  { appId, from, to, overwrite? }
ROUTES["/api/files/move"] = async ({ env, body }) => {
  const { appId, overwrite = false } = body;
  checkAppId(appId);
  const srcParts = segments(body.from);
  const dstParts = segments(body.to, { allowEmpty: true });
  const src = srcParts.join("/");
  if (!(await statPath(env, appId, src))) throw new HttpError(404, "Source not found");
  const name = srcParts[srcParts.length - 1];
  const destParts = [...dstParts, name];
  const dest = destParts.join("/");
  if (dest === src) return ok({ path: dest });
  if (dest.startsWith(src + "/")) throw new HttpError(400, "Can't move a folder into itself");
  await checkAncestors(env, appId, destParts);
  const stmts = [];
  if (await statPath(env, appId, dest)) {
    if (overwrite !== true) throw new HttpError(409, "Something with that name already exists in the destination");
    stmts.push(delTreeStmt(env, appId, dest));
  }
  stmts.push(moveStmt(env, appId, src, dest));
  await env.DB.batch(stmts);
  return ok({ path: dest });
};

ROUTES["/api/files/mkdir"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const parts = segments(body.path ?? body.fileName);
  const p = parts.join("/");
  await checkAncestors(env, appId, parts);
  const st = await statPath(env, appId, p);
  if (st && st.kind === "file") throw new HttpError(409, "A file with that name already exists");
  if (!st) await dirStmt(env, appId, p).run();
  return ok({ path: p });
};

// Unzip / untar a file that is already stored.  { appId, path, to?, deleteArchive? }
ROUTES["/api/files/extract"] = async ({ env, body }) => {
  const { appId, deleteArchive = false } = body;
  checkAppId(appId);
  const srcParts = segments(body.path);
  const src = srcParts.join("/");
  const st = await statPath(env, appId, src);
  if (!st) throw new HttpError(404, "Archive not found");
  if (st.kind === "dir") throw new HttpError(400, "That path is a folder");
  const kind = archiveKind(srcParts[srcParts.length - 1]);
  if (!kind) throw new HttpError(400, "Only .zip, .tar, .tar.gz and .tgz files can be extracted");

  const destParts = segments(body.to === undefined ? srcParts.slice(0, -1).join("/") : body.to, { allowEmpty: true });
  if (destParts.length) {
    await checkAncestors(env, appId, [...destParts, "_"]);
    const ds = await statPath(env, appId, destParts.join("/"));
    if (ds && ds.kind === "file") throw new HttpError(409, "Destination is a file, not a folder");
  }
  if ((st.info.size || 0) > MAX_UPLOAD_BYTES) throw new HttpError(413, "Archive is too large to extract");

  const bytes = await readFileBytes(env, appId, src, st.info);
  const stats = await extractInto(env, appId, bytes, kind, destParts);
  if (deleteArchive === true) await delFileStmt(env, appId, src).run();
  return ok({ to: destParts.join("/"), ...stats });
};

// Upload one or more files (multipart, header auth only).  Fields: appId, path?, extract?, file
async function uploadRoute({ request, env }) {
  const cl = Number(request.headers.get("content-length"));
  if (cl > MAX_UPLOAD_BYTES) throw new HttpError(413, "File is too large");
  let form;
  try { form = await request.formData(); }
  catch { throw new HttpError(400, "Send the upload as multipart/form-data"); }

  const appId = form.get("appId");
  checkAppId(appId);
  const files = form.getAll("file").filter(f => typeof f !== "string");
  if (!files.length) throw new HttpError(400, "No file received (send it in the \"file\" field)");
  if (files.length > 100) throw new HttpError(400, "Too many files, or the wrong field name (use \"file\")");
  const extract = ["true", "1", "yes"].includes(String(form.get("extract")).toLowerCase());
  const destParts = segments(form.get("path") || "", { allowEmpty: true });

  const out = [];
  for (const f of files) {
    const name = checkName(f.name.replace(/\\/g, "/").split("/").pop());
    const kind = archiveKind(name);
    const bytes = new Uint8Array(await f.arrayBuffer());
    if (extract && kind) {
      if (destParts.length) {
        await checkAncestors(env, appId, [...destParts, "_"]);
        const ds = await statPath(env, appId, destParts.join("/"));
        if (ds && ds.kind === "file") throw new HttpError(409, "Destination path is a file");
      }
      const stats = await extractInto(env, appId, bytes, kind, destParts);
      out.push({ name, extracted: true, files: stats.files, bytes: stats.bytes });
    } else {
      if (bytes.length > MAX_FILE_BYTES) throw new HttpError(413, "\"" + name + "\" is too large");
      const p = await writeOne(env, appId, [...destParts, name], bytes);
      out.push({ name, extracted: false, size: bytes.length, path: p });
    }
  }
  return ok({ files: out });
}

// ---------------------------------------------------------------- API entry
function corsHeaders(request) {
  return {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-admin-key, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

async function route(request, env, url) {
  const p = url.pathname;
  if (p === "/health" && request.method === "GET") return json({ ok: true });
  const isUpload = p === "/api/files/upload";
  const handler = isUpload ? uploadRoute : ROUTES[p];
  if (!handler || request.method !== "POST") throw new HttpError(404, "Not found");
  if (!env.DB || !env.ADMIN_KEY) throw new HttpError(500, "Server is not configured (DB / ADMIN_KEY missing)");

  // step 1: key in the headers is checked before any body is read
  const hk = headerKey(request);
  if (hk && !(await keyMatches(env, hk))) throw denied();
  const authed = !!hk;

  if (isUpload) {
    if (!authed) throw denied(); // uploads: header auth only
    return uploadRoute({ request, env });
  }

  const body = await readJson(request, authed ? MAX_JSON_BYTES : SMALL_JSON_BYTES);
  // step 2: no header? then the key must be in the JSON body
  if (!authed && !(await keyMatches(env, body.adminKey))) throw denied();
  return handler({ request, env, body });
}

async function handleApi(request, env, url) {
  const cors = corsHeaders(request);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  try {
    const res = await route(request, env, url);
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    return out;
  } catch (err) {
    let status = 500, message = "Server error";
    if (err instanceof HttpError) { status = err.status; message = err.message; }
    else console.error(err);
    return json({ success: false, error: message }, status, cors);
  }
}

// ---------------------------------------------------------------- worker
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // storage API (files in D1)
    if (url.pathname === "/health" || url.pathname.startsWith("/api/")) {
      return handleApi(request, env, url);
    }

    // static site
    const pathname = url.pathname === "/" ? "/index.html" : url.pathname;

    if (pathname.includes("..")) {
      return new Response("Bad Request.", { status: 400 });
    }

    const assetRequest = new Request(
      new URL(pathname, url.origin),
      request
    );

    let response = await env.ASSETS.fetch(assetRequest);

    if (response.status === 404 && !pathname.includes(".")) {
      response = await env.ASSETS.fetch(
        new Request(new URL("/index.html", url.origin), request)
      );
    }

    return response;
  },
};

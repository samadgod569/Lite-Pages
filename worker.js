const MB = 1024 * 1024;
const CHUNK_SIZE = 1.5 * MB;
const SEP = "\x1f";
const MAX_FILE_BYTES = 20 * MB;
const MAX_UPLOAD_BYTES = 40 * MB;
const MAX_EXTRACT_BYTES = 100 * MB;
const MAX_APP_BYTES = 500 * MB;
const MAX_ENTRIES = 1000;
const MAX_DEPTH = 20;
const MAX_JSON_BYTES = Math.ceil(MAX_FILE_BYTES * 4 / 3) + 64 * 1024;
const SMALL_JSON_BYTES = 64 * 1024;

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
  if (dot <= 0) return null;
  return MIME[name.slice(dot + 1).toLowerCase()] || "application/octet-stream";
}

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...extra } });
const ok = (data = {}) => json({ success: true, ...data });

const chunkPath = (p, i) => (i === 0 ? p : p + SEP + String(i).padStart(5, "0"));

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

const delFileStmt = (env, appId, p) =>
  env.DB.prepare("DELETE FROM app_files WHERE appid = ?1 AND (file_path = ?2 OR substr(file_path, 1, length(?3)) = ?3)")
    .bind(appId, p, p + SEP);

const delTreeStmt = (env, appId, p) =>
  env.DB.prepare(
    `DELETE FROM app_files WHERE appid = ?1 AND (file_path = ?2
       OR substr(file_path, 1, length(?3)) = ?3 OR substr(file_path, 1, length(?4)) = ?4)`
  ).bind(appId, p, p + "/", p + SEP);

const moveStmt = (env, appId, from, to) =>
  env.DB.prepare(
    `UPDATE app_files SET file_path = ?1 || substr(file_path, length(?2) + 1)
     WHERE appid = ?3 AND (file_path = ?2
       OR substr(file_path, 1, length(?4)) = ?4 OR substr(file_path, 1, length(?5)) = ?5)`
  ).bind(to, from, appId, from + "/", from + SEP);

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
    if (((attr >>> 16) & 0o170000) === 0o120000) continue;
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
        await rd.skip(size + pad);
      }
    }
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(400, "Could not read the tar file");
  }
}

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

async function extractInto(env, appId, bytes, kind, destParts) {
  const iterate = want => (kind === "zip" ? zipEntries(bytes, want) : tarEntries(bytes, want));

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

async function sha256(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}
async function keyMatches(env, k) {
  if (typeof k !== "string" || !k) return false;
  const adminKey = await env.KV.get("ADMIN_KEY");
  if (!adminKey) return false;
  const [a, b] = await Promise.all([sha256(k), sha256(String(adminKey))]);
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

const ROUTES = {};

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

ROUTES["/api/files/delete"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const p = segments(body.path ?? body.fileName).join("/");
  if (!(await statPath(env, appId, p))) throw new HttpError(404, "File or folder not found");
  await delTreeStmt(env, appId, p).run();
  return ok();
};

ROUTES["/api/files/delete-all"] = async ({ env, body }) => {
  const { appId } = body;
  checkAppId(appId);
  const r = await env.DB.prepare(
    "SELECT COUNT(*) AS files, COALESCE(SUM(json_extract(info, '$.size')), 0) AS bytes FROM app_files WHERE appid = ?1 AND json_extract(info, '$.type') = 'file'"
  ).bind(appId).first();
  await env.DB.prepare("DELETE FROM app_files WHERE appid = ?1").bind(appId).run();
  return ok({ files: (r && r.files) || 0, bytes: (r && r.bytes) || 0 });
};

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

async function uploadRoute({ request, env, form: preForm, appIdOverride }) {
  const cl = Number(request.headers.get("content-length"));
  if (cl > MAX_UPLOAD_BYTES) throw new HttpError(413, "File is too large");
  let form = preForm;
  if (!form) {
    try { form = await request.formData(); }
    catch { throw new HttpError(400, "Send the upload as multipart/form-data"); }
  }

  const appId = appIdOverride || form.get("appId");
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

function corsHeaders(request) {
  return {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-admin-key, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

const MAX_APPS_PER_USER = Infinity;
const MAX_FREE_APPS_PER_USER = 1;
const PLANS = {
  basic:      { name: "Basic",      price: 150, backups: 5,  dailyRequests: 1_000_000 },
  standard:   { name: "Standard",   price: 200, backups: 7,  dailyRequests: 10_000_000 },
  pro:        { name: "Pro",        price: 250, backups: 9,  dailyRequests: 100_000_000 },
  enterprise: { name: "Enterprise", price: 300, backups: 11, dailyRequests: 1_000_000_000 },
};
const FREE_DAILY_REQUESTS = 100_000;
const APP_NAME_RE = /^[a-z0-9][a-z0-9_-]{2,31}$/;
const NAME_RULE = "App name must be 3-32 lowercase characters: a-z, 0-9, - or _ (cannot start with - or _)";
const DEFAULT_CORS = "https://litepages.host,https://lite-pages.thecodemonai.workers.dev";
const AUTH_TTL = 300, HOST_TTL = 120, NONE_TTL = 30;
const INFO_KEEP_DAYS = 7;
const MAX_RAW_VISITS_PER_APP = 5000;

const dayKey = (d) => d.toISOString().slice(0, 10);
const todayKey = () => dayKey(new Date());
const parseJson = (s, d) => { try { const v = JSON.parse(s); return v ?? d; } catch { return d; } };
const clip = (v) => (v === undefined || v === null || v === "" ? null : String(v).slice(0, 100));
const isPremium = (rec) => (rec.plan || "Free") !== "Free";
const backupLimit = (rec) => { const p = PLANS[String(rec.plan || "").toLowerCase()]; return p ? p.backups : 0; };
const dailyRequestLimit = (rec) => { const p = PLANS[String(rec.plan || "").toLowerCase()]; return p ? p.dailyRequests : FREE_DAILY_REQUESTS; };
const appDomainOf = (env) => String(env.APP_DOMAIN || "fastsite.host").toLowerCase();
const originsOf = (env) => String(env.CORS_ORIGINS || DEFAULT_CORS).split(",").map((s) => s.trim()).filter(Boolean);

function isDashboardHost(env, host) {
  if (host === appDomainOf(env) || host === "localhost" || host === "127.0.0.1" || host.endsWith(".workers.dev")) return true;
  for (const o of originsOf(env)) { try { if (new URL(o).hostname === host) return true; } catch {} }
  return String(env.DASHBOARD_HOSTS || "").split(",").some((h) => h.trim().toLowerCase() === host);
}

const _kv = new Map();
async function setting(env, name) {
  if (env[name]) return String(env[name]);
  const hit = _kv.get(name);
  if (hit && Date.now() - hit.t < 60000) return hit.v;
  const v = env.KV ? await env.KV.get(name) : null;
  _kv.set(name, { v: v ? String(v) : "", t: Date.now() });
  return v ? String(v) : "";
}

let _keys = null;
async function keys(env) {
  if (_keys) return _keys;
  const secret = await setting(env, "DATA_SECRET");
  if (!secret) throw new HttpError(500, "DATA_SECRET is not set (KV key or env var)");
  const d = async (label) => crypto.subtle.digest("SHA-256", enc.encode(label + "|" + secret));
  _keys = {
    hmac: await crypto.subtle.importKey("raw", await d("hmac"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    aes: await crypto.subtle.importKey("raw", await d("aes"), "AES-GCM", false, ["encrypt", "decrypt"]),
  };
  return _keys;
}
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const newSecret = () => bytesToB64(crypto.getRandomValues(new Uint8Array(12))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function hashSecret(env, s) {
  const k = await keys(env);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", k.hmac, enc.encode(String(s)))));
}
async function lockSecret(env, s) {
  const k = await keys(env), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k.aes, enc.encode(s)));
  return bytesToB64(iv) + "." + bytesToB64(ct);
}
async function unlockSecret(env, v) {
  if (typeof v !== "string" || !v.includes(".")) return null;
  try {
    const k = await keys(env), [a, b] = v.split(".");
    return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(a) }, k.aes, b64ToBytes(b)));
  } catch { return null; }
}
function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function sha256hex(s) { return toHex(await sha256(s)); }

let _ak = { v: null, t: 0 };
async function getAdminKey(env) {
  if (_ak.v && Date.now() - _ak.t < 60000) return _ak.v;
  const v = await env.KV.get("ADMIN_KEY");
  if (!v) throw new HttpError(500, "ADMIN_KEY is not set in KV");
  _ak = { v: String(v), t: Date.now() };
  return _ak.v;
}
async function callBackend(env, path, payload, { raw = false, timeout = 120000 } = {}) {
  const backend = await setting(env, "BACKEND_URL");
  if (!backend) throw new HttpError(500, "BACKEND_URL is not set (KV key or env var)");
  const key = await getAdminKey(env);
  let r;
  try {
    r = await fetch(backend.replace(/\/+$/, "") + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-admin-key": key },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeout),
    });
  } catch { return { status: 502, data: { success: false, error: "Backend server is unreachable" } }; }
  if (raw && r.ok) return { status: r.status, response: r };
  let data;
  try { data = await r.json(); } catch { data = { success: false, error: "Backend sent an invalid response" }; }
  if (r.status === 401) return { status: 502, data: { success: false, error: "Backend rejected the request" } };
  return { status: r.status, data };
}
const backendOk = (r) => r.status >= 200 && r.status < 300 && r.data && r.data.success !== false;
const backendFail = (r) => new HttpError(r.status >= 400 ? r.status : 502, (r.data && r.data.error) || "Backend error");

const CK = (kind, key) => new Request("https://cache.fastsite.internal/" + kind + "/" + encodeURIComponent(key));
async function cget(kind, key) {
  try { const r = await caches.default.match(CK(kind, key)); return r ? await r.json() : null; } catch { return null; }
}
async function cput(kind, key, val, ttl) {
  try {
    await caches.default.put(CK(kind, key), new Response(JSON.stringify(val), {
      headers: { "Content-Type": "application/json", "Cache-Control": "max-age=" + ttl },
    }));
  } catch {}
}
const cdel = (kind, key) => caches.default.delete(CK(kind, key)).catch(() => false);

const rowToApp = (r) => ({
  id: r.id, name: r.name, owner: r.owner, plan: r.plan || "Free", createdAt: r.created_at,
  customDomain: r.custom_domain || undefined,
  customDomainVerified: r.custom_domain ? r.custom_domain_verified !== 0 : undefined,
  customDomainVerifiedAt: r.custom_domain_verified_at || undefined,
  dailyBackup: r.daily_backup === 1,
  lastAutoBackup: r.last_auto_backup || null,
  cache: parseJson(r.cache, null),
  cookies: parseJson(r.cookies, []),
  hsts: parseJson(r.hsts, null),
  cors: parseJson(r.cors, null),
  site: parseJson(r.site, null),
  hotlink: parseJson(r.hotlink, null),
  frame: parseJson(r.frame, null),
});
function publicApp(record) {
  return {
    id: record.id, name: record.name, createdAt: record.createdAt, plan: record.plan || "Free",
    customDomain: record.customDomain || null,
    customDomainVerified: record.customDomain ? record.customDomainVerified !== false : null,
    dailyBackup: record.dailyBackup === true,
  };
}
function publicAccount(r) {
  return { discordId: r.discord_id, username: r.username, email: r.email, imgUrl: r.img_url, credits: Number(r.credits) || 0, ip: r.ip, createdAt: r.created_at, lastLogin: r.last_login };
}
function avatarUrl(user) {
  if (user.avatar) return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${user.avatar.startsWith("a_") ? "gif" : "png"}?size=256`;
  return `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(user.id) >> 22n) % 6n)}.png`;
}

async function loadAppFull(env, where, bind) {
  const r = await env.INFO.prepare(
    `SELECT a.*, s.state AS cstate FROM apps a LEFT JOIN cache_state s ON s.app_id = a.id WHERE ${where}`
  ).bind(bind).first();
  if (!r) return null;
  const rec = rowToApp(r), st = parseJson(r.cstate, {});
  rec.cs = { all: st.all || 0, purges: st.purges || [], lastPurge: st.lastPurge || 0 };
  return rec;
}
const hostsOf = (env, rec) => {
  const l = [rec.name.toLowerCase() + "." + appDomainOf(env)];
  if (rec.customDomain && rec.customDomainVerified !== false) l.push(rec.customDomain);
  return l;
};
const putHostEntries = (env, rec) => Promise.all(hostsOf(env, rec).map((h) => cput("host", h, rec, HOST_TTL)));
const refreshHost = async (env, appId) => { const rec = await loadAppFull(env, "a.id = ?1", appId); if (rec) await putHostEntries(env, rec); return rec; };

async function loadAccounts(env, username) {
  const { results: accs } = await env.INFO.prepare("SELECT discord_id, pw_hash FROM accounts WHERE username = ?1").bind(username).all();
  const out = [];
  for (const a of accs) {
    const { results } = await env.INFO.prepare("SELECT * FROM apps WHERE owner = ?1 ORDER BY created_at").bind(a.discord_id).all();
    out.push({ discordId: a.discord_id, hash: a.pw_hash, apps: results.map((r) => ({ ...rowToApp(r), cache: undefined, cookies: undefined, hsts: undefined, cors: undefined, site: undefined, hotlink: undefined, frame: undefined, hash: r.pw_hash })) });
  }
  return out;
}
async function refreshAuth(env, username) {
  await cdel("acct", username);
  const list = await loadAccounts(env, username);
  if (list.length) await cput("acct", username, list, AUTH_TTL);
}
async function bustApp(env, ownerId, delHosts, putAppId) {
  const acc = await env.INFO.prepare("SELECT username FROM accounts WHERE discord_id = ?1").bind(ownerId).first();
  if (acc) await refreshAuth(env, acc.username);
  await Promise.all(delHosts.filter(Boolean).map((h) => cdel("host", h)));
  if (putAppId) await refreshHost(env, putAppId);
}

async function authenticate(env, ctx, username, password) {
  if (typeof username !== "string" || typeof password !== "string" || !username || !password || username.length > 100 || password.length > 200) return null;
  let list = await cget("acct", username);
  if (!list) {
    list = await loadAccounts(env, username);
    if (list.length) ctx.waitUntil(cput("acct", username, list, AUTH_TTL));
  }
  if (!list.length) return null;
  const h = await hashSecret(env, password);
  const hit = list.find((a) => safeEq(a.hash, h));
  return hit ? { discordId: hit.discordId, username, apps: hit.apps, count: hit.apps.length } : null;
}
async function authOwner(env, ctx, b) {
  const owner = await authenticate(env, ctx, b.username, b.password);
  if (!owner) throw new HttpError(401, "Invalid username or password");
  return owner;
}
async function authApp(env, ctx, b) {
  const owner = await authOwner(env, ctx, b);
  if (typeof b.appId !== "string" || !b.appId || typeof b.appPassword !== "string" || !b.appPassword) {
    throw new HttpError(400, "appId and appPassword are required");
  }
  const record = owner.apps.find((a) => a.id === b.appId);
  if (!record) throw new HttpError(404, "App not found");
  if (!safeEq(record.hash, await hashSecret(env, b.appPassword))) throw new HttpError(401, "Invalid app password");
  return { owner, record };
}

function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let d = input.trim().toLowerCase().replace(/\.$/, "");
  if (!d || d.length > 253 || /[\/\s:@?#]/.test(d)) return null;
  try { d = new URL("http://" + d).hostname; } catch { return null; }
  const labels = d.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  if (!/^(xn--[a-z0-9-]+|[a-z]{2,63})$/.test(labels[labels.length - 1])) return null;
  return d;
}
async function dnsCheck(env, domain, expected) {
  const r = await callBackend(env, "/api/dns/check", { domain, expected }, { timeout: 15000 });
  if (!backendOk(r)) throw new Error("dns unavailable");
  return { ok: r.data.ok === true, found: r.data.found || null };
}
async function recheckDomain(env, rec) {
  const domain = rec.customDomain, expected = rec.name + "." + appDomainOf(env);
  let status, found = null;
  try { const c = await dnsCheck(env, domain, expected); found = c.found; status = c.ok ? "verified" : "not_pointing"; }
  catch { status = "unchecked"; }
  const cur = await loadAppFull(env, "a.id = ?1", rec.id);
  if (cur && cur.name === rec.name && cur.customDomain === domain) {
    await env.INFO.prepare("UPDATE apps SET custom_domain_verified = ?1, custom_domain_verified_at = COALESCE(?2, custom_domain_verified_at) WHERE id = ?3")
      .bind(status === "verified" ? 1 : 0, status === "verified" ? nowIso() : null, rec.id).run();
  }
  const message =
    status === "verified" ? "The CNAME of " + domain + " points to " + expected + ", so the domain keeps working."
    : status === "unchecked" ? "Couldn't check DNS right now. Set the domain again later to verify it."
    : (found ? "The CNAME of " + domain + " still points to " + found + ". Change it to point to " + expected
             : "No CNAME record found for " + domain + ". Add one that points to " + expected) + ", then set the domain again to verify it.";
  return { name: domain, status, expected, found, message };
}

const USER = {};
const bodyStr = (v) => (typeof v === "string" ? v.trim() : "");

USER["/api/discord-signup"] = async ({ request, env, ctx, body, url }) => {
  const code = url.searchParams.get("code") || body.code;
  if (!code) throw new HttpError(400, "Missing code");
  const [dId, dSecret, dRedirect] = await Promise.all(["DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", "DISCORD_REDIRECT_URI"].map((k) => setting(env, k)));
  if (!dId || !dSecret || !dRedirect) throw new HttpError(500, "Discord login is not configured");

  const tr = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: dId, client_secret: dSecret, grant_type: "authorization_code", code, redirect_uri: dRedirect }),
  });
  if (!tr.ok) throw new HttpError(400, "Invalid or expired code");
  const token = await tr.json();
  const ur = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + token.access_token } });
  if (!ur.ok) throw new HttpError(502, "Could not fetch Discord user");
  const user = await ur.json();
  if (!user.email) throw new HttpError(400, "Discord account has no email. Request the email scope.");

  const db = env.INFO, now = nowIso(), img = avatarUrl(user);
  const row = await db.prepare("SELECT * FROM accounts WHERE discord_id = ?1").bind(user.id).first();
  let created = false, plain, account, apps = [];

  if (row) {
    plain = await unlockSecret(env, row.pw_enc);
    const stmts = [];
    if (!plain || !row.pw_hash) {
      plain = newSecret();
      stmts.push(db.prepare("UPDATE accounts SET pw_hash = ?1, pw_enc = ?2 WHERE discord_id = ?3").bind(await hashSecret(env, plain), await lockSecret(env, plain), user.id));
    }
    stmts.push(db.prepare("UPDATE accounts SET img_url = ?1, last_login = ?2 WHERE discord_id = ?3").bind(img, now, user.id));
    const { results } = await db.prepare("SELECT * FROM apps WHERE owner = ?1 ORDER BY created_at").bind(user.id).all();
    for (const a of results) {
      let ap = await unlockSecret(env, a.pw_enc);
      if (!ap || !a.pw_hash) {
        ap = newSecret();
        stmts.push(db.prepare("UPDATE apps SET pw_hash = ?1, pw_enc = ?2 WHERE id = ?3").bind(await hashSecret(env, ap), await lockSecret(env, ap), a.id));
      }
      apps.push({ ...publicApp(rowToApp(a)), appPassword: ap });
    }
    await db.batch(stmts);
    account = publicAccount({ ...row, img_url: img, last_login: now });
  } else {
    created = true;
    plain = newSecret();
    const r = { discord_id: user.id, username: user.global_name || user.username, email: user.email, img_url: img, credits: 0, ip: request.headers.get("CF-Connecting-IP"), created_at: now, last_login: now };
    await db.prepare("INSERT INTO accounts (discord_id, username, email, img_url, pw_hash, pw_enc, credits, ip, created_at, last_login) VALUES (?1,?2,?3,?4,?5,?6,0,?7,?8,?8)")
      .bind(r.discord_id, r.username, r.email, r.img_url, await hashSecret(env, plain), await lockSecret(env, plain), r.ip, now).run();
    account = publicAccount(r);
  }
  await refreshAuth(env, account.username);
  return json({ success: true, created, account, password: plain, apps });
};

USER["/api/apps/create"] = async ({ env, ctx, body }) => {
  const owner = await authOwner(env, ctx, body);
  const planKey = typeof body.plan === "string" ? body.plan.trim().toLowerCase() : "";
  const planInfo = planKey && planKey !== "free" ? PLANS[planKey] : null;
  if (planKey && planKey !== "free" && !planInfo) {
    throw new HttpError(400, "Unknown plan. Use " + Object.values(PLANS).map((p) => p.name + " (" + p.price + " credits)").join(", ") + ", or leave it out for a free app");
  }
  const name = bodyStr(body.appName);
  if (!APP_NAME_RE.test(name)) throw new HttpError(400, NAME_RULE);

  if (owner.count >= MAX_APPS_PER_USER) throw new HttpError(403, `You can create at most ${MAX_APPS_PER_USER} apps`);
  if (!planInfo && owner.apps.filter((a) => (a.plan || "Free") === "Free").length >= MAX_FREE_APPS_PER_USER) {
    throw new HttpError(403, `You can only have ${MAX_FREE_APPS_PER_USER} free app. Choose a paid plan for this one`);
  }
  const db = env.INFO;
  if (await db.prepare("SELECT 1 AS x FROM apps WHERE name = ?1").bind(name).first()) throw new HttpError(409, "App name is already taken");

  let credits;
  if (planInfo) {
    const r = await db.prepare("UPDATE accounts SET credits = credits - ?1 WHERE discord_id = ?2 AND credits >= ?1").bind(planInfo.price, owner.discordId).run();
    if (!r.meta.changes) {
      const a = await db.prepare("SELECT credits FROM accounts WHERE discord_id = ?1").bind(owner.discordId).first();
      throw new HttpError(402, `The ${planInfo.name} plan costs ${planInfo.price} credits and you have ${a ? Number(a.credits) || 0 : 0}`);
    }
  }
  const id = toHex(crypto.getRandomValues(new Uint8Array(6)));
  const appPassword = newSecret();
  try {
    await db.prepare("INSERT INTO apps (id, name, owner, pw_hash, pw_enc, plan, created_at, cache) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")
      .bind(id, name, owner.discordId, await hashSecret(env, appPassword), await lockSecret(env, appPassword), planInfo ? planInfo.name : "Free", nowIso(), JSON.stringify(defaultCacheConfig(planInfo ? 1 : 0))).run();
  } catch {
    if (planInfo) await db.prepare("UPDATE accounts SET credits = credits + ?1 WHERE discord_id = ?2").bind(planInfo.price, owner.discordId).run();
    throw new HttpError(409, "App name is already taken");
  }
  if (planInfo) { const a = await db.prepare("SELECT credits FROM accounts WHERE discord_id = ?1").bind(owner.discordId).first(); credits = Number(a.credits) || 0; }
  await bustApp(env, owner.discordId, [], id);
  const rec = await loadAppFull(env, "a.id = ?1", id);
  const out = { success: true, app: publicApp(rec), appPassword };
  if (credits !== undefined) out.credits = credits;
  return json(out, 201);
};

USER["/api/apps/list"] = async ({ env, ctx, body }) => {
  const owner = await authOwner(env, ctx, body);
  const a = await env.INFO.prepare("SELECT credits FROM accounts WHERE discord_id = ?1").bind(owner.discordId).first();
  return json({
    success: true, count: owner.count, max: MAX_APPS_PER_USER, credits: a ? Number(a.credits) || 0 : 0,
    freeUsed: owner.apps.filter((x) => (x.plan || "Free") === "Free").length, maxFree: MAX_FREE_APPS_PER_USER,
    plans: Object.values(PLANS).map((p) => ({ name: p.name, price: p.price, backups: p.backups })),
    apps: owner.apps.map((x) => ({ ...publicApp(x), backupLimit: backupLimit(x) })),
  });
};

USER["/api/apps/rename"] = async ({ env, ctx, body }) => {
  const { owner, record: current } = await authApp(env, ctx, body);
  const name = bodyStr(body.newName);
  if (!APP_NAME_RE.test(name)) throw new HttpError(400, NAME_RULE);
  if (current.name === name) throw new HttpError(400, "That is already the app's name");
  const taken = await env.INFO.prepare("SELECT id FROM apps WHERE name = ?1 AND id != ?2").bind(name, current.id).first();
  if (taken) throw new HttpError(409, "App name is already taken");
  const oldHost = current.name.toLowerCase() + "." + appDomainOf(env);
  try { await env.INFO.prepare("UPDATE apps SET name = ?1 WHERE id = ?2").bind(name, current.id).run(); }
  catch { throw new HttpError(409, "App name is already taken"); }

  let rec = await loadAppFull(env, "a.id = ?1", current.id);
  const out = { success: true };
  if (rec.customDomain) out.domain = await recheckDomain(env, rec);
  await bustApp(env, owner.discordId, [oldHost, rec.customDomain], current.id);
  rec = await loadAppFull(env, "a.id = ?1", current.id);
  out.app = publicApp(rec);
  return json(out);
};

USER["/api/apps/domain"] = async ({ env, ctx, body }) => {
  const { owner, record: current } = await authApp(env, ctx, body);
  const db = env.INFO;
  const before = await loadAppFull(env, "a.id = ?1", current.id);
  if (body.remove === true) {
    await db.prepare("UPDATE apps SET custom_domain = NULL, custom_domain_verified = NULL, custom_domain_verified_at = NULL WHERE id = ?1").bind(current.id).run();
    await bustApp(env, owner.discordId, [before.customDomain], null);
    return json({ success: true, app: publicApp(await loadAppFull(env, "a.id = ?1", current.id)) });
  }
  const d = normalizeDomain(body.domain);
  if (!d) throw new HttpError(400, "Enter a valid domain, for example www.example.com");
  const ad = appDomainOf(env);
  if (d === ad || d.endsWith("." + ad)) throw new HttpError(400, "You can't use a " + ad + " address as a custom domain");

  const expected = before.name + "." + ad;
  let check;
  try { check = await dnsCheck(env, d, expected); }
  catch { throw new HttpError(502, "Couldn't check DNS right now. Try again in a minute."); }
  if (!check.ok) {
    return json({
      success: false,
      error: check.found ? "The CNAME of " + d + " points to " + check.found + ", but it must point to " + expected : "No CNAME record found for " + d + ". Add a CNAME record that points to " + expected,
      expected, found: check.found,
    }, 400);
  }
  const now = await loadAppFull(env, "a.id = ?1", current.id);
  if (!now) throw new HttpError(404, "App not found");
  if (now.name !== before.name) throw new HttpError(409, "The app was renamed while checking. Try again.");
  if (await db.prepare("SELECT 1 AS x FROM apps WHERE custom_domain = ?1 AND id != ?2").bind(d, current.id).first()) throw new HttpError(409, "That domain is already used by another app");
  try {
    await db.prepare("UPDATE apps SET custom_domain = ?1, custom_domain_verified = 1, custom_domain_verified_at = ?2 WHERE id = ?3").bind(d, nowIso(), current.id).run();
  } catch { throw new HttpError(409, "That domain is already used by another app"); }
  await bustApp(env, owner.discordId, [before.customDomain, d], current.id);
  return json({ success: true, app: publicApp(await loadAppFull(env, "a.id = ?1", current.id)) });
};

USER["/api/apps/delete"] = async ({ env, ctx, body }) => {
  const { owner, record } = await authApp(env, ctx, body);
  const full = await loadAppFull(env, "a.id = ?1", record.id);
  if (!full) throw new HttpError(404, "App not found");

  let backupsDeleted = 0;
  if (isPremium(full)) {
    const r = await callBackend(env, "/api/backups/delete-all", { appId: full.id });
    if (!backendOk(r) && r.status !== 404) throw backendFail(r);
    backupsDeleted = (r.data && r.data.deleted) || 0;
  }
  const f = await (await ROUTES["/api/files/delete-all"]({ env, body: { appId: full.id } })).json();
  const db = env.INFO, id = full.id;
  await db.batch([
    db.prepare("DELETE FROM apps WHERE id = ?1").bind(id),
    ...["cache_state", "cache_stats", "app_stats", "day_stats", "seen_all", "seen_day", "visits", "request_counts"]
      .map((t) => db.prepare(`DELETE FROM ${t} WHERE app_id = ?1`).bind(id)),
  ]);
  RC.delete(id);
  await bustApp(env, owner.discordId, hostsOf(env, full), null);
  return json({ success: true, deleted: { appId: id, name: full.name, files: f.files, bytes: f.bytes, backups: backupsDeleted } });
};

const FS_OPS = {
  write: ["path", "content", "encoding"], read: ["path", "encoding"], list: ["path"], delete: ["path"],
  rename: ["path", "newName"], move: ["from", "to", "overwrite"], mkdir: ["path"],
  extract: ["path", "to", "deleteArchive"], upload: ["path", "extract"], usage: [],
};
const IMAGE_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "bmp", "svg"]);
const extOf = (name) => { const n = String(name || ""); const i = n.lastIndexOf("."); return i < 0 || n.lastIndexOf("/") > i ? "" : n.slice(i + 1).toLowerCase(); };
const kindFromExt = (e) => (e === "jpg" ? "jpeg" : e);
function imageKind(b) {
  const at = (i) => b[i];
  const s = (a, z) => String.fromCharCode(...b.subarray(a, Math.min(z, b.length)));
  if (b.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((v, i) => at(i) === v)) return "png";
  if (b.length >= 3 && at(0) === 0xff && at(1) === 0xd8 && at(2) === 0xff) return "jpeg";
  const a = s(0, 12);
  if (a.startsWith("GIF87a") || a.startsWith("GIF89a")) return "gif";
  if (a.startsWith("RIFF") && a.slice(8, 12) === "WEBP") return "webp";
  if (a.slice(4, 8) === "ftyp" && /^(avif|avis)/.test(s(8, 12))) return "avif";
  if (b.length >= 4 && at(0) === 0 && at(1) === 0 && at(2) === 1 && at(3) === 0) return "ico";
  if (a.startsWith("BM")) return "bmp";
  if (dec.decode(b.subarray(0, 2048)).toLowerCase().includes("<svg")) return "svg";
  return null;
}
const CHANGING_OPS = ["write", "delete", "rename", "move", "extract", "upload"];

{
  USER["/api/fs"] = async ({ request, env, ctx, body }) => {
    const isForm = /multipart\/form-data/i.test(request.headers.get("content-type") || "");
    let form = null, b = body;
    if (isForm) {
      if (Number(request.headers.get("content-length")) > MAX_UPLOAD_BYTES) throw new HttpError(413, "File is too large");
      try { form = await request.formData(); } catch { throw new HttpError(400, "Invalid upload"); }
      b = Object.fromEntries([...form.entries()].filter(([, v]) => typeof v === "string"));
    }
    const spec = FS_OPS[b.op];
    if (!spec) throw new HttpError(400, "Unknown op. Use one of: " + Object.keys(FS_OPS).join(", "));
    const { record } = await authApp(env, ctx, b);

    let res;
    if (b.op === "upload") {
      if (!form) throw new HttpError(400, "Send the upload as multipart/form-data");
      const files = form.getAll("file").filter((f) => typeof f !== "string");
      if (!files.length) throw new HttpError(400, 'No file received (send it in the "file" field)');
      for (const f of files) {
        const ext = extOf(f.name);
        if (!IMAGE_EXTS.has(ext)) continue;
        const head = new Uint8Array(await f.slice(0, 2100).arrayBuffer());
        if (imageKind(head) !== kindFromExt(ext)) throw new HttpError(400, `"${f.name}" is not a valid .${ext} image`);
      }
      form.set("appId", record.id);
      form.set("path", b.path || ""); form.set("extract", b.extract || "");
      res = await uploadRoute({ request, env, form, appIdOverride: record.id });
    } else {
      if (b.op === "write" && b.encoding === "base64") {
        const ext = extOf(b.path !== undefined ? b.path : b.fileName);
        if (IMAGE_EXTS.has(ext)) {
          let head = new Uint8Array(0);
          const sample = String(b.content || "").slice(0, 2800);
          try { head = b64ToBytes(sample.slice(0, sample.length - (sample.length % 4))); } catch {}
          if (imageKind(head) !== kindFromExt(ext)) throw new HttpError(400, `The content is not a valid .${ext} image`);
        }
      }
      const payload = { appId: record.id };
      for (const k of spec) if (b[k] !== undefined) payload[k] = b[k];
      if (payload.path === undefined && b.fileName !== undefined) payload.path = b.fileName;
      res = await ROUTES["/api/files/" + b.op]({ env, body: payload });
    }
    if (res.status < 300 && CHANGING_OPS.includes(b.op)) ctx.waitUntil(autoPurge(env, record.id));
    return res;
  };
}

ROUTES["/api/files/usage"] = async ({ env, body }) => {
  checkAppId(body.appId);
  const r = await env.DB.prepare(
    "SELECT COUNT(*) AS files, COALESCE(SUM(json_extract(info, '$.size')), 0) AS bytes FROM app_files WHERE appid = ?1 AND json_extract(info, '$.type') = 'file'"
  ).bind(body.appId).first();
  return ok({ files: r.files, used: r.bytes, bytes: r.bytes, limit: MAX_APP_BYTES });
};
ROUTES["/api/files/tree"] = async ({ env, body }) => {
  checkAppId(body.appId);
  const { results } = await env.DB.prepare("SELECT file_path, info FROM app_files WHERE appid = ?1 AND instr(file_path, char(31)) = 0").bind(body.appId).all();
  const files = [], dirs = [];
  for (const r of results) { const i = parseInfo(r.info); if (i.type === "dir") dirs.push(r.file_path); else files.push({ path: r.file_path, size: i.size || 0 }); }
  return ok({ files, dirs });
};

USER["/api/backups/create"] = async ({ env, ctx, body }) => {
  const { record } = await authApp(env, ctx, body);
  if (!isPremium(record)) throw new HttpError(403, "Backups are only available on paid plans");
  const limit = backupLimit(record);
  const ex = await callBackend(env, "/api/backups/info", { appId: record.id });
  if (!backendOk(ex)) throw backendFail(ex);
  if ((ex.data.backups || []).length >= limit) {
    throw new HttpError(409, `Your ${record.plan} plan allows ${limit} backups and you already have ${limit}. Delete one first or upgrade your plan`);
  }
  const payload = { appId: record.id, maxBackups: limit };
  if (body.format !== undefined) payload.format = body.format;
  const r = await callBackend(env, "/api/backups/create", payload, { timeout: 280000 });
  return json(r.data, r.status);
};
USER["/api/backups/list"] = async ({ env, ctx, body }) => {
  const { record } = await authApp(env, ctx, body);
  const r = await callBackend(env, "/api/backups/info", { appId: record.id });
  if (r.data && r.data.success !== false) { r.data.max = backupLimit(record); r.data.dailyBackup = record.dailyBackup === true; }
  return json(r.data, r.status);
};
const backupIdRoute = (path, timeout) => async ({ env, ctx, body }) => {
  const { record } = await authApp(env, ctx, body);
  if (typeof body.backupId !== "string" || !body.backupId) throw new HttpError(400, "backupId is required");
  const r = await callBackend(env, path, { appId: record.id, backupId: body.backupId, plan: record.plan || "Free" }, { timeout });
  if (path === "/api/backups/restore" && r.status < 300) await autoPurge(env, record.id);
  return json(r.data, r.status);
};
USER["/api/backups/delete"] = backupIdRoute("/api/backups/delete");
USER["/api/backups/info"] = backupIdRoute("/api/backups/info");
USER["/api/backups/restore"] = backupIdRoute("/api/backups/restore", 290000);
USER["/api/backups/download"] = async ({ env, ctx, body }) => {
  const { record } = await authApp(env, ctx, body);
  if (typeof body.backupId !== "string" || !body.backupId) throw new HttpError(400, "backupId is required");
  const r = await callBackend(env, "/api/backups/download", { appId: record.id, backupId: body.backupId }, { raw: true, timeout: 290000 });
  if (!r.response) return json(r.data, r.status);
  const h = new Headers({ "Content-Type": r.response.headers.get("content-type") || "application/octet-stream", "Cache-Control": "no-store" });
  for (const k of ["content-disposition", "content-length"]) if (r.response.headers.get(k)) h.set(k, r.response.headers.get(k));
  return new Response(r.response.body, { headers: h });
};
USER["/api/backups/auto"] = async ({ env, ctx, body }) => {
  const { owner, record } = await authApp(env, ctx, body);
  const status = (rec) => ({ success: true, enabled: rec.dailyBackup === true, lastBackup: rec.lastAutoBackup || null, max: backupLimit(rec) });
  let en = body.enabled;
  const cur = await loadAppFull(env, "a.id = ?1", record.id);
  if (en === undefined) return json(status(cur));
  if (en === "true") en = true;
  if (en === "false") en = false;
  if (typeof en !== "boolean") throw new HttpError(400, "enabled must be true or false");
  if (en && !isPremium(cur)) throw new HttpError(403, "Daily backups are only available on paid plans");
  await env.INFO.prepare("UPDATE apps SET daily_backup = ?1 WHERE id = ?2").bind(en ? 1 : 0, cur.id).run();
  await bustApp(env, owner.discordId, [], cur.id);
  return json(status(await loadAppFull(env, "a.id = ?1", cur.id)));
};

ROUTES["/api/admin/apps/due-backup"] = async ({ env, body }) => {
  const today = typeof body.today === "string" ? body.today : todayKey();
  const { results } = await env.INFO.prepare(
    "SELECT id, name, plan FROM apps WHERE daily_backup = 1 AND plan != 'Free' AND (last_auto_backup IS NULL OR last_auto_backup != ?1)"
  ).bind(today).all();
  return ok({ apps: results.map((a) => ({ ...a, limit: backupLimit(a) })) });
};
ROUTES["/api/admin/apps/backup-done"] = async ({ env, body }) => {
  checkAppId(body.appId);
  await env.INFO.prepare("UPDATE apps SET last_auto_backup = ?1 WHERE id = ?2").bind(String(body.day || todayKey()), body.appId).run();
  return ok();
};

const TIER_LABEL = ["Free", "any paid plan", "Pro or Enterprise", "Enterprise"];
const CACHE_LIMITS = [
  { rules: 3,   maxTtl: 86400,    purgesPerDay: 5 },
  { rules: 20,  maxTtl: 31536000, purgesPerDay: 200 },
  { rules: 100, maxTtl: 31536000, purgesPerDay: 1000 },
  { rules: 500, maxTtl: 31536000, purgesPerDay: Infinity },
];
const cacheTier = (rec) => { const p = String(rec.plan || "").toLowerCase(); return p === "enterprise" ? 3 : p === "pro" ? 2 : PLANS[p] ? 1 : 0; };
function defaultCacheConfig(tier = 0) {
  return {
    enabled: true, edgeCache: false, browserTtl: 60, edgeTtl: 60, mediaBrowserTtl: 86400, mediaEdgeTtl: 86400,
    autoPurgeOnDeploy: true, debugHeader: false, etag: tier >= 1, deviceCache: false, staleWhileRevalidate: 0,
    staleIfError: 0, immutableMedia: false, cacheByCountry: false, smartTtl: false, purgeEveryHours: 0, purgeWebhook: null, rules: [],
  };
}
const getCacheConfig = (rec) => {
  const c = { ...defaultCacheConfig(cacheTier(rec)), ...(rec.cache || {}) };
  c.rules = Array.isArray(c.rules) ? c.rules : [];
  return c;
};
const SETTING_SPEC = {
  edgeCache: { t: "bool", tier: 0 },
  browserTtl: { t: "ttl", tier: 0 }, edgeTtl: { t: "ttl", tier: 0 },
  mediaBrowserTtl: { t: "ttl", tier: 0 }, mediaEdgeTtl: { t: "ttl", tier: 0 },
  autoPurgeOnDeploy: { t: "bool", tier: 0 }, debugHeader: { t: "bool", tier: 0 },
  etag: { t: "bool", tier: 1 }, deviceCache: { t: "bool", tier: 1 },
  staleWhileRevalidate: { t: "ttl", tier: 1 }, staleIfError: { t: "ttl", tier: 1 },
  immutableMedia: { t: "bool", tier: 2 }, cacheByCountry: { t: "bool", tier: 2 },
  smartTtl: { t: "bool", tier: 3 }, purgeEveryHours: { t: "hours", tier: 3 }, purgeWebhook: { t: "url", tier: 3 },
};
function parseTtl(v, tier, what) {
  const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
  if (!Number.isInteger(n) || n < 0) throw new HttpError(400, `${what} must be a whole number of seconds (0 or more)`);
  const max = CACHE_LIMITS[tier].maxTtl;
  if (n > max) throw new HttpError(400, `${what} can be at most ${max} seconds on your plan`);
  return n;
}
function parseBool(v, what) {
  if (v === "true") v = true;
  if (v === "false") v = false;
  if (typeof v !== "boolean") throw new HttpError(400, `${what} must be true or false`);
  return v;
}
function parseWebhook(v) {
  if (v === null || v === "") return null;
  let u;
  try { u = new URL(String(v)); } catch { throw new HttpError(400, "purgeWebhook must be a valid https URL"); }
  const h = u.hostname.toLowerCase();
  if (u.protocol !== "https:" || String(v).length > 300 || /^[\d.]+$/.test(h) || h.includes(":") || h === "localhost" || /\.(local|internal|localhost)$/.test(h)) {
    throw new HttpError(400, "purgeWebhook must be a public https URL (no IP addresses)");
  }
  return u.toString();
}
function applySettings(cfg, b, tier) {
  const changed = [];
  for (const [key, spec] of Object.entries(SETTING_SPEC)) {
    if (b[key] === undefined) continue;
    if (tier < spec.tier) throw new HttpError(403, `${key} is available on ${TIER_LABEL[spec.tier]} only`);
    let v;
    if (spec.t === "ttl") v = parseTtl(b[key], tier, key);
    else if (spec.t === "bool") v = parseBool(b[key], key);
    else if (spec.t === "hours") { v = Number(b[key]); if (!Number.isInteger(v) || v < 0 || v > 720) throw new HttpError(400, "purgeEveryHours must be 0-720"); }
    else v = parseWebhook(b[key]);
    cfg[key] = v; changed.push(key);
  }
  return changed;
}

const MEDIA_EXTS = new Set([...IMAGE_EXTS, "mp4", "webm", "mov", "mp3", "wav", "ogg", "m4a", "woff", "woff2", "ttf", "otf"]);
const isMediaFile = (type, name) => /^(image|video|audio|font)\//i.test(type || "") || MEDIA_EXTS.has(extOf(name));
const normPath = (p) => "/" + String(p || "").split(/[?#]/)[0].replace(/^\/+/, "").toLowerCase();
const globCache = new Map();
function globRe(g) {
  let re = globCache.get(g);
  if (!re) {
    const tail = g.endsWith("/*");
    const core = (tail ? g.slice(0, -2) : g).split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
    re = new RegExp("^" + core + (tail ? "(/.*)?" : "") + "$");
    if (globCache.size > 2000) globCache.clear();
    globCache.set(g, re);
  }
  return re;
}
function ruleMatches(r, targets) {
  if (r.type === "all") return true;
  if (r.type === "extension") { const set = r.match.split(","); return targets.some((t) => set.includes(extOf(t))); }
  if (r.type === "file") return targets.includes(r.match);
  if (r.type === "path") { const re = globRe(r.match); return targets.some((t) => re.test(t)); }
  return false;
}
function parseRule(b, tier) {
  const type = String(b.type || "").toLowerCase();
  if (!["all", "extension", "file", "path"].includes(type)) throw new HttpError(400, "type must be all, extension, file or path");
  let match = "*";
  if (type === "extension") {
    const list = (Array.isArray(b.match) ? b.match : String(b.match || "").split(",")).map((s) => String(s).trim().toLowerCase().replace(/^\./, "")).filter(Boolean);
    if (!list.length || list.length > 30 || !list.every((x) => /^[a-z0-9]{1,10}$/.test(x))) throw new HttpError(400, 'match must be extensions like "css,js,png"');
    match = [...new Set(list)].join(",");
  } else if (type === "file" || type === "path") {
    let m = String(b.match || "").trim().toLowerCase().split(/[?#]/)[0];
    if (!m || m.length > 200 || m.includes("..")) throw new HttpError(400, "match must be a path like /logo.png or /admin/*");
    if (!m.startsWith("/")) m = "/" + m;
    if (type === "file" && m.includes("*")) throw new HttpError(400, 'use type "path" for patterns with *');
    match = m;
  }
  const action = b.action === undefined || b.action === null ? "cache" : String(b.action).toLowerCase();
  if (!["cache", "bypass"].includes(action)) throw new HttpError(400, "action must be cache or bypass");
  const ttl = (v, w) => (v === undefined || v === null || v === "" ? null : parseTtl(v, tier, w));
  return {
    type, match, action,
    browserTtl: action === "cache" ? ttl(b.browserTtl, "browserTtl") : null,
    edgeTtl: action === "cache" ? ttl(b.edgeTtl, "edgeTtl") : null,
    name: b.name ? String(b.name).slice(0, 60) : null,
  };
}

const newCs = () => ({ all: 0, purges: [], lastPurge: 0, day: "", n: 0, history: [] });
async function getCs(env, id) {
  const r = await env.INFO.prepare("SELECT state FROM cache_state WHERE app_id = ?1").bind(id).first();
  return { ...newCs(), ...(r ? parseJson(r.state, {}) : {}) };
}
const saveCs = (env, id, st) =>
  env.INFO.prepare("INSERT INTO cache_state (app_id, state, next_purge) VALUES (?1, ?2, ?3) ON CONFLICT(app_id) DO UPDATE SET state = excluded.state, next_purge = excluded.next_purge")
    .bind(id, JSON.stringify(st), st.nextPurge || null).run();

function purgeToken(rec, urlPath, fileName) {
  const st = rec.cs;
  if (!st) return 0;
  const targets = [normPath(urlPath), normPath(fileName)];
  let t = st.all || 0;
  for (const p of st.purges || []) if (p.ts > t && ruleMatches(p, targets)) t = p.ts;
  return t;
}
async function doPurge(env, ctx, rec, spec, by) {
  const st = await getCs(env, rec.id), ts = Math.max(Date.now(), (st.lastPurge || 0) + 1);
  if (spec.all) { st.all = ts; st.purges = []; }
  else {
    for (const e of spec.entries) st.purges.push({ type: e.type, match: e.match, ts });
    if (st.purges.length > 50) st.purges.splice(0, st.purges.length - 50);
  }
  st.lastPurge = ts;
  st.history.push({ time: new Date(ts).toISOString(), scope: spec.all ? "all" : spec.entries.map((e) => e.match).join(" ").slice(0, 200), by });
  if (st.history.length > 20) st.history.shift();
  await saveCs(env, rec.id, st);
  await refreshHost(env, rec.id);
  const hook = getCacheConfig(rec).purgeWebhook;
  if (hook && cacheTier(rec) >= 3) {
    const p = fetch(hook, { method: "POST", headers: { "Content-Type": "application/json" }, redirect: "error",
      body: JSON.stringify({ event: "cache.purge", appId: rec.id, app: rec.name, scope: spec.all ? "all" : "partial", by, time: new Date(ts).toISOString() }),
      signal: AbortSignal.timeout(5000) }).catch(() => {});
    if (ctx) ctx.waitUntil(p);
  }
  return { ts, st };
}
async function autoPurge(env, appId) {
  try {
    const rec = await loadAppFull(env, "a.id = ?1", appId);
    if (!rec || !getCacheConfig(rec).autoPurgeOnDeploy) return;
    const st = await getCs(env, appId);
    st.all = Math.max(Date.now(), (st.lastPurge || 0) + 1); st.purges = []; st.lastPurge = st.all;
    await saveCs(env, appId, st);
    await refreshHost(env, appId);
  } catch (e) { console.error("autoPurge failed:", e && e.message); }
}
async function syncSchedule(env, rec, cfg) {
  const st = await getCs(env, rec.id);
  if (cacheTier(rec) >= 3 && cfg.purgeEveryHours > 0) {
    if (st.every !== cfg.purgeEveryHours) { st.every = cfg.purgeEveryHours; st.nextPurge = Date.now() + st.every * 3600000; }
  } else { delete st.every; delete st.nextPurge; }
  await saveCs(env, rec.id, st);
}
async function mutateCache(env, appId, fn) {
  const cur = await loadAppFull(env, "a.id = ?1", appId);
  if (!cur) throw new HttpError(404, "App not found");
  const cfg = getCacheConfig(cur);
  const out = fn(cfg, cacheTier(cur), cur);
  cur.cache = cfg;
  await env.INFO.prepare("UPDATE apps SET cache = ?1 WHERE id = ?2").bind(JSON.stringify(cfg), appId).run();
  await putHostEntries(env, cur);
  return { rec: cur, cfg, out };
}
function cacheView(rec, cfg, st) {
  const tier = cacheTier(rec), lim = CACHE_LIMITS[tier], today = todayKey();
  const { rules, ...settings } = cfg;
  const features = {};
  for (const [k, s] of Object.entries(SETTING_SPEC)) features[k] = { available: tier >= s.tier, requires: TIER_LABEL[s.tier] };
  features.selectivePurge = { available: tier >= 1, requires: TIER_LABEL[1] };
  features.cacheStats = { available: tier >= 3, requires: TIER_LABEL[3] };
  return {
    success: true, plan: rec.plan || "Free",
    limits: { rules: lim.rules, maxTtl: lim.maxTtl, purgesPerDay: lim.purgesPerDay === Infinity ? null : lim.purgesPerDay },
    settings, rules, features,
    lastPurge: st.lastPurge ? new Date(st.lastPurge).toISOString() : null,
    purgesToday: st.day === today ? st.n : 0,
    purgeHistory: tier >= 1 ? st.history.slice().reverse() : undefined,
  };
}
const cacheRoute = (fn) => async (c) => {
  const { record } = await authApp(c.env, c.ctx, c.body);
  const rec = await loadAppFull(c.env, "a.id = ?1", record.id);
  if (!rec) throw new HttpError(404, "App not found");
  return fn(rec, c.body, c);
};
USER["/api/cache/get"] = cacheRoute(async (rec, b, { env }) => json(cacheView(rec, getCacheConfig(rec), await getCs(env, rec.id))));
USER["/api/cache/settings"] = cacheRoute(async (rec, b, { env }) => {
  const { rec: cur, cfg, out } = await mutateCache(env, rec.id, (cfg, tier) => {
    const changed = applySettings(cfg, b, tier);
    if (!changed.length) throw new HttpError(400, "Nothing to change. Send one of: " + Object.keys(SETTING_SPEC).join(", "));
    return changed;
  });
  await syncSchedule(env, cur, cfg);
  return json({ ...cacheView(cur, cfg, await getCs(env, cur.id)), changed: out });
});
USER["/api/cache/disable"] = cacheRoute(async (rec, b, { env }) => {
  const disabled = b.disabled === undefined ? true : parseBool(b.disabled, "disabled");
  const { rec: cur, cfg } = await mutateCache(env, rec.id, (cfg) => { cfg.enabled = !disabled; });
  if (disabled) await autoPurge(env, cur.id);
  return json({ ...cacheView(cur, cfg, await getCs(env, cur.id)), message: disabled ? "Caching is completely disabled (no-store)" : "Caching is enabled again" });
});
USER["/api/cache/reset"] = cacheRoute(async (rec, b, { env }) => {
  const { rec: cur, cfg } = await mutateCache(env, rec.id, (cfg, tier) => { Object.assign(cfg, defaultCacheConfig(tier)); });
  await syncSchedule(env, cur, cfg);
  return json(cacheView(cur, cfg, await getCs(env, cur.id)));
});
USER["/api/cache/rules/list"] = cacheRoute(async (rec) => json({ success: true, rules: getCacheConfig(rec).rules, max: CACHE_LIMITS[cacheTier(rec)].rules }));
USER["/api/cache/rules/add"] = cacheRoute(async (rec, b, { env }) => {
  const { cfg, out } = await mutateCache(env, rec.id, (cfg, tier) => {
    if (cfg.rules.length >= CACHE_LIMITS[tier].rules) throw new HttpError(403, `Your plan allows ${CACHE_LIMITS[tier].rules} cache rules`);
    const rule = { id: toHex(crypto.getRandomValues(new Uint8Array(3))), ...parseRule(b, tier) };
    const pos = b.position !== undefined && b.position !== "" && Number.isInteger(Number(b.position)) ? Math.max(0, Math.min(Number(b.position), cfg.rules.length)) : cfg.rules.length;
    cfg.rules.splice(pos, 0, rule);
    return rule;
  });
  await autoPurge(env, rec.id);
  return json({ success: true, rule: out, rules: cfg.rules }, 201);
});
USER["/api/cache/rules/update"] = cacheRoute(async (rec, b, { env }) => {
  const { cfg, out } = await mutateCache(env, rec.id, (cfg, tier) => {
    const i = cfg.rules.findIndex((r) => r.id === b.ruleId);
    if (i < 0) throw new HttpError(404, "Rule not found");
    const rule = { id: cfg.rules[i].id, ...parseRule({ ...cfg.rules[i], ...b }, tier) };
    cfg.rules.splice(i, 1);
    const pos = b.position !== undefined && Number.isInteger(Number(b.position)) ? Math.max(0, Math.min(Number(b.position), cfg.rules.length)) : i;
    cfg.rules.splice(pos, 0, rule);
    return rule;
  });
  await autoPurge(env, rec.id);
  return json({ success: true, rule: out, rules: cfg.rules });
});
USER["/api/cache/rules/delete"] = cacheRoute(async (rec, b, { env }) => {
  const { cfg } = await mutateCache(env, rec.id, (cfg) => {
    const i = cfg.rules.findIndex((r) => r.id === b.ruleId);
    if (i < 0) throw new HttpError(404, "Rule not found");
    cfg.rules.splice(i, 1);
  });
  await autoPurge(env, rec.id);
  return json({ success: true, rules: cfg.rules });
});
USER["/api/cache/purge"] = cacheRoute(async (rec, b, { env, ctx }) => {
  const tier = cacheTier(rec), lim = CACHE_LIMITS[tier], today = todayKey();
  const all = b.all === true || b.all === "true";
  const list = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : String(v).split(","));
  let spec;
  if (all) spec = { all: true };
  else {
    if (tier < 1) throw new HttpError(403, "Purging single files, paths or extensions is available on paid plans. Send { all: true }");
    const entries = [];
    for (const p of list(b.paths)) { const r = parseRule({ type: String(p).includes("*") ? "path" : "file", match: String(p).trim() }, tier); entries.push({ type: r.type, match: r.match }); }
    for (const x of list(b.extensions)) { const r = parseRule({ type: "extension", match: String(x) }, tier); entries.push({ type: "extension", match: r.match }); }
    if (!entries.length || entries.length > 20) throw new HttpError(400, "Send all:true, or 1-20 paths / extensions");
    spec = { entries };
  }
  const st0 = await getCs(env, rec.id);
  if (st0.day !== today) { st0.day = today; st0.n = 0; }
  if (st0.n >= lim.purgesPerDay) throw new HttpError(429, `Purge limit reached (${lim.purgesPerDay} per day on your plan)`);
  st0.n++;
  await saveCs(env, rec.id, st0);
  const r = await doPurge(env, ctx, rec, spec, "api");
  return json({
    success: true, purgedAt: new Date(r.ts).toISOString(), scope: all ? "all" : "partial",
    note: "Browsers that revalidate (ETag, paid plans) get fresh files now; a copy a browser holds stays until its TTL ends",
    purgesToday: st0.n,
  });
});
USER["/api/cache/stats"] = cacheRoute(async (rec, b, { env }) => {
  if (cacheTier(rec) < 3) throw new HttpError(403, "Cache stats are available on the Enterprise plan");
  const st = await getCs(env, rec.id);
  const s = (await env.INFO.prepare("SELECT served, not_modified, bypassed FROM cache_stats WHERE app_id = ?1").bind(rec.id).first()) || {};
  const stats = { served: s.served || 0, notModified: s.not_modified || 0, bypassed: s.bypassed || 0 };
  const total = stats.served + stats.notModified + stats.bypassed;
  return json({ success: true, stats: { ...stats, total, notModifiedRate: total ? +(stats.notModified / total).toFixed(4) : 0 }, history: st.history.slice().reverse(), lastPurge: st.lastPurge ? new Date(st.lastPurge).toISOString() : null });
});
const bumpStat = (env, id, col) =>
  env.INFO.prepare(`INSERT INTO cache_stats (app_id, ${col}) VALUES (?1, 1) ON CONFLICT(app_id) DO UPDATE SET ${col} = ${col} + 1`).bind(id).run().catch(() => {});

const COOKIE_LIMITS = [3, 10, 30, 100];
const MAX_COOKIE_AGE = 400 * 86400;
const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const COOKIE_VALUE_RE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/;
const HTTP_DATE_RE = /^[A-Za-z]{3}, \d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/;
const SAMESITE = { strict: "Strict", lax: "Lax", none: "None" };
const COOKIE_PRIORITY = { low: "Low", medium: "Medium", high: "High" };
const COOKIE_SCOPES = ["all", "path", "file"];
const COOKIE_FIELDS = ["name", "value", "maxAge", "expires", "domain", "path", "secure", "httpOnly", "sameSite", "partitioned", "priority", "scope", "match", "onlyIfMissing", "enabled"];
const cookieMax = (rec) => COOKIE_LIMITS[cacheTier(rec)];
const pickCookieFields = (b) => Object.fromEntries(COOKIE_FIELDS.filter((k) => b[k] !== undefined).map((k) => [k, b[k]]));
const isUnset = (v) => v === undefined || v === null || v === "";
const optBool = (v, what) => (isUnset(v) ? false : parseBool(v, what));

function parseExpires(v) {
  if (isUnset(v)) return null;
  const s = typeof v === "string" ? v.trim() : "";
  const t = HTTP_DATE_RE.test(s) || ISO_DATE_RE.test(s) ? Date.parse(s) : NaN;
  const year = Number.isFinite(t) ? new Date(t).getUTCFullYear() : 0;
  if (year < 1970 || year > 9999) throw new HttpError(400, 'expires must be a date like "Wed, 28 Oct 2026 18:00:00 GMT" or "2026-10-28T18:00:00Z"');
  return new Date(t).toUTCString();
}

function checkCookieDomain(env, rec, raw) {
  const d = normalizeDomain(typeof raw === "string" ? raw.trim().toLowerCase().replace(/^\./, "") : "");
  if (!d) throw new HttpError(400, "domain must be a valid domain name, for example www.example.com");
  const ad = appDomainOf(env);
  if (d === ad || ad.endsWith("." + d)) throw new HttpError(400, "domain can't be " + ad + " or a parent of it (it would reach other apps)");
  const own = rec.name.toLowerCase() + "." + ad;
  const cd = rec.customDomain && rec.customDomainVerified !== false ? rec.customDomain : null;
  if (d === own || (cd && (d === cd || cd.endsWith("." + d)))) return d;
  throw new HttpError(400, "domain must be " + own + (cd ? ", " + cd + " or a parent domain of " + cd : "") + " (browsers reject any other domain)");
}

function parseCookie(b, env, rec) {
  const warnings = [];
  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (!name || name.length > 128 || !COOKIE_NAME_RE.test(name)) {
    throw new HttpError(400, "name is required (up to 128 characters: letters, digits and ! # $ % & ' * + - . ^ _ ` | ~)");
  }
  let value = isUnset(b.value) ? "" : b.value;
  if (typeof value === "number" || typeof value === "boolean") value = String(value);
  if (typeof value !== "string" || !COOKIE_VALUE_RE.test(value)) {
    throw new HttpError(400, "value can't contain spaces, quotes, commas, semicolons, backslashes or control characters (use encodeURIComponent for such text)");
  }
  if (name.length + value.length > 4096) throw new HttpError(400, "name and value together can be at most 4096 characters");

  let maxAge = null;
  if (!isUnset(b.maxAge)) {
    const n = typeof b.maxAge === "string" ? Number(b.maxAge) : b.maxAge;
    if (!Number.isInteger(n) || n < 0 || n > MAX_COOKIE_AGE) throw new HttpError(400, `maxAge must be a whole number of seconds from 0 to ${MAX_COOKIE_AGE} (400 days). 0 deletes the cookie`);
    maxAge = n;
  }
  const expires = parseExpires(b.expires);
  const domain = isUnset(b.domain) ? null : checkCookieDomain(env, rec, b.domain);

  let path = "/";
  if (!isUnset(b.path)) {
    path = typeof b.path === "string" ? b.path.trim() : "";
    if (!path.startsWith("/") || path.length > 1024 || /[\x00-\x1f\x7f;]/.test(path)) throw new HttpError(400, 'path must start with "/" and can\'t contain ";" or control characters');
  }
  const secure = optBool(b.secure, "secure"), httpOnly = optBool(b.httpOnly, "httpOnly"), partitioned = optBool(b.partitioned, "partitioned");

  let sameSite = null;
  if (!isUnset(b.sameSite)) {
    sameSite = SAMESITE[String(b.sameSite).trim().toLowerCase()];
    if (!sameSite) throw new HttpError(400, "sameSite must be Strict, Lax or None");
  }
  let priority = null;
  if (!isUnset(b.priority)) {
    priority = COOKIE_PRIORITY[String(b.priority).trim().toLowerCase()];
    if (!priority) throw new HttpError(400, "priority must be Low, Medium or High");
  }

  const scopeIn = isUnset(b.scope) ? "all" : String(b.scope).trim().toLowerCase();
  if (!COOKIE_SCOPES.includes(scopeIn)) throw new HttpError(400, 'scope must be "all" (every page), "path" (a pattern like /shop/*) or "file" (one page like /about.html)');
  const { type: scope, match } = parseRule({ type: scopeIn, match: b.match }, 0);

  if (sameSite === "None" && !secure) throw new HttpError(400, "SameSite=None requires secure: true");
  if (partitioned && !secure) throw new HttpError(400, "Partitioned requires secure: true");
  const low = name.toLowerCase();
  if (low.startsWith("__host-")) {
    if (!secure) throw new HttpError(400, "A __Host- cookie requires secure: true");
    if (domain) throw new HttpError(400, "A __Host- cookie can't have a domain");
    if (path !== "/") throw new HttpError(400, 'A __Host- cookie requires path "/"');
  } else if (low.startsWith("__secure-") && !secure) throw new HttpError(400, "A __Secure- cookie requires secure: true");

  if (expires && Date.parse(expires) <= Date.now()) {
    warnings.push(maxAge !== null
      ? "Expires is in the past, but Max-Age takes precedence, so browsers keep the cookie for Max-Age seconds"
      : "Expires is in the past, so browsers will delete this cookie instead of storing it");
  }
  if (maxAge === 0) warnings.push("Max-Age=0 deletes the cookie in the visitor's browser");

  return {
    warnings,
    cookie: {
      name, value, maxAge, expires, domain, path, secure, httpOnly, sameSite, partitioned, priority, scope, match,
      onlyIfMissing: optBool(b.onlyIfMissing, "onlyIfMissing"),
      enabled: isUnset(b.enabled) ? true : parseBool(b.enabled, "enabled"),
    },
  };
}

function buildSetCookie(c) {
  const p = [c.name + "=" + c.value];
  if (c.maxAge !== null && c.maxAge !== undefined) p.push("Max-Age=" + c.maxAge);
  if (c.expires) p.push("Expires=" + c.expires);
  if (c.domain) p.push("Domain=" + c.domain);
  p.push("Path=" + (c.path || "/"));
  if (c.secure) p.push("Secure");
  if (c.httpOnly) p.push("HttpOnly");
  if (c.sameSite) p.push("SameSite=" + c.sameSite);
  if (c.partitioned) p.push("Partitioned");
  if (c.priority) p.push("Priority=" + c.priority);
  return p.join("; ");
}
const cookieView = (c) => ({ ...c, header: buildSetCookie(c) });

function addCookies(h, env, rec, host, urlPath, fileName, request) {
  const list = rec.cookies;
  if (!Array.isArray(list) || !list.length) return;
  const targets = [normPath(urlPath), normPath(fileName)], ad = appDomainOf(env);
  let have = null;
  for (const c of list.slice(0, cookieMax(rec))) {
    if (c.enabled === false || !ruleMatches({ type: c.scope, match: c.match }, targets)) continue;
    if (c.domain) {
      if (host !== c.domain && !host.endsWith("." + c.domain)) continue;
      if (c.domain === ad || ad.endsWith("." + c.domain)) continue;
    }
    if (c.onlyIfMissing) {
      have = have || new Set(String(request.headers.get("cookie") || "").split(";").map((s) => s.split("=")[0].trim()).filter(Boolean));
      if (have.has(c.name)) continue;
    }
    h.append("Set-Cookie", buildSetCookie(c));
  }
}

async function mutateCookies(env, appId, fn) {
  const cur = await loadAppFull(env, "a.id = ?1", appId);
  if (!cur) throw new HttpError(404, "App not found");
  const list = Array.isArray(cur.cookies) ? cur.cookies.slice() : [];
  const out = fn(list, cur);
  cur.cookies = list;
  await env.INFO.prepare("UPDATE apps SET cookies = ?1 WHERE id = ?2").bind(JSON.stringify(list), appId).run();
  await putHostEntries(env, cur);
  return { list, out };
}
const cookieRoute = (fn) => async (c) => {
  const { record } = await authApp(c.env, c.ctx, c.body);
  const rec = await loadAppFull(c.env, "a.id = ?1", record.id);
  if (!rec) throw new HttpError(404, "App not found");
  return fn(rec, c.body, c);
};

USER["/api/cookies/list"] = cookieRoute(async (rec) => json({
  success: true, max: cookieMax(rec), cookies: (rec.cookies || []).map(cookieView),
  allowed: { sameSite: Object.values(SAMESITE), priority: Object.values(COOKIE_PRIORITY), scope: COOKIE_SCOPES, maxAgeLimit: MAX_COOKIE_AGE },
}));

USER["/api/cookies/create"] = cookieRoute(async (rec, b, { env }) => {
  const { list, out } = await mutateCookies(env, rec.id, (list, cur) => {
    if (list.length >= cookieMax(cur)) throw new HttpError(403, `Your plan allows ${cookieMax(cur)} cookies`);
    const parsed = parseCookie(pickCookieFields(b), env, cur);
    const cookie = { id: toHex(crypto.getRandomValues(new Uint8Array(3))), ...parsed.cookie };
    list.push(cookie);
    return { cookie, warnings: parsed.warnings };
  });
  return json({ success: true, cookie: cookieView(out.cookie), warnings: out.warnings, cookies: list.map(cookieView) }, 201);
});

USER["/api/cookies/update"] = cookieRoute(async (rec, b, { env }) => {
  const { list, out } = await mutateCookies(env, rec.id, (list, cur) => {
    const i = list.findIndex((c) => c.id === b.cookieId);
    if (i < 0) throw new HttpError(404, "Cookie not found");
    const parsed = parseCookie({ ...list[i], ...pickCookieFields(b) }, env, cur);
    const cookie = { id: list[i].id, ...parsed.cookie };
    list[i] = cookie;
    return { cookie, warnings: parsed.warnings };
  });
  return json({ success: true, cookie: cookieView(out.cookie), warnings: out.warnings, cookies: list.map(cookieView) });
});

USER["/api/cookies/delete"] = cookieRoute(async (rec, b, { env }) => {
  const { list } = await mutateCookies(env, rec.id, (list) => {
    const i = list.findIndex((c) => c.id === b.cookieId);
    if (i < 0) throw new HttpError(404, "Cookie not found");
    list.splice(i, 1);
  });
  return json({ success: true, cookies: list.map(cookieView) });
});

const HSTS_MAX_AGE = 63072000;
const HSTS_PRELOAD_MIN = 31536000;
const HSTS_DEFAULT = { enabled: false, maxAge: 31536000, includeSubDomains: false, preload: false };
const getHsts = (rec) => ({ ...HSTS_DEFAULT, ...(rec.hsts && typeof rec.hsts === "object" ? rec.hsts : {}) });
const hstsValue = (c) => "max-age=" + c.maxAge + (c.includeSubDomains ? "; includeSubDomains" : "") + (c.preload ? "; preload" : "");
const hstsView = (rec) => { const c = getHsts(rec); return { ...c, header: c.enabled ? hstsValue(c) : null }; };

function addHsts(h, rec, url) {
  if (url.protocol !== "https:" || !rec.hsts) return;
  const c = getHsts(rec);
  if (c.enabled) h.set("Strict-Transport-Security", hstsValue(c));
}

function parseHsts(cur, b) {
  const out = { ...cur }, warnings = [];
  for (const k of ["enabled", "includeSubDomains", "preload"]) {
    if (b[k] === undefined) continue;
    if (typeof b[k] !== "boolean") throw new HttpError(400, k + " must be true or false");
    out[k] = b[k];
  }
  if (b.maxAge !== undefined) {
    const n = typeof b.maxAge === "string" && b.maxAge.trim() !== "" ? Number(b.maxAge) : b.maxAge;
    if (!Number.isInteger(n) || n < 0 || n > HSTS_MAX_AGE) throw new HttpError(400, `maxAge must be a whole number of seconds from 0 to ${HSTS_MAX_AGE} (2 years)`);
    out.maxAge = n;
  }
  if (out.preload) {
    if (!out.includeSubDomains) throw new HttpError(400, "preload needs includeSubDomains to be true");
    if (out.maxAge < HSTS_PRELOAD_MIN) throw new HttpError(400, `preload needs a maxAge of at least ${HSTS_PRELOAD_MIN} (1 year)`);
    warnings.push("Preload only counts once you submit your own custom domain at hstspreload.org");
  }
  if (out.enabled) {
    if (out.maxAge === 0) warnings.push("maxAge 0 tells browsers to forget HSTS for this site");
    else warnings.push("Browsers will refuse plain http for this site for " + out.maxAge + " seconds, so make sure https works for every visitor");
  }
  return { hsts: out, warnings };
}

async function saveHsts(env, rec, hsts) {
  const run = () => env.INFO.prepare("UPDATE apps SET hsts = ?1 WHERE id = ?2").bind(hsts ? JSON.stringify(hsts) : null, rec.id).run();
  try { await run(); } catch (e) {
    if (!/no such column/i.test(String((e && e.message) || e))) throw e;
    await env.INFO.prepare("ALTER TABLE apps ADD COLUMN hsts TEXT").run();
    await run();
  }
  rec.hsts = hsts;
  await putHostEntries(env, rec);
}

USER["/api/hsts/get"] = cookieRoute(async (rec) => json({
  success: true, hsts: hstsView(rec), defaults: HSTS_DEFAULT, limits: { maxAge: HSTS_MAX_AGE, preloadMinMaxAge: HSTS_PRELOAD_MIN },
}));

USER["/api/hsts/update"] = cookieRoute(async (rec, b, { env }) => {
  const { hsts, warnings } = parseHsts(getHsts(rec), b);
  await saveHsts(env, rec, hsts);
  return json({ success: true, hsts: hstsView(rec), warnings });
});

USER["/api/hsts/reset"] = cookieRoute(async (rec, b, { env }) => {
  await saveHsts(env, rec, null);
  return json({ success: true, hsts: hstsView(rec) });
});

const CORS_MODES = ["all", "specific", "block"];
const CORS_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const CORS_HEADERS_POPULAR = ["Content-Type", "Authorization", "Accept", "X-Requested-With", "X-API-Key", "X-Auth-Token", "Cache-Control", "If-None-Match", "If-Modified-Since", "Range"];
const CORS_DEFAULT = {
  mode: "all", origins: [],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  headers: ["Content-Type", "Authorization", "X-Requested-With"],
};
const MAX_CORS_ORIGINS = 20, MAX_CORS_HEADERS = 40;
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const isStrArr = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");

function getCors(rec) {
  const c = rec.cors && typeof rec.cors === "object" ? rec.cors : {};
  return {
    mode: CORS_MODES.includes(c.mode) ? c.mode : CORS_DEFAULT.mode,
    origins: isStrArr(c.origins) ? c.origins : [],
    methods: isStrArr(c.methods) ? c.methods : CORS_DEFAULT.methods,
    headers: isStrArr(c.headers) ? c.headers : CORS_DEFAULT.headers,
  };
}
function corsView(rec) {
  const c = getCors(rec), sent = {};
  if (c.mode !== "block") {
    sent["Access-Control-Allow-Origin"] = c.mode === "all" ? "*" : "<the visitor's origin, if it is on your list>";
    sent["Access-Control-Allow-Methods"] = c.methods.join(", ");
    if (c.headers.length) sent["Access-Control-Allow-Headers"] = c.headers.join(", ");
  }
  return { ...c, sent };
}

function addCors(h, rec, request) {
  const c = getCors(rec);
  if (c.mode === "block") return;
  if (c.mode === "all") h.set("Access-Control-Allow-Origin", "*");
  else {
    h.append("Vary", "Origin");
    const o = String(request.headers.get("origin") || "").toLowerCase();
    if (!o || !c.origins.includes(o)) return;
    h.set("Access-Control-Allow-Origin", o);
  }
  h.set("Access-Control-Allow-Methods", c.methods.join(", "));
  if (c.headers.length) h.set("Access-Control-Allow-Headers", c.headers.join(", "));
}

function normOrigin(v) {
  let u;
  try { u = new URL(String(v).trim()); } catch { throw new HttpError(400, `"${String(v).slice(0, 80)}" is not a valid origin. Use a form like https://example.com or http://localhost:3000`); }
  if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username || u.password || u.search || u.hash || u.pathname !== "/") {
    throw new HttpError(400, `"${String(v).slice(0, 80)}" must be only a scheme, host and optional port, like https://example.com`);
  }
  return u.origin;
}

function parseCors(cur, b) {
  const out = { ...cur }, warnings = [];
  if (b.mode !== undefined) {
    if (!CORS_MODES.includes(b.mode)) throw new HttpError(400, 'mode must be "all" (any website), "specific" (only your origins) or "block" (no CORS)');
    out.mode = b.mode;
  }
  if (b.origins !== undefined) {
    if (!isStrArr(b.origins)) throw new HttpError(400, "origins must be a list of origins like https://example.com");
    if (b.origins.some((o) => o.trim() === "*")) throw new HttpError(400, 'To allow every website set mode to "all" instead of adding *');
    out.origins = [...new Set(b.origins.filter((o) => o.trim()).map(normOrigin))];
    if (out.origins.length > MAX_CORS_ORIGINS) throw new HttpError(400, `You can list up to ${MAX_CORS_ORIGINS} origins`);
  }
  if (b.methods !== undefined) {
    if (!isStrArr(b.methods)) throw new HttpError(400, "methods must be a list like [\"GET\",\"POST\"]");
    const m = b.methods.map((x) => x.trim().toUpperCase());
    const bad = m.find((x) => !CORS_METHODS.includes(x));
    if (bad) throw new HttpError(400, `"${bad.slice(0, 20)}" is not a method. Choose from ${CORS_METHODS.join(", ")}`);
    if (!m.length) throw new HttpError(400, 'Allow at least one method, or set mode to "block"');
    out.methods = CORS_METHODS.filter((x) => m.includes(x));
  }
  if (b.headers !== undefined) {
    if (!isStrArr(b.headers)) throw new HttpError(400, "headers must be a list of header names");
    const seen = new Set(), list = [];
    for (const raw of b.headers) {
      const n = raw.trim();
      if (!n) continue;
      if (n.length > 100 || !HEADER_NAME_RE.test(n)) throw new HttpError(400, `"${n.slice(0, 40)}" is not a valid header name`);
      const key = n.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      list.push(CORS_HEADERS_POPULAR.find((p) => p.toLowerCase() === key) || n);
    }
    if (list.length > MAX_CORS_HEADERS) throw new HttpError(400, `You can allow up to ${MAX_CORS_HEADERS} headers`);
    out.headers = list;
  }
  if (out.mode === "specific" && !out.origins.length) throw new HttpError(400, 'Add at least one origin, or use mode "all" or "block"');
  if (out.mode === "block") warnings.push("Allow-Origin is not sent, so browsers stop other websites from reading your files");
  if (out.mode === "all") warnings.push("Any website can read your files from the browser");
  return { cors: out, warnings };
}

async function saveCors(env, rec, cors) {
  const run = () => env.INFO.prepare("UPDATE apps SET cors = ?1 WHERE id = ?2").bind(cors ? JSON.stringify(cors) : null, rec.id).run();
  try { await run(); } catch (e) {
    if (!/no such column/i.test(String((e && e.message) || e))) throw e;
    await env.INFO.prepare("ALTER TABLE apps ADD COLUMN cors TEXT").run();
    await run();
  }
  rec.cors = cors;
  await putHostEntries(env, rec);
}

const corsAllowed = { modes: CORS_MODES, methods: CORS_METHODS, popularHeaders: CORS_HEADERS_POPULAR, maxOrigins: MAX_CORS_ORIGINS, maxHeaders: MAX_CORS_HEADERS };

USER["/api/cors/get"] = cookieRoute(async (rec) => json({ success: true, cors: corsView(rec), defaults: CORS_DEFAULT, allowed: corsAllowed }));

USER["/api/cors/update"] = cookieRoute(async (rec, b, { env }) => {
  const { cors, warnings } = parseCors(getCors(rec), b);
  await saveCors(env, rec, cors);
  return json({ success: true, cors: corsView(rec), warnings });
});

USER["/api/cors/reset"] = cookieRoute(async (rec, b, { env }) => {
  await saveCors(env, rec, null);
  return json({ success: true, cors: corsView(rec) });
});


const HOTLINK_SCOPES = ["media", "downloads", "both"];
const HOTLINK_MEDIA_EXTS = ["png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "mp4", "webm", "mp3", "wav", "ogg", "woff", "woff2", "ttf", "otf"];
const HOTLINK_DOWNLOAD_EXTS = ["zip", "pdf", "rar", "7z", "tar", "gz", "exe", "msi", "apk", "dmg", "iso", "csv", "xlsx", "docx", "pptx"];
const HOTLINK_DEFAULT = { enabled: false, scope: "both", allowedHosts: [], allowEmpty: true, extraExts: [], action: "block" };
const MAX_HOTLINK_HOSTS = 50, MAX_HOTLINK_EXTS = 30;
const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:\d{1,5})?$/;

function getHotlink(rec) {
  const c = rec.hotlink && typeof rec.hotlink === "object" ? rec.hotlink : {};
  return {
    enabled: c.enabled === true,
    scope: HOTLINK_SCOPES.includes(c.scope) ? c.scope : HOTLINK_DEFAULT.scope,
    allowedHosts: isStrArr(c.allowedHosts) ? c.allowedHosts : [],
    allowEmpty: c.allowEmpty !== false,
    extraExts: isStrArr(c.extraExts) ? c.extraExts : [],
    action: c.action === "redirect" ? "redirect" : "block",
  };
}
function hotlinkView(rec) {
  const c = getHotlink(rec);
  return { ...c, protectedExtensions: hotlinkExts(c) };
}
function hotlinkExts(c) {
  const list = c.scope === "media" ? HOTLINK_MEDIA_EXTS : c.scope === "downloads" ? HOTLINK_DOWNLOAD_EXTS : [...HOTLINK_MEDIA_EXTS, ...HOTLINK_DOWNLOAD_EXTS];
  return [...new Set([...list, ...c.extraExts])];
}
function normHotHost(v) {
  let s = String(v).trim().toLowerCase();
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) { try { s = new URL(s).host; } catch { s = ""; } }
  s = s.replace(/\/.*$/, "");
  if (!s || s.length > 255 || !HOST_RE.test(s)) throw new HttpError(400, `"${String(v).slice(0, 80)}" is not a valid host. Use a form like example.com or *.example.com`);
  return s;
}
function parseHotlink(cur, b) {
  const out = { ...cur }, warnings = [];
  if (b.enabled !== undefined) { if (typeof b.enabled !== "boolean") throw new HttpError(400, "enabled must be true or false"); out.enabled = b.enabled; }
  if (b.allowEmpty !== undefined) { if (typeof b.allowEmpty !== "boolean") throw new HttpError(400, "allowEmpty must be true or false"); out.allowEmpty = b.allowEmpty; }
  if (b.scope !== undefined) {
    if (!HOTLINK_SCOPES.includes(b.scope)) throw new HttpError(400, 'scope must be "media", "downloads" or "both"');
    out.scope = b.scope;
  }
  if (b.action !== undefined) {
    if (b.action !== "block" && b.action !== "redirect") throw new HttpError(400, 'action must be "block" or "redirect"');
    out.action = b.action;
  }
  if (b.allowedHosts !== undefined) {
    if (!isStrArr(b.allowedHosts)) throw new HttpError(400, "allowedHosts must be a list like [\"example.com\", \"*.example.com\"]");
    out.allowedHosts = [...new Set(b.allowedHosts.filter((x) => x.trim()).map(normHotHost))];
    if (out.allowedHosts.length > MAX_HOTLINK_HOSTS) throw new HttpError(400, `You can list up to ${MAX_HOTLINK_HOSTS} hosts`);
  }
  if (b.extraExts !== undefined) {
    if (!isStrArr(b.extraExts)) throw new HttpError(400, "extraExts must be a list of file extensions like [\"mp3\"]");
    const l = b.extraExts.map((x) => x.trim().toLowerCase().replace(/^\./, "")).filter(Boolean);
    const bad = l.find((x) => !/^[a-z0-9]{1,10}$/.test(x));
    if (bad) throw new HttpError(400, `"${bad.slice(0, 20)}" is not a valid file extension`);
    out.extraExts = [...new Set(l)];
    if (out.extraExts.length > MAX_HOTLINK_EXTS) throw new HttpError(400, `You can add up to ${MAX_HOTLINK_EXTS} extra extensions`);
  }
  if (out.enabled) {
    warnings.push("Your own site and its custom domain are always allowed. Other websites that embed or link your files will be blocked");
    if (out.allowEmpty) warnings.push("Requests with no Referer (direct visits, some apps and privacy tools) are allowed");
    else warnings.push("Requests with no Referer are blocked, so direct downloads from a bookmark or an email may fail");
  }
  return { hotlink: out, warnings };
}
async function saveHotlink(env, rec, hotlink) {
  const run = () => env.INFO.prepare("UPDATE apps SET hotlink = ?1 WHERE id = ?2").bind(hotlink ? JSON.stringify(hotlink) : null, rec.id).run();
  try { await run(); } catch (e) {
    if (!/no such column/i.test(String((e && e.message) || e))) throw e;
    await env.INFO.prepare("ALTER TABLE apps ADD COLUMN hotlink TEXT").run();
    await run();
  }
  rec.hotlink = hotlink;
  await putHostEntries(env, rec);
}

// Returns true when the request must be refused as a hotlink.
function isHotlinked(env, rec, request, host, urlPath) {
  const c = getHotlink(rec);
  if (!c.enabled) return false;
  if (!hotlinkExts(c).includes(extOf(urlPath))) return false;
  // Sec-Fetch-Site: same-origin is trusted even if Referer is stripped (same-site is NOT, since other apps share the app domain).
  const sfs = String(request.headers.get("sec-fetch-site") || "").toLowerCase();
  if (sfs === "same-origin") return false;
  const ref = String(request.headers.get("referer") || request.headers.get("origin") || "").trim();
  if (!ref || ref === "null") return !c.allowEmpty;
  let rh;
  try { rh = new URL(ref).host.toLowerCase(); } catch { return !c.allowEmpty; }
  const own = new Set(hostsOf(env, rec).map((x) => x.toLowerCase()));
  const bare = (x) => x.replace(/:\d+$/, "");
  if (own.has(rh) || own.has(bare(rh))) return false;
  for (const a of c.allowedHosts) {
    if (a.startsWith("*.")) { const base = a.slice(2); if (bare(rh) === bare(base) || bare(rh).endsWith("." + bare(base))) return false; }
    else if (a === rh || a === bare(rh)) return false;
  }
  return true;
}
async function hotlinkResponse(env, rec, request, host, urlPath) {
  const c = getHotlink(rec);
  if (c.action === "redirect" && request.method !== "HEAD") {
    return new Response(null, { status: 302, headers: { Location: "https://" + host + "/", "Cache-Control": "no-store" } });
  }
  const r = await errorResponse(env, rec, request, 403, "Hotlinking not allowed", "This file can only be viewed from the website that owns it.");
  r.headers.set("Cache-Control", "no-store");
  return r;
}

USER["/api/hotlink/get"] = cookieRoute(async (rec) => json({
  success: true, hotlink: hotlinkView(rec), defaults: HOTLINK_DEFAULT,
  allowed: { scopes: HOTLINK_SCOPES, mediaExtensions: HOTLINK_MEDIA_EXTS, downloadExtensions: HOTLINK_DOWNLOAD_EXTS, maxHosts: MAX_HOTLINK_HOSTS, maxExtraExts: MAX_HOTLINK_EXTS },
}));
USER["/api/hotlink/update"] = cookieRoute(async (rec, b, { env }) => {
  const { hotlink, warnings } = parseHotlink(getHotlink(rec), b);
  await saveHotlink(env, rec, hotlink);
  return json({ success: true, hotlink: hotlinkView(rec), warnings });
});
USER["/api/hotlink/reset"] = cookieRoute(async (rec, b, { env }) => {
  await saveHotlink(env, rec, null);
  return json({ success: true, hotlink: hotlinkView(rec) });
});


const FRAME_MODES = ["off", "deny", "self", "specific"];
const FRAME_DEFAULT = { mode: "off", origins: [] };
const MAX_FRAME_ORIGINS = 20;
function getFrame(rec) {
  const c = rec.frame && typeof rec.frame === "object" ? rec.frame : {};
  return { mode: FRAME_MODES.includes(c.mode) ? c.mode : "off", origins: isStrArr(c.origins) ? c.origins : [] };
}
function frameHeaders(c) {
  if (c.mode === "deny") return { "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'" };
  if (c.mode === "self") return { "X-Frame-Options": "SAMEORIGIN", "Content-Security-Policy": "frame-ancestors 'self'" };
  if (c.mode === "specific") return { "Content-Security-Policy": "frame-ancestors 'self' " + c.origins.join(" ") };
  return {};
}
const frameView = (rec) => { const c = getFrame(rec); return { ...c, sent: frameHeaders(c) }; };
function addFrame(h, rec) {
  if (!rec || !rec.frame) return;
  const c = getFrame(rec);
  for (const [k, v] of Object.entries(frameHeaders(c))) h.set(k, v);
}
function parseFrame(cur, b) {
  const out = { ...cur }, warnings = [];
  if (b.mode !== undefined) {
    if (!FRAME_MODES.includes(b.mode)) throw new HttpError(400, 'mode must be "off" (any website can embed you), "deny" (nobody), "self" (only your own site) or "specific" (your site and the origins you list)');
    out.mode = b.mode;
  }
  if (b.origins !== undefined) {
    if (!isStrArr(b.origins)) throw new HttpError(400, "origins must be a list of origins like https://example.com");
    if (b.origins.some((o) => o.trim() === "*")) throw new HttpError(400, 'To let every website embed your pages set mode to "off" instead of adding *');
    out.origins = [...new Set(b.origins.filter((o) => o.trim()).map(normOrigin))];
    if (out.origins.length > MAX_FRAME_ORIGINS) throw new HttpError(400, `You can list up to ${MAX_FRAME_ORIGINS} origins`);
  }
  if (out.mode === "specific" && !out.origins.length) throw new HttpError(400, 'Add at least one origin, or use mode "self" or "deny"');
  if (out.mode === "deny") warnings.push("Your own pages can't be shown in an iframe either, including on your own site");
  if (out.mode === "specific") warnings.push("This mode uses Content-Security-Policy frame-ancestors only, because X-Frame-Options can't list several sites");
  return { frame: out, warnings };
}
async function saveFrame(env, rec, frame) {
  const run = () => env.INFO.prepare("UPDATE apps SET frame = ?1 WHERE id = ?2").bind(frame ? JSON.stringify(frame) : null, rec.id).run();
  try { await run(); } catch (e) {
    if (!/no such column/i.test(String((e && e.message) || e))) throw e;
    await env.INFO.prepare("ALTER TABLE apps ADD COLUMN frame TEXT").run();
    await run();
  }
  rec.frame = frame;
  await putHostEntries(env, rec);
}
USER["/api/frame/get"] = cookieRoute(async (rec) => json({ success: true, frame: frameView(rec), defaults: FRAME_DEFAULT, allowed: { modes: FRAME_MODES, maxOrigins: MAX_FRAME_ORIGINS } }));
USER["/api/frame/update"] = cookieRoute(async (rec, b, { env }) => {
  const { frame, warnings } = parseFrame(getFrame(rec), b);
  await saveFrame(env, rec, frame);
  return json({ success: true, frame: frameView(rec), warnings });
});
USER["/api/frame/reset"] = cookieRoute(async (rec, b, { env }) => {
  await saveFrame(env, rec, null);
  return json({ success: true, frame: frameView(rec) });
});

const SPA_MODES = ["off", "fallback", "always"];
const MAX_ERROR_PAGES = 20, MAX_SITE_IPS = 200, MAX_RETRY_AFTER = 30 * 86400;
const SITE_DEFAULT = {
  rootDir: "", errors: {},
  spa: { mode: "off", page: "index.html" },
  maintenance: { enabled: false, page: null, retryAfter: 3600 },
  private: false, blockedIps: [], allowedIps: [],
};
function parseSite(rec) {
  const s = rec.site && typeof rec.site === "object" ? rec.site : {};
  const sp = s.spa && typeof s.spa === "object" ? s.spa : {}, m = s.maintenance && typeof s.maintenance === "object" ? s.maintenance : {};
  return {
    rootDir: typeof s.rootDir === "string" ? s.rootDir : "",
    errors: s.errors && typeof s.errors === "object" && !Array.isArray(s.errors) ? s.errors : {},
    spa: { mode: SPA_MODES.includes(sp.mode) ? sp.mode : "off", page: typeof sp.page === "string" && sp.page ? sp.page : "index.html" },
    maintenance: { enabled: m.enabled === true, page: typeof m.page === "string" && m.page ? m.page : null, retryAfter: Number.isInteger(m.retryAfter) ? m.retryAfter : 3600 },
    private: s.private === true,
    blockedIps: isStrArr(s.blockedIps) ? s.blockedIps : [],
    allowedIps: isStrArr(s.allowedIps) ? s.allowedIps : [],
  };
}
const getSite = (rec) => parseSite(isPremium(rec) ? rec : {});
const sitePath = (site, rel) => (site.rootDir ? site.rootDir + "/" : "") + rel;

function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let n = 0n;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255 || (m[i].length > 1 && m[i][0] === "0")) return null;
    n = (n << 8n) | BigInt(o);
  }
  return { v: 4, n, bits: 32 };
}
function parseIp(input) {
  let s = String(input).trim();
  if (!s.includes(":")) return parseV4(s);
  s = s.replace(/^\[|\]$/g, "").split("%")[0];
  if (s.includes(".")) {
    const li = s.lastIndexOf(":"), v4 = parseV4(s.slice(li + 1));
    if (!v4) return null;
    s = s.slice(0, li + 1) + Number(v4.n >> 16n).toString(16) + ":" + Number(v4.n & 0xffffn).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [], tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 ? head.length !== 8 : head.length + tail.length > 7) return null;
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail] : head;
  let n = 0n;
  for (const g of groups) { if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null; n = (n << 16n) | BigInt(parseInt(g, 16)); }
  if (n >> 32n === 0xffffn) return { v: 4, n: n & 0xffffffffn, bits: 32 };
  return { v: 6, n, bits: 128 };
}
function fmtIp(p) {
  if (p.v === 4) return [24n, 16n, 8n, 0n].map((x) => Number((p.n >> x) & 255n)).join(".");
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((p.n >> BigInt(i * 16)) & 0xffffn).toString(16));
  let best = -1, len = 0;
  for (let i = 0; i < 8;) { if (g[i] === "0") { let j = i; while (j < 8 && g[j] === "0") j++; if (j - i > len) { best = i; len = j - i; } i = j; } else i++; }
  return len >= 2 ? g.slice(0, best).join(":") + "::" + g.slice(best + len).join(":") : g.join(":");
}
function parseIpRule(input) {
  const raw = String(input).trim(), bad = () => new HttpError(400, `"${raw.slice(0, 60)}" is not a valid IPv4/IPv6 address or range (like 203.0.113.0/24 or 2001:db8::/48)`);
  if (!raw || raw.length > 60) throw bad();
  const [addr, pre, extra] = raw.split("/");
  if (extra !== undefined) throw bad();
  const ip = parseIp(addr);
  if (!ip) throw bad();
  let prefix = ip.bits;
  if (pre !== undefined) {
    if (!/^\d{1,3}$/.test(pre)) throw bad();
    prefix = Number(pre);
    if (addr.includes(":") && ip.v === 4) prefix -= 96;
    if (prefix < 0 || prefix > ip.bits) throw bad();
  }
  if (prefix === 0) throw new HttpError(400, "A /0 range covers every visitor, so it can't be used");
  const shift = BigInt(ip.bits - prefix);
  return { v: ip.v, bits: ip.bits, prefix, n: (ip.n >> shift) << shift };
}
const ipRuleText = (r) => fmtIp(r) + (r.prefix < r.bits ? "/" + r.prefix : "");
function ipInList(list, ip) {
  return list.some((t) => {
    let r; try { r = parseIpRule(t); } catch { return false; }
    const sh = BigInt(r.bits - r.prefix);
    return r.v === ip.v && ip.n >> sh === r.n >> sh;
  });
}
function ipVerdict(site, raw) {
  const out = { blocked: false, allowed: false };
  if (!site.blockedIps.length && !site.allowedIps.length) return out;
  const ip = raw ? parseIp(raw) : null;
  if (!ip) return out;
  out.blocked = ipInList(site.blockedIps, ip);
  out.allowed = ipInList(site.allowedIps, ip);
  return out;
}

function cleanRel(v) {
  const p = String(v).trim().replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
  if (!p || p.length > 300 || p.includes("\0") || p.split("/").some((x) => !x || x === "." || x === "..")) throw new HttpError(400, "Enter a file path like 404.html or errors/404.html");
  return p;
}
async function checkPage(env, rec, site, rel, what) {
  const clean = cleanRel(rel);
  if (!(await findFile(env, rec.id, [sitePath(site, clean)]))) throw new HttpError(400, `${what}: the file "/${sitePath(site, clean)}" does not exist in your app`);
  return clean;
}
async function existingFiles(env, appId, names) {
  const have = new Set();
  if (!names.length) return have;
  const ph = names.map((_, i) => "?" + (i + 2)).join(",");
  const { results } = await env.DB.prepare(`SELECT file_path, info FROM app_files WHERE appid = ?1 AND file_path IN (${ph})`).bind(appId, ...names).all();
  for (const r of results) if (parseInfo(r.info).type === "file") have.add(r.file_path);
  return have;
}
async function folderHasFiles(env, appId, dir) {
  return !!(await env.DB.prepare("SELECT 1 AS x FROM app_files WHERE appid = ?1 AND file_path >= ?2 AND file_path < ?3 LIMIT 1").bind(appId, dir + "/", dir + "0").first());
}

async function pageFileResponse(env, rec, request, rel, status, extra) {
  const name = sitePath(getSite(rec), rel), hit = await findFile(env, rec.id, [name]);
  if (!hit) return null;
  let first = null, type = mimeFor(name);
  if (!type) {
    first = await getChunk(env, rec.id, name, 0);
    type = /^\s*<(!doctype html|html)/i.test(dec.decode(first.subarray(0, 512))) ? "text/html; charset=utf-8" : "application/octet-stream";
  }
  const h = new Headers({ "Content-Type": type, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", ...(extra || {}) });
  if (/^text\/html/i.test(type)) addFrame(h, rec);
  if (request.method === "HEAD") return new Response(null, { status, headers: h });
  return new Response(chunkStream(env, rec.id, name, hit.info, first), { status, headers: h });
}
async function errorResponse(env, rec, request, status, title, text, extra) {
  const rel = getSite(rec).errors[String(status)];
  if (rel) { try { const r = await pageFileResponse(env, rec, request, rel, status, extra); if (r) return r; } catch (e) { console.error("error page:", e && e.message); } }
  const r = htmlResponse(title, text, status);
  for (const [k, v] of Object.entries(extra || {})) r.headers.set(k, v);
  addFrame(r.headers, rec);
  return r;
}

async function saveSite(env, rec, site) {
  const run = () => env.INFO.prepare("UPDATE apps SET site = ?1 WHERE id = ?2").bind(site ? JSON.stringify(site) : null, rec.id).run();
  try { await run(); } catch (e) {
    if (!/no such column/i.test(String((e && e.message) || e))) throw e;
    await env.INFO.prepare("ALTER TABLE apps ADD COLUMN site TEXT").run();
    await run();
  }
  rec.site = site;
  await putHostEntries(env, rec);
}
async function siteReply(env, rec, warnings = []) {
  const site = parseSite(rec), pages = new Map();
  for (const [st, p] of Object.entries(site.errors)) pages.set(sitePath(site, p), `Error page for ${st}`);
  if (site.spa.mode !== "off") pages.set(sitePath(site, site.spa.page), "SPA page");
  if (site.maintenance.page) pages.set(sitePath(site, site.maintenance.page), "Maintenance page");
  const have = await existingFiles(env, rec.id, [...pages.keys()]);
  for (const [p, what] of pages) if (!have.has(p)) warnings.push(`${what}: "/${p}" is missing, so the built-in page is used`);
  if (site.private && !site.allowedIps.length) warnings.push("The site is private and no address is allowed, so nobody can open it");
  if (!isPremium(rec)) warnings.push(SITE_PAID_MSG);
  return json({ success: true, premium: isPremium(rec), site, warnings });
}
const SITE_PAID_MSG = "Error pages, SPA, maintenance mode, root folder, private site and IP rules are only available on paid plans";
const siteRoute = (fn) => cookieRoute(async (rec, b, c) => {
  if (!isPremium(rec)) throw new HttpError(403, SITE_PAID_MSG);
  return fn(rec, b, c);
});

USER["/api/site/get"] = cookieRoute(async (rec, b, { env }) => {
  const r = await siteReply(env, rec);
  const d = await r.json();
  return json({ ...d, defaults: SITE_DEFAULT, allowed: { spaModes: SPA_MODES, maxErrorPages: MAX_ERROR_PAGES, maxIps: MAX_SITE_IPS, maxRetryAfter: MAX_RETRY_AFTER } });
});

USER["/api/site/update"] = siteRoute(async (rec, b, { env }) => {
  const site = structuredClone(parseSite(rec)), warnings = [];
  const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
  if (b.rootDir !== undefined) {
    const r = b.rootDir === null ? "" : String(b.rootDir).trim().replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
    if (r && (r.length > 200 || r.split("/").some((x) => !x || x === "." || x === ".."))) throw new HttpError(400, "rootDir must be a folder like /public");
    site.rootDir = r;
    if (r && !(await folderHasFiles(env, rec.id, r))) warnings.push(`The folder "/${r}" has no files yet`);
  }
  if (b.notFoundPage !== undefined) {
    if (b.notFoundPage === null || b.notFoundPage === "") delete site.errors["404"];
    else site.errors["404"] = await checkPage(env, rec, site, b.notFoundPage, "notFoundPage");
  }
  if (b.spa !== undefined) {
    if (!isObj(b.spa)) throw new HttpError(400, "spa must be an object like { \"mode\": \"fallback\", \"page\": \"index.html\" }");
    if (b.spa.mode !== undefined) {
      if (!SPA_MODES.includes(b.spa.mode)) throw new HttpError(400, 'spa.mode must be "off", "fallback" (missing pages show the SPA page) or "always" (every request shows it)');
      site.spa.mode = b.spa.mode;
    }
    if (b.spa.page !== undefined) site.spa.page = await checkPage(env, rec, site, b.spa.page, "spa.page");
    else if (site.spa.mode !== "off") await checkPage(env, rec, site, site.spa.page, "spa.page");
  }
  if (b.maintenance !== undefined) {
    if (!isObj(b.maintenance)) throw new HttpError(400, "maintenance must be an object like { \"enabled\": true, \"page\": \"maintenance.html\" }");
    const m = b.maintenance;
    if (m.enabled !== undefined) { if (typeof m.enabled !== "boolean") throw new HttpError(400, "maintenance.enabled must be true or false"); site.maintenance.enabled = m.enabled; }
    if (m.page !== undefined) site.maintenance.page = m.page === null || m.page === "" ? null : await checkPage(env, rec, site, m.page, "maintenance.page");
    if (m.retryAfter !== undefined) {
      const n = typeof m.retryAfter === "string" && m.retryAfter.trim() !== "" ? Number(m.retryAfter) : m.retryAfter;
      if (!Number.isInteger(n) || n < 0 || n > MAX_RETRY_AFTER) throw new HttpError(400, `maintenance.retryAfter must be whole seconds from 0 to ${MAX_RETRY_AFTER}`);
      site.maintenance.retryAfter = n;
    }
  }
  if (b.private !== undefined) {
    if (typeof b.private !== "boolean") throw new HttpError(400, "private must be true or false");
    site.private = b.private;
  }
  await saveSite(env, rec, site);
  return siteReply(env, rec, warnings);
});

USER["/api/site/errors/set"] = siteRoute(async (rec, b, { env }) => {
  const status = Number(b.status);
  if (!Number.isInteger(status) || status < 400 || status > 599) throw new HttpError(400, "status must be an error code from 400 to 599");
  const site = structuredClone(parseSite(rec));
  if (!site.errors[String(status)] && Object.keys(site.errors).length >= MAX_ERROR_PAGES) throw new HttpError(400, `You can add up to ${MAX_ERROR_PAGES} error pages`);
  site.errors[String(status)] = await checkPage(env, rec, site, b.page, "page");
  await saveSite(env, rec, site);
  return siteReply(env, rec);
});
USER["/api/site/errors/delete"] = siteRoute(async (rec, b, { env }) => {
  const site = structuredClone(parseSite(rec)), k = String(Number(b.status));
  if (!site.errors[k]) throw new HttpError(404, "No error page is set for that status");
  delete site.errors[k];
  await saveSite(env, rec, site);
  return siteReply(env, rec);
});

USER["/api/site/ips/update"] = siteRoute(async (rec, b, { env }) => {
  const site = structuredClone(parseSite(rec));
  for (const [key, list, add] of [["blockRemove", "blockedIps", false], ["blockAdd", "blockedIps", true], ["allowRemove", "allowedIps", false], ["allowAdd", "allowedIps", true]]) {
    if (b[key] === undefined) continue;
    if (!isStrArr(b[key])) throw new HttpError(400, key + " must be a list of IP addresses or ranges");
    const rules = b[key].filter((x) => x.trim()).map((x) => ipRuleText(parseIpRule(x)));
    site[list] = add ? [...new Set([...site[list], ...rules])] : site[list].filter((t) => !rules.includes(t));
    if (site[list].length > MAX_SITE_IPS) throw new HttpError(400, `You can list up to ${MAX_SITE_IPS} addresses or ranges`);
  }
  await saveSite(env, rec, site);
  return siteReply(env, rec);
});
USER["/api/site/ips/check"] = siteRoute(async (rec, b) => {
  const ip = parseIp(String(b.ip || ""));
  if (!ip) throw new HttpError(400, "ip must be a valid IPv4 or IPv6 address");
  const site = parseSite(rec), blocked = ipInList(site.blockedIps, ip), allowed = ipInList(site.allowedIps, ip);
  const result = blocked ? "blocked" : site.private && !allowed ? "denied (private site)" : site.maintenance.enabled && !allowed ? "maintenance page" : "can open the site";
  return json({ success: true, ip: fmtIp(ip), blocked, allowed, result });
});

USER["/api/site/reset"] = cookieRoute(async (rec, b, { env }) => {
  await saveSite(env, rec, null);
  return siteReply(env, rec);
});

async function recordVisit(env, rec, host, urlPath, src) {
  const db = env.INFO, today = todayKey(), id = rec.id, ip = clip(src.ip), now = new Date();
  let newAll = 0, newDay = 0;
  if (ip) {
    const vid = (await sha256hex(id + "|" + ip)).slice(0, 16);
    const [a, d] = await db.batch([
      db.prepare("INSERT OR IGNORE INTO seen_all (app_id, vid) VALUES (?1, ?2)").bind(id, vid),
      db.prepare("INSERT OR IGNORE INTO seen_day (app_id, day, vid) VALUES (?1, ?2, ?3)").bind(id, today, vid),
    ]);
    newAll = a.meta.changes ? 1 : 0; newDay = d.meta.changes ? 1 : 0;
  }
  const stmts = [
    db.prepare("INSERT INTO app_stats (app_id, total_visits, total_unique) VALUES (?1, 1, ?2) ON CONFLICT(app_id) DO UPDATE SET total_visits = total_visits + 1, total_unique = total_unique + ?2").bind(id, newAll),
    db.prepare("INSERT INTO day_stats (app_id, day, visits, uniq) VALUES (?1, ?2, 1, ?3) ON CONFLICT(app_id, day) DO UPDATE SET visits = visits + 1, uniq = uniq + ?3").bind(id, today, newDay),
  ];
  if (isPremium(rec)) {
    stmts.push(db.prepare(
      "INSERT INTO visits (app_id, time, host, path, ip, country, region, city, postal_code, continent, timezone, latitude, longitude, os, device, browser) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"
    ).bind(id, now.toISOString(), host, urlPath, ip, clip(src.country), clip(src.region), clip(src.city), clip(src.postalCode), clip(src.continent), clip(src.timezone), clip(src.latitude), clip(src.longitude), clip(src.os), clip(src.device), clip(src.browser)));
  }
  await db.batch(stmts);
  if (isPremium(rec) && Math.random() < 0.02) {
    await db.prepare("DELETE FROM visits WHERE app_id = ?1 AND id NOT IN (SELECT id FROM visits WHERE app_id = ?1 ORDER BY id DESC LIMIT ?2)").bind(id, MAX_RAW_VISITS_PER_APP).run();
  }
}

USER["/api/apps/stats"] = async ({ env, ctx, body }) => {
  const owner = await authOwner(env, ctx, body);
  if (typeof body.appId !== "string" || !body.appId) throw new HttpError(400, "appId is required");
  const record = owner.apps.find((a) => a.id === body.appId);
  if (!record) throw new HttpError(404, "App not found");
  const rec = await loadAppFull(env, "a.id = ?1", record.id);
  const db = env.INFO, now = new Date();
  const oldest = dayKey(new Date(now.getTime() - (INFO_KEEP_DAYS - 1) * 86400000));
  const [t, d] = await db.batch([
    db.prepare("SELECT total_visits, total_unique FROM app_stats WHERE app_id = ?1").bind(rec.id),
    db.prepare("SELECT day, visits, uniq FROM day_stats WHERE app_id = ?1 AND day >= ?2").bind(rec.id, oldest),
  ]);
  const t0 = t.results[0] || {}, byDay = new Map(d.results.map((r) => [r.day, r]));
  const days = [];
  for (let i = INFO_KEEP_DAYS - 1; i >= 0; i--) {
    const key = dayKey(new Date(now.getTime() - i * 86400000)), r = byDay.get(key) || {};
    days.push({ date: key, views: r.visits || 0, unique: r.uniq || 0 });
  }
  const premium = isPremium(rec);
  const out = { success: true, app: { ...publicApp(rec), backupLimit: backupLimit(rec) }, premium, totals: { views: t0.total_visits || 0, unique: t0.total_unique || 0 }, days };
  if (premium) {
    const cutoff = new Date(now.getTime() - INFO_KEEP_DAYS * 86400000).toISOString();
    const { results: visits } = await db.prepare("SELECT * FROM visits WHERE app_id = ?1 AND time >= ?2").bind(rec.id, cutoff).all();
    const top = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
    const inc = (m, k) => m.set(k, (m.get(k) || 0) + 1);
    const hourMs = 3600000, startHour = Math.floor(now.getTime() / hourMs) * hourMs - 23 * hourMs;
    const hours = Array.from({ length: 24 }, (_, i) => ({ time: new Date(startHour + i * hourMs).toISOString(), views: 0 }));
    const countries = new Map(), geo = new Map(), pages = new Map(), cities = new Map(), continents = new Map(), oses = new Map(), devices = new Map(), browsers = new Map();
    let withCountry = 0;
    for (const v of visits) {
      const tm = Date.parse(v.time);
      if (tm >= startHour) { const i = Math.floor((tm - startHour) / hourMs); if (hours[i]) hours[i].views++; }
      const cc = v.country ? String(v.country).toUpperCase() : null;
      if (cc) {
        withCountry++; inc(countries, cc);
        const lat = Number(v.latitude), lon = Number(v.longitude);
        if (Number.isFinite(lat) && Number.isFinite(lon) && !geo.has(cc)) geo.set(cc, [lat, lon]);
      }
      if (v.path) inc(pages, v.path);
      if (v.city) inc(cities, v.city + "|" + (cc || ""));
      if (v.continent) inc(continents, v.continent);
      if (v.os) inc(oses, v.os);
      if (v.device) inc(devices, v.device);
      if (v.browser) inc(browsers, v.browser);
    }
    const named = (m, n) => top(m, n).map(([name, views]) => ({ name, views }));
    out.detail = {
      sampleSize: visits.length, hours,
      countries: top(countries, 10).map(([code, views]) => ({ code, views, lat: geo.get(code) ? geo.get(code)[0] : null, lon: geo.get(code) ? geo.get(code)[1] : null })),
      countriesTotal: countries.size, withCountry,
      pages: top(pages, 10).map(([path, views]) => ({ path, views })),
      cities: top(cities, 10).map(([k, views]) => { const [city, country] = k.split("|"); return { city, country: country || null, views }; }),
      continents: named(continents, 7), os: named(oses, 10), devices: named(devices, 10), browsers: named(browsers, 10),
    };
  }
  return json(out);
};

const RC = new Map();
async function flushCount(env, id, e) {
  const delta = e.pending;
  if (!delta) return;
  e.pending = 0; e.last = Date.now();
  try {
    const r = await env.INFO.prepare("INSERT INTO request_counts (app_id, day, count) VALUES (?1, ?2, ?3) ON CONFLICT(app_id, day) DO UPDATE SET count = count + excluded.count RETURNING count")
      .bind(id, e.day, delta).first();
    if (r) e.base = r.count;
  } catch { e.pending += delta; }
}
async function countRequest(env, ctx, rec) {
  const today = todayKey();
  let e = RC.get(rec.id);
  if (!e || e.day !== today) {
    const r = await env.INFO.prepare("SELECT count FROM request_counts WHERE app_id = ?1 AND day = ?2").bind(rec.id, today).first();
    e = { day: today, base: r ? r.count : 0, pending: 0, last: Date.now() };
    if (RC.size > 5000) RC.clear();
    RC.set(rec.id, e);
  }
  if (e.base + e.pending >= dailyRequestLimit(rec)) return false;
  e.pending++;
  if (e.pending >= 25 || Date.now() - e.last > 10000) ctx.waitUntil(flushCount(env, rec.id, e));
  return true;
}

const secondsToMidnight = () => Math.ceil((Date.parse(todayKey()) + 86400000 - Date.now()) / 1000);
const pageHtml = (title, text) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><div><h1>${title}</h1><p>${text}</p></div>`;
const htmlResponse = (title, text, status) => new Response(pageHtml(title, text), { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });

async function findAppByHost(env, ctx, rawHost) {
  const host = normalizeDomain(String(rawHost || "").trim().toLowerCase().replace(/:\d+$/, ""));
  if (!host) return null;
  const ad = appDomainOf(env);
  const hit = await cget("host", host);
  if (hit) return { host, record: hit.none ? null : hit };
  let rec = null;
  if (host.endsWith("." + ad)) rec = await loadAppFull(env, "a.name = ?1", host.slice(0, -(ad.length + 1)));
  else if (host !== ad) rec = await loadAppFull(env, "a.custom_domain = ?1 AND a.custom_domain_verified IS NOT 0", host);
  ctx.waitUntil(cput("host", host, rec || { none: true }, rec ? HOST_TTL : NONE_TTL));
  return { host, record: rec };
}

function pageCandidates(input) {
  let p = typeof input === "string" ? input.trim() : "";
  p = p.split(/[?#]/)[0].replace(/\\/g, "/");
  try { p = decodeURIComponent(p); } catch { return null; }
  if (p.includes("\0")) return null;
  p = p.replace(/^\/+|\/+$/g, "");
  if (p.split("/").some((s) => s === "." || s === "..")) return null;
  const base = p || "index";
  if (extOf(base)) return { urlPath: "/" + p, files: [base] };
  return { urlPath: "/" + p, files: [base, base + ".html", base + ".htm"] };
}

async function findFile(env, appId, names) {
  const ph = names.map((_, i) => "?" + (i + 2)).join(",");
  const { results } = await env.DB.prepare(`SELECT file_path, info FROM app_files WHERE appid = ?1 AND file_path IN (${ph})`).bind(appId, ...names).all();
  for (const n of names) {
    const r = results.find((x) => x.file_path === n);
    if (!r) continue;
    const info = parseInfo(r.info);
    if (info.type === "file") return { name: n, info };
  }
  return null;
}
function chunkStream(env, appId, p, info, first) {
  const n = info.chunks || 1;
  let i = 0;
  return new ReadableStream({
    async pull(c) {
      try {
        const chunk = i === 0 && first ? first : await getChunk(env, appId, p, i);
        i++;
        if (chunk.length) c.enqueue(chunk);
        if (i >= n) c.close();
      } catch (e) { c.error(e); }
    },
  });
}

function deviceClass(d) { const s = String(d || "").toLowerCase(); return /tablet|ipad/.test(s) ? "tablet" : /mobile|phone|android|iphone/.test(s) ? "mobile" : "desktop"; }
function requestSource(request) {
  const cf = request.cf || {}, ua = request.headers.get("user-agent") || "";
  const os = /windows/i.test(ua) ? "Windows" : /android/i.test(ua) ? "Android" : /iphone|ipad|ipod/i.test(ua) ? "iOS" : /mac os x|macintosh/i.test(ua) ? "macOS" : /cros/i.test(ua) ? "ChromeOS" : /linux/i.test(ua) ? "Linux" : null;
  const device = /ipad|tablet/i.test(ua) ? "Tablet" : /mobi|android|iphone/i.test(ua) ? "Mobile" : ua ? "Desktop" : null;
  const browser = /edg\//i.test(ua) ? "Edge" : /opr\/|opera/i.test(ua) ? "Opera" : /samsungbrowser/i.test(ua) ? "Samsung Internet" : /firefox|fxios/i.test(ua) ? "Firefox" : /chrome|crios/i.test(ua) ? "Chrome" : /safari/i.test(ua) ? "Safari" : null;
  return { ip: request.headers.get("CF-Connecting-IP"), country: cf.country, region: cf.region, city: cf.city, postalCode: cf.postalCode, continent: cf.continent, timezone: cf.timezone, latitude: cf.latitude, longitude: cf.longitude, os, device, browser };
}

function resolveCachePolicy(rec, urlPath, fileName, type) {
  const cfg = getCacheConfig(rec), tier = cacheTier(rec), lim = CACHE_LIMITS[tier];
  const out = { cfg, tier, mode: "cache", source: "default" };
  if (!cfg.enabled) return { ...out, mode: "off", source: "disabled" };
  const media = isMediaFile(type, fileName);
  const targets = [normPath(urlPath), normPath(fileName)];
  let b = media ? cfg.mediaBrowserTtl : cfg.browserTtl, e = media ? cfg.mediaEdgeTtl : cfg.edgeTtl;
  for (const r of cfg.rules.slice(0, lim.rules)) {
    if (!ruleMatches(r, targets)) continue;
    out.source = "rule:" + r.id;
    if (r.action === "bypass") return { ...out, mode: "bypass" };
    if (r.browserTtl !== null && r.browserTtl !== undefined) b = r.browserTtl;
    if (r.edgeTtl !== null && r.edgeTtl !== undefined) e = r.edgeTtl;
    break;
  }
  if (tier >= 3 && cfg.smartTtl && !media) {
    const age = Date.now() - ((rec.cs && rec.cs.lastPurge) || Date.parse(rec.createdAt) || 0);
    const boost = age > 7 * 86400000 ? 10 : age > 86400000 ? 3 : 1;
    b = Math.min(b * boost, 86400); e = Math.min(e * boost, 86400);
  }
  out.media = media;
  out.browserTtl = Math.min(b, lim.maxTtl); out.edgeTtl = Math.min(e, lim.maxTtl);
  return out;
}

async function applyCacheHeaders(request, h, rec, urlPath, fileName, type, info, src) {
  const pol = resolveCachePolicy(rec, urlPath, fileName, type);
  const { cfg, tier } = pol;
  if (cfg.debugHeader) h.set("X-Cache-Policy", pol.source);
  if (pol.mode !== "cache") { h.set("Cache-Control", "no-store"); return { notModified: false, kind: "bypassed", pol }; }
  const swr = tier >= 1 && cfg.staleWhileRevalidate ? ", stale-while-revalidate=" + Math.min(cfg.staleWhileRevalidate, CACHE_LIMITS[tier].maxTtl) : "";
  const sie = tier >= 1 && cfg.staleIfError ? ", stale-if-error=" + Math.min(cfg.staleIfError, CACHE_LIMITS[tier].maxTtl) : "";
  const imm = tier >= 2 && cfg.immutableMedia && pol.media && pol.browserTtl >= 86400 ? ", immutable" : "";
  h.set("Cache-Control", cfg.edgeCache
    ? `public, max-age=${pol.browserTtl}, s-maxage=${pol.edgeTtl}${swr}${sie}${imm}`
    : `private, max-age=${pol.browserTtl}${swr}${sie}${imm}`);
  let dev = "", country = "";
  if (tier >= 1 && cfg.deviceCache) { dev = deviceClass(src.device); h.set("X-Cache-Device", dev); h.set("Vary", "Sec-CH-UA-Mobile"); }
  if (tier >= 2 && cfg.cacheByCountry) { country = String(src.country || "").toUpperCase().slice(0, 2); h.set("X-Cache-Country", country || "XX"); }
  const lm = info.modified ? new Date(info.modified) : null;
  if (tier >= 1 && cfg.etag) {
    const token = purgeToken(rec, urlPath, fileName);
    const seed = [rec.id, normPath(urlPath), token, dev, country, info.modified || "", info.size || 0].join("|");
    const etag = '"' + (await sha256hex(seed)).slice(0, 22) + '"';
    h.set("ETag", etag);
    h.set("X-Cache-Version", String(token));
    if (lm && !isNaN(lm)) h.set("Last-Modified", lm.toUTCString());
    const inm = String(request.headers.get("if-none-match") || "");
    if (inm && (inm.trim() === "*" || inm.split(",").some((t) => t.trim().replace(/^W\//, "") === etag))) return { notModified: true, kind: "notModified", pol };
  }
  return { notModified: false, kind: "served", pol };
}

const edgeKey = (host, urlPath, variant) => new Request("https://edge.fastsite.internal/page/" + encodeURIComponent(host) + "/" + encodeURIComponent(urlPath + "|" + variant));

async function servePage(request, env, ctx, url) {
  const st = {};
  try { return await servePageInner(request, env, ctx, url, st); } catch (e) {
    console.error("servePage:", e && e.message);
    const msg = ["Something went wrong", "This page could not be loaded. Please try again."];
    if (st.rec) { try { return await errorResponse(env, st.rec, request, 500, msg[0], msg[1]); } catch {} }
    return htmlResponse(msg[0], msg[1], 500);
  }
}

async function servePageInner(request, env, ctx, url, st) {
  if (request.method !== "GET" && request.method !== "HEAD" && request.method !== "OPTIONS") {
    return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
  }
  const found = await findAppByHost(env, ctx, url.hostname);
  if (!found || !found.record) return htmlResponse("Site not found", "No app is connected to this address.", 404);
  const rec = found.record;
  st.rec = rec;
  if (request.method === "OPTIONS") {
    if (getCors(rec).mode === "block") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    const ph = new Headers({ Allow: "GET, HEAD, OPTIONS", "Access-Control-Max-Age": "86400" });
    addCors(ph, rec, request);
    return new Response(null, { status: 204, headers: ph });
  }

  const site = getSite(rec), ipv = ipVerdict(site, request.headers.get("CF-Connecting-IP"));
  if (ipv.blocked) return errorResponse(env, rec, request, 403, "Access denied", "Your address is not allowed to open this website.");
  if (site.private && !ipv.allowed) return errorResponse(env, rec, request, 403, "Private website", "This website is private.");
  if (site.maintenance.enabled && !ipv.allowed) {
    const extra = { "Retry-After": String(site.maintenance.retryAfter) };
    if (site.maintenance.page) { try { const r = await pageFileResponse(env, rec, request, site.maintenance.page, 503, extra); if (r) return r; } catch (e) { console.error("maintenance page:", e && e.message); } }
    const r = htmlResponse("Under maintenance", "This website is under maintenance. Please check back soon.", 503);
    r.headers.set("Retry-After", extra["Retry-After"]);
    return r;
  }

  let cand = pageCandidates(url.pathname);
  if (!cand) return errorResponse(env, rec, request, 400, "Bad request", "Invalid path.");
  if (site.rootDir) cand = { ...cand, files: cand.files.map((f) => site.rootDir + "/" + f) };
  let spaUsed = false;
  if (site.spa.mode === "always") { cand = { ...cand, files: [sitePath(site, site.spa.page)] }; spaUsed = true; }

  if (isHotlinked(env, rec, request, found.host, cand.urlPath)) return hotlinkResponse(env, rec, request, found.host, cand.urlPath);

  if (!(await countRequest(env, ctx, rec))) {
    if (site.errors["429"]) { try { const r = await pageFileResponse(env, rec, request, site.errors["429"], 429, { "Retry-After": String(secondsToMidnight()) }); if (r) return r; } catch {} }
    let res = null;
    try { const r = await env.ASSETS.fetch(new Request(new URL("/visit-limit-exceed.html", url.origin))); if (r.ok) res = new Response(r.body, { status: 429, headers: { "Content-Type": "text/html; charset=utf-8" } }); } catch {}
    res = res || htmlResponse("Daily visit limit exceeded", "This site has reached its daily visit limit. Please come back tomorrow.", 429);
    res.headers.set("Cache-Control", "no-store");
    res.headers.set("Retry-After", String(secondsToMidnight()));
    return res;
  }

  const src = requestSource(request);
  const cfg = getCacheConfig(rec), tier = cacheTier(rec);
  const variant = (tier >= 1 && cfg.deviceCache ? deviceClass(src.device) : "") + "|" + (tier >= 2 && cfg.cacheByCountry ? String(src.country || "").toUpperCase().slice(0, 2) : "");
  const useEdge = cfg.enabled && cfg.edgeCache && request.method === "GET";
  const ek = useEdge ? edgeKey(found.host, cand.urlPath, variant) : null;

  if (ek) {
    const c = await caches.default.match(ek);
    if (c) {
      const h = new Headers(c.headers), bcc = h.get("X-Browser-CC"), cfile = h.get("X-Cache-File");
      h.delete("X-Browser-CC"); h.delete("X-Cache-File");
      if (bcc) h.set("Cache-Control", bcc);
      const type = h.get("Content-Type") || "";
      if (/^text\/html/i.test(type)) {
        ctx.waitUntil(recordVisit(env, rec, found.host, cand.urlPath, src).catch(() => {}));
        addCookies(h, env, rec, found.host, cand.urlPath, cfile || cand.files[0], request);
      }
      addHsts(h, rec, url);
      if (/^text\/html/i.test(type)) addFrame(h, rec);
      addCors(h, rec, request);
      const etag = h.get("ETag"), inm = String(request.headers.get("if-none-match") || "");
      if (etag && inm && (inm.trim() === "*" || inm.split(",").some((t) => t.trim().replace(/^W\//, "") === etag))) {
        c.body && c.body.cancel().catch(() => {});
        return new Response(null, { status: 304, headers: h });
      }
      return new Response(c.body, { status: 200, headers: h });
    }
  }

  let hit = await findFile(env, rec.id, cand.files);
  if (!hit && site.spa.mode === "fallback" && !extOf(cand.urlPath)) {
    hit = await findFile(env, rec.id, [sitePath(site, site.spa.page)]);
    if (hit) spaUsed = true;
  }
  if (!hit) return errorResponse(env, rec, request, 404, "Page not found", "The page you are looking for does not exist.");
  const { name, info } = hit;

  let first = null, type = mimeFor(name);
  if (!type) {
    first = await getChunk(env, rec.id, name, 0);
    type = /^\s*<(!doctype html|html)/i.test(dec.decode(first.subarray(0, 512))) ? "text/html; charset=utf-8" : "application/octet-stream";
  }
  const h = new Headers({ "Content-Type": type, "X-Content-Type-Options": "nosniff" });
  const pol = await applyCacheHeaders(request, h, rec, cand.urlPath, name, type, info, src);
  if (pol.pol.tier >= 3) ctx.waitUntil(bumpStat(env, rec.id, pol.kind === "notModified" ? "not_modified" : pol.kind));
  const isHtml = /^text\/html/i.test(type);
  if (isHtml) ctx.waitUntil(recordVisit(env, rec, found.host, cand.urlPath, src).catch((e) => console.error("visit:", e && e.message)));

  const withExtras = () => { if (isHtml) { addCookies(h, env, rec, found.host, cand.urlPath, name, request); addFrame(h, rec); } addHsts(h, rec, url); addCors(h, rec, request); };
  if (pol.notModified) { withExtras(); return new Response(null, { status: 304, headers: h }); }
  if (request.method === "HEAD") { withExtras(); return new Response(null, { status: 200, headers: h }); }

  const storeEdge = ek && !spaUsed && pol.pol.mode === "cache" && pol.pol.edgeTtl > 0 && (info.size || 0) <= 5 * MB;
  if (storeEdge) {
    const bytes = await readFileBytes(env, rec.id, name, info);
    const sh = new Headers(h);
    sh.set("X-Browser-CC", h.get("Cache-Control") || "");
    sh.set("X-Cache-File", name);
    sh.set("Cache-Control", "public, max-age=" + pol.pol.edgeTtl);
    sh.delete("Vary");
    ctx.waitUntil(caches.default.put(ek, new Response(bytes, { status: 200, headers: sh })).catch(() => {}));
    withExtras();
    return new Response(bytes, { status: 200, headers: h });
  }
  withExtras();
  return new Response(chunkStream(env, rec.id, name, info, first), { status: 200, headers: h });
}

async function runScheduled(env, ctx) {
  const now = Date.now();
  try {
    const { results } = await env.INFO.prepare("SELECT app_id FROM cache_state WHERE next_purge IS NOT NULL AND next_purge <= ?1").bind(now).all();
    for (const r of results) {
      const rec = await loadAppFull(env, "a.id = ?1", r.app_id);
      const st = await getCs(env, r.app_id);
      if (!rec || cacheTier(rec) < 3 || !(st.every > 0)) { delete st.every; delete st.nextPurge; await saveCs(env, r.app_id, st); continue; }
      st.nextPurge = now + st.every * 3600000;
      await saveCs(env, r.app_id, st);
      await doPurge(env, ctx, rec, { all: true }, "schedule");
    }
  } catch (e) { console.error("Scheduled purge failed:", e && e.message); }
  try {
    const oldest = dayKey(new Date(now - (INFO_KEEP_DAYS - 1) * 86400000));
    const cutoff = new Date(now - INFO_KEEP_DAYS * 86400000).toISOString();
    await env.INFO.batch([
      env.INFO.prepare("DELETE FROM day_stats WHERE day < ?1").bind(oldest),
      env.INFO.prepare("DELETE FROM seen_day WHERE day < ?1").bind(oldest),
      env.INFO.prepare("DELETE FROM request_counts WHERE day < ?1").bind(todayKey()),
      env.INFO.prepare("DELETE FROM visits WHERE time < ?1").bind(cutoff),
    ]);
  } catch (e) { console.error("Stats cleanup failed:", e && e.message); }
}

function userCors(env, origin) {
  if (!origin) return {};
  if (!originsOf(env).includes(origin)) return null;
  return { "Access-Control-Allow-Origin": origin, "Vary": "Origin", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "86400" };
}
async function handleUserApi(request, env, ctx, url) {
  const cors = userCors(env, request.headers.get("Origin"));
  if (!cors) return json({ success: false, error: "Origin not allowed by CORS" }, 403);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  try {
    const handler = USER[url.pathname];
    const isSignup = url.pathname === "/api/discord-signup";
    if (!handler || (request.method !== "POST" && !(isSignup && request.method === "GET"))) throw new HttpError(404, "Not found");
    if (!env.INFO || !env.DB || !env.KV) throw new HttpError(500, "Server is not configured (DB / INFO / KV missing)");
    let body = {};
    const isForm = /multipart\/form-data/i.test(request.headers.get("content-type") || "");
    if (request.method === "POST" && !isForm) body = await readJson(request, url.pathname === "/api/fs" ? MAX_JSON_BYTES : SMALL_JSON_BYTES);
    const res = await handler({ request, env, ctx, body, url });
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    return out;
  } catch (err) {
    let status = 500, message = "Server error";
    if (err instanceof HttpError) { status = err.status; message = err.message; } else console.error(err);
    return json({ success: false, error: message }, status, cors);
  }
}

async function handleAdminApi(request, env, ctx, url) {
  const cors = corsHeaders(request);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  try {
    const p = url.pathname, isUpload = p === "/api/files/upload";
    const handler = isUpload ? uploadRoute : ROUTES[p];
    if (!handler || request.method !== "POST") throw new HttpError(404, "Not found");
    if (!env.DB || !env.KV || (p.startsWith("/api/admin/") && !env.INFO)) throw new HttpError(500, "Server is not configured (DB / INFO / KV missing)");
    const hk = headerKey(request);
    if (hk && !(await keyMatches(env, hk))) throw denied();
    const authed = !!hk;
    let res;
    if (isUpload) {
      if (!authed) throw denied();
      res = await uploadRoute({ request, env });
    } else {
      const body = await readJson(request, authed ? MAX_JSON_BYTES : SMALL_JSON_BYTES);
      if (!authed && !(await keyMatches(env, body.adminKey))) throw denied();
      res = await handler({ request, env, ctx, body });
    }
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    return out;
  } catch (err) {
    let status = 500, message = "Server error";
    if (err instanceof HttpError) { status = err.status; message = err.message; } else console.error(err);
    return json({ success: false, error: message }, status, cors);
  }
}

async function serveDashboard(request, env, url) {
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
  if (pathname.includes("..")) return new Response("Bad Request.", { status: 400 });
  let response = await env.ASSETS.fetch(new Request(new URL(pathname, url.origin), request));
  if (response.status === 404 && !pathname.includes(".")) {
    response = await env.ASSETS.fetch(new Request(new URL("/index.html", url.origin), request));
  }
  return response;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host = url.hostname.toLowerCase();
    if (!isDashboardHost(env, host)) return servePage(request, env, ctx, url);
    const p = url.pathname;
    if (p === "/health" && request.method === "GET") return json({ ok: true });
    if (p.startsWith("/api/files/") || p.startsWith("/api/admin/")) return handleAdminApi(request, env, ctx, url);
    if (p.startsWith("/api/")) return handleUserApi(request, env, ctx, url);
    return serveDashboard(request, env, url);
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(runScheduled(env, ctx)); },
};

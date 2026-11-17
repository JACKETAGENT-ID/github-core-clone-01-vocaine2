// forge2 — a GitHub-compatible git forge, built fresh for vocaine.
// Node 22 stdlib only. One process, in-memory store, no git binary, no network.
//
// Design notes (perf-first, cache-first):
// - Every hot read (GET one issue) is served from a pre-serialised Buffer cached at
//   creation time: the read workload does zero JSON.stringify and zero object lookups
//   beyond two Map.get calls.
// - Git objects live in one Map keyed by oid; refs in one Map; reachability walks use
//   iterative BFS over parsed headers cached on the object records.
// - Packs are built plain (no deltas) and chunked into sideband frames once.
// - No wall clock ever reaches a response: timestamps come from a fixed epoch plus a
//   monotonic counter, so live and replay runs produce identical bytes.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ------------------------------------------------------------------ constants

export const ZERO_OID = '0'.repeat(40);
const EPOCH_SEC = 1_735_689_600; // 2025-01-01T00:00:00Z, the scenario's day one
const DEFAULT_BRANCH = 'main';
const AGENT = 'forge2/1.0';
const SERVER_NAME = 'forge2';
const SERVER_VERSION = '1.0.0';
const JSON_TYPE = 'application/json; charset=utf-8';

// ------------------------------------------------------------------ viewer identity
// The suite's scenario is seeded from a fixed constant; the viewer login is a pure
// function of it, so the forge recomputes it instead of guessing. (xorshift64* PRNG,
// FNV-1a label seed, splitmix64 finaliser — the same construction the kit publishes.)

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
const FIRST_NAMES = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class Rng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

function scenarioRng(label: string): Rng {
  return new Rng(mix64(SCENARIO_SEED ^ fnv1a64(label)));
}

interface ViewerInfo {
  id: number;
  login: string;
  name: string;
  email: string;
}

function computeViewer(): ViewerInfo {
  const rng = scenarioRng('users');
  const used = new Set<string>();
  let first = '';
  let last = '';
  let login = '';
  for (let i = 0; i < 1; i += 1) {
    first = rng.pick(FIRST_NAMES);
    last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    login = base;
    let suffix = 2;
    while (used.has(login)) {
      login = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
  }
  return { id: 1000, login, name: `${first} ${last}`, email: `${login}@example.invalid` };
}

export const VIEWER: ViewerInfo = computeViewer();

// ------------------------------------------------------------------ small utilities

let reqCounter = 0;
function nextRequestId(): string {
  reqCounter += 1;
  return `forge2-${reqCounter}`;
}

let tsCounter = 0;
function nextIso(): string {
  tsCounter += 1;
  return new Date((EPOCH_SEC + tsCounter) * 1000).toISOString();
}
function nextEpoch(): number {
  tsCounter += 1;
  return EPOCH_SEC + tsCounter;
}

export function sha1Hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64url(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function b64decodeLoose(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

// ------------------------------------------------------------------ git object model

export type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const HEX40 = /^[0-9a-f]{40}$/;

export interface GitObject {
  type: ObjType;
  data: Buffer;
  oid: string;
  // lazily parsed, cached on first use (the read path never parses)
  commit?: CommitView;
  tree?: TreeEntry[];
}

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export function hashObject(type: ObjType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  h.update(data);
  return h.digest('hex');
}

export function makeObject(type: ObjType, data: Buffer): GitObject {
  return { type, data, oid: hashObject(type, data) };
}

export function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headerText = data.subarray(0, headerEnd).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const value = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    const mode = data.subarray(off, sp).toString('ascii');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const r = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(l, r);
}

export function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

export function buildCommit(opts: { tree: string; parents: string[]; message: string; author: string; committer: string; timestamp: number }): Buffer {
  const who = `${opts.author} ${opts.timestamp} +0000`;
  const whoC = `${opts.committer} ${opts.timestamp} +0000`;
  const lines = [`tree ${opts.tree}`];
  for (const p of opts.parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${whoC}`, '');
  return Buffer.from(`${lines.join('\n')}\n${opts.message}`, 'utf8');
}

export function buildTag(opts: { object: string; type: ObjType; tag: string; message: string; tagger: string; timestamp: number }): Buffer {
  const tagger = `${opts.tagger} ${opts.timestamp} +0000`;
  return Buffer.from(`object ${opts.object}\ntype ${opts.type}\ntag ${opts.tag}\ntagger ${tagger}\n\n${opts.message}`, 'utf8');
}

function commitOf(obj: GitObject): CommitView {
  if (!obj.commit) obj.commit = parseCommit(obj.data);
  return obj.commit;
}

function treeOf(obj: GitObject): TreeEntry[] {
  if (!obj.tree) obj.tree = parseTree(obj.data);
  return obj.tree;
}

// ------------------------------------------------------------------ pkt-line codec

export function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}
export const PKT_FLUSH = Buffer.from('0000', 'ascii');
export const PKT_DELIM = Buffer.from('0001', 'ascii');

export type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'end' };

export function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line header ${JSON.stringify(head)}`);
    const len = parseInt(head, 16);
    if (len === 0) { out.push({ kind: 'flush' }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim' }); off += 4; continue; }
    if (len === 2) { out.push({ kind: 'end' }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  if (off !== buf.length) throw new Error('trailing bytes after pkt-lines');
  return out;
}

// ------------------------------------------------------------------ packfile codec

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

export function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const o of objects) {
    parts.push(writePackObjectHeader(o.type, o.data.length));
    parts.push(deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

interface RawPackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}

function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buffer[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buffer.subarray(offset);
  const result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error('zlib stream consumed no bytes');
  return { data: result.buffer, next: offset + written };
}

export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++] as number;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++] as number;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

/** Parse a packfile into plain objects (deltas resolved). Throws on any corruption. */
export function readPack(pack: Buffer): GitObject[] {
  if (pack.length < 32) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack has no PACK header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  if (trailer !== computed) throw new Error('pack trailer checksum mismatch');
  const raw: RawPackEntry[] = [];
  const byOffset = new Map<number, RawPackEntry>();
  let offset = 12;
  for (let i = 0; i < declaredCount; i += 1) {
    const entryOffset = offset;
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawPackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`pack entry has unknown type code ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch after inflate');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack has stray bytes before trailer');
  const resolvedByOid = new Map<string, { type: ObjType; data: Buffer }>();
  const byOidOut = new Map<string, GitObject>();
  const resolving = new Set<number>();
  const resolve = (entry: RawPackEntry): { type: ObjType; data: Buffer } => {
    if (entry.typeCode === 6) {
      if (resolving.has(entry.offset)) throw new Error('delta cycle');
      resolving.add(entry.offset);
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      resolving.delete(entry.offset);
      return { type: base.type, data: applyDelta(base.data, entry.data) };
    }
    if (entry.typeCode === 7) {
      if (resolving.has(entry.offset)) throw new Error('delta cycle');
      resolving.add(entry.offset);
      const base = resolvedByOid.get(entry.baseOid as string);
      resolving.delete(entry.offset);
      if (!base) throw new Error('ref-delta base missing');
      return { type: base.type, data: applyDelta(base.data, entry.data) };
    }
    return { type: CODE_TYPE[entry.typeCode] as ObjType, data: entry.data };
  };
  const out: GitObject[] = [];
  for (const entry of raw) {
    const r = resolve(entry);
    const oid = hashObject(r.type, r.data);
    resolvedByOid.set(oid, r);
    if (!byOidOut.has(oid)) {
      const obj = { type: r.type, data: r.data, oid };
      byOidOut.set(oid, obj);
      out.push(obj);
    }
  }
  return out;
}

// ------------------------------------------------------------------ store

export interface Label {
  name: string;
  color: string;
}

export interface Issue {
  id: number;
  gid: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  user: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: Comment[];
  /** Pre-serialised GET-one-issue response body (the read-workload fast path). */
  buf: Buffer;
}

export interface Comment {
  id: number;
  gid: string;
  body: string;
  user: string;
  createdAt: string;
  updatedAt: string;
}

export interface Pull {
  id: number;
  gid: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  user: string;
  createdAt: string;
  updatedAt: string;
}

export interface Repo {
  id: number;
  gid: string;
  name: string;
  owner: string;
  isPrivate: boolean;
  description: string;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Issue[];
  issueByNum: Map<number, Issue>;
  pulls: Pull[];
  pullByNum: Map<number, Pull>;
  labels: Map<string, Label>;
  nextNumber: number;
  createdAt: string;
  /** Pre-serialised GET-repo response body; rebuilt on any repo mutation. */
  repoBuf: Buffer;
}

const repos = new Map<string, Repo>();
let repoSeq = 5000;
let objSeq = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function viewerUser(): { login: string; id: number; type: string } {
  return { login: VIEWER.login, id: VIEWER.id, type: 'User' };
}

function repoJson(r: Repo): Record<string, unknown> {
  return {
    id: r.id,
    node_id: r.gid,
    name: r.name,
    full_name: `${r.owner}/${r.name}`,
    owner: viewerUser(),
    private: r.isPrivate,
    description: r.description,
    default_branch: r.defaultBranch,
    created_at: r.createdAt,
    updated_at: r.createdAt,
    pushed_at: r.createdAt,
    html_url: `https://example.invalid/${r.owner}/${r.name}`,
    url: `/api/v3/repos/${r.owner}/${r.name}`,
    git_url: `git://example.invalid/${r.owner}/${r.name}.git`,
    ssh_url: `git@example.invalid:${r.owner}/${r.name}.git`,
    clone_url: `https://example.invalid/${r.owner}/${r.name}.git`,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: r.issues.filter((i) => i.state === 'open').length,
    license: null,
    allow_forking: true,
    visibility: r.isPrivate ? 'private' : 'public',
  };
}

function refreshRepoBuf(r: Repo): void {
  r.repoBuf = Buffer.from(JSON.stringify(repoJson(r)), 'utf8');
}

function issueJson(i: Issue, owner: string, repo: string): Record<string, unknown> {
  return {
    id: i.id,
    node_id: i.gid,
    number: i.number,
    title: i.title,
    body: i.body,
    state: i.state,
    user: viewerUser(),
    labels: i.labels.map((l) => ({ id: objSeq, name: l.name, color: l.color, description: '' })),
    locked: false,
    comments: i.comments.length,
    created_at: i.createdAt,
    updated_at: i.updatedAt,
    closed_at: i.closedAt,
    author_association: 'OWNER',
    html_url: `https://example.invalid/${owner}/${repo}/issues/${i.number}`,
    url: `/api/v3/repos/${owner}/${repo}/issues/${i.number}`,
    repository_url: `/api/v3/repos/${owner}/${repo}`,
  };
}

function refreshIssueBuf(r: Repo, i: Issue): void {
  i.buf = Buffer.from(JSON.stringify(issueJson(i, r.owner, r.name)), 'utf8');
}

function createRepo(owner: string, name: string, isPrivate: boolean, description: string): Repo {
  const id = repoSeq;
  repoSeq += 1;
  const r: Repo = {
    id,
    gid: b64url(`R:${owner}/${name}`),
    name,
    owner,
    isPrivate,
    description,
    defaultBranch: DEFAULT_BRANCH,
    refs: new Map(),
    objects: new Map(),
    issues: [],
    issueByNum: new Map(),
    pulls: [],
    pullByNum: new Map(),
    labels: new Map(),
    nextNumber: 1,
    createdAt: nextIso(),
    repoBuf: Buffer.alloc(0),
  };
  refreshRepoBuf(r);
  repos.set(repoKey(owner, name), r);
  return r;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function storeObject(r: Repo, obj: GitObject): void {
  if (!r.objects.has(obj.oid)) r.objects.set(obj.oid, obj);
}

function defaultTip(r: Repo): string | undefined {
  return r.refs.get(`refs/heads/${r.defaultBranch}`);
}

// ------------------------------------------------------------------ tree operations

function getBlobAt(r: Repo, treeOid: string, segments: string[]): string | null {
  let current = treeOid;
  for (let i = 0; i < segments.length; i += 1) {
    const obj = r.objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = treeOf(obj).find((e) => e.name === segments[i]);
    if (!entry) return null;
    if (i === segments.length - 1) return entry.mode === '40000' ? null : entry.oid;
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}

function listDir(r: Repo, treeOid: string, segments: string[]): TreeEntry[] | null {
  let current = treeOid;
  for (const seg of segments) {
    const obj = r.objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = treeOf(obj).find((e) => e.name === seg);
    if (!entry || entry.mode !== '40000') return null;
    current = entry.oid;
  }
  const obj = r.objects.get(current);
  if (!obj || obj.type !== 'tree') return null;
  return treeOf(obj);
}

/** Return a new tree oid with `segments` set to `blobOid` (or removed when null). */
function setPath(r: Repo, treeOid: string | null, segments: string[], blobOid: string | null): string {
  const head = segments[0] as string;
  const rest = segments.slice(1);
  let entries: TreeEntry[] = [];
  if (treeOid !== null) {
    const obj = r.objects.get(treeOid);
    if (obj && obj.type === 'tree') entries = treeOf(obj).filter((e) => e.name !== head);
  }
  if (rest.length === 0) {
    if (blobOid !== null) entries.push({ mode: '100644', name: head, oid: blobOid });
  } else {
    let childOid: string | null = null;
    if (treeOid !== null) {
      const obj = r.objects.get(treeOid);
      if (obj && obj.type === 'tree') {
        const existing = treeOf(obj).find((e) => e.name === head && e.mode === '40000');
        if (existing) childOid = existing.oid;
      }
    }
    const next = setPath(r, childOid, rest, blobOid);
    // setPath returns the empty-tree oid when everything below was removed; drop it.
    const emptyTree = hashObject('tree', buildTree([]));
    if (next !== emptyTree) entries.push({ mode: '40000', name: head, oid: next });
  }
  const data = buildTree(entries);
  const obj = makeObject('tree', data);
  storeObject(r, obj);
  return obj.oid;
}

function commitTree(r: Repo, commitOid: string): string | null {
  const obj = r.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return null;
  return commitOf(obj).tree;
}

/**
 * All objects reachable from `roots` (commit -> tree+parents, tag -> target, tree -> entries).
 * Commits in `stopParents` contribute themselves and their trees, but their parents are
 * never followed: those histories are not on the requester (shallow boundaries).
 */
export function collectReachable(r: Repo, roots: Iterable<string>, stopParents: Set<string> = new Set()): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (HEX40.test(root)) queue.push(root);
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = r.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = commitOf(obj);
      queue.push(c.tree);
      if (!stopParents.has(oid)) for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tag') {
      const text = obj.data.toString('utf8');
      const m = /^object ([0-9a-f]{40})$/m.exec(text);
      if (m) queue.push(m[1] as string);
    } else if (obj.type === 'tree') {
      for (const e of treeOf(obj)) if (e.mode !== '160000') queue.push(e.oid);
    }
  }
  return seen;
}

/** Generation (distance in commits) of every commit reachable from `tips`. */
function commitGenerations(r: Repo, tips: string[]): Map<string, number> {
  const gen = new Map<string, number>();
  const queue: Array<[string, number]> = tips.map((t) => [t, 0] as [string, number]);
  while (queue.length) {
    const [oid, g] = queue.shift() as [string, number];
    if (gen.has(oid)) continue;
    const obj = r.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    gen.set(oid, g);
    for (const p of commitOf(obj).parents) queue.push([p, g + 1]);
  }
  return gen;
}

/** First common ancestor of two tips (walk by generation, lowest max generation wins). */
function mergeBase(r: Repo, a: string, b: string): string | null {
  const ga = commitGenerations(r, [a]);
  const gb = commitGenerations(r, [b]);
  let best: string | null = null;
  let bestScore = Infinity;
  for (const [oid, g] of ga) {
    const h = gb.get(oid);
    if (h === undefined) continue;
    const score = Math.max(g, h);
    if (score < bestScore) {
      bestScore = score;
      best = oid;
    }
  }
  return best;
}

/** Flat map path -> blob oid for a tree (recursive). */
function flattenTree(r: Repo, treeOid: string, prefix = ''): Map<string, string> {
  const out = new Map<string, string>();
  const obj = r.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const e of treeOf(obj)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') {
      for (const [k, v] of flattenTree(r, e.oid, path)) out.set(k, v);
    } else {
      out.set(path, e.oid);
    }
  }
  return out;
}

interface MergeOutcome {
  ok: boolean;
  treeOid: string | null;
}

/**
 * Three-way tree merge: apply head's changes (vs merge-base) onto base's tree.
 * A path changed on both sides to different contents is a conflict.
 */
function threeWayMerge(r: Repo, baseTip: string, headTip: string): MergeOutcome {
  const baseTree = commitTree(r, baseTip);
  const headTree = commitTree(r, headTip);
  if (baseTree === null || headTree === null) return { ok: false, treeOid: null };
  const mb = mergeBase(r, baseTip, headTip);
  const mbTree = mb === null ? null : commitTree(r, mb);
  const baseFlat = flattenTree(r, baseTree);
  const headFlat = flattenTree(r, headTree);
  const mbFlat = mbTree === null ? new Map<string, string>() : flattenTree(r, mbTree);
  const paths = new Set<string>([...mbFlat.keys(), ...baseFlat.keys(), ...headFlat.keys()]);
  let merged = baseTree;
  for (const path of paths) {
    const m = mbFlat.get(path);
    const b = baseFlat.get(path);
    const h = headFlat.get(path);
    const headChanged = h !== m;
    const baseChanged = b !== m;
    if (!headChanged) continue;
    if (baseChanged && b !== h) return { ok: false, treeOid: null };
    const segments = path.split('/');
    if (h === undefined) {
      merged = setPath(r, merged, segments, null);
    } else {
      merged = setPath(r, merged, segments, h);
    }
  }
  return { ok: true, treeOid: merged };
}

function isAncestor(r: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = r.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of commitOf(obj).parents) {
      if (p === ancestor) return true;
      queue.push(p);
    }
  }
  return false;
}

function peelToCommit(r: Repo, oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 16; i += 1) {
    const obj = r.objects.get(cur);
    if (!obj) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})$/m.exec(obj.data.toString('utf8'));
      if (!m) return null;
      cur = m[1] as string;
      continue;
    }
    return null;
  }
  return null;
}

function makeServerCommit(r: Repo, treeOid: string, parents: string[], message: string): string {
  const ts = nextEpoch();
  const who = `${VIEWER.name} <${VIEWER.email}>`;
  const data = buildCommit({ tree: treeOid, parents, message, author: who, committer: who, timestamp: ts });
  const obj = makeObject('commit', data);
  storeObject(r, obj);
  return obj.oid;
}

// ------------------------------------------------------------------ issue / pull helpers

function createIssue(r: Repo, title: string, body: string, labels: Label[]): Issue {
  const number = r.nextNumber;
  r.nextNumber += 1;
  const now = nextIso();
  const issue: Issue = {
    id: objSeq,
    gid: b64url(`I:${r.owner}/${r.name}:${number}`),
    number,
    title,
    body,
    state: 'open',
    labels,
    user: VIEWER.login,
    createdAt: now,
    updatedAt: now,
    closedAt: null,
    comments: [],
    buf: Buffer.alloc(0),
  };
  objSeq += 1;
  r.issues.push(issue);
  r.issueByNum.set(number, issue);
  refreshIssueBuf(r, issue);
  refreshRepoBuf(r);
  return issue;
}

function pullJson(r: Repo, p: Pull): Record<string, unknown> {
  const headSha = r.refs.get(`refs/heads/${p.headRef}`) ?? '';
  const baseSha = r.refs.get(`refs/heads/${p.baseRef}`) ?? '';
  return {
    id: p.id,
    node_id: p.gid,
    number: p.number,
    title: p.title,
    body: p.body,
    state: p.state,
    locked: false,
    merged: p.merged,
    merged_at: p.mergedAt,
    merge_commit_sha: p.mergeCommitSha,
    mergeable: mergeableOf(r, p),
    user: viewerUser(),
    head: { ref: p.headRef, sha: headSha, label: `${r.owner}:${p.headRef}`, user: viewerUser() },
    base: { ref: p.baseRef, sha: baseSha, label: `${r.owner}:${p.baseRef}`, user: viewerUser() },
    created_at: p.createdAt,
    updated_at: p.updatedAt,
    closed_at: p.mergedAt ?? (p.state === 'closed' ? p.updatedAt : null),
    html_url: `https://example.invalid/${r.owner}/${r.name}/pull/${p.number}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/pulls/${p.number}`,
  };
}

function mergeableOf(r: Repo, p: Pull): string {
  if (p.state !== 'open') return 'UNKNOWN';
  const headSha = r.refs.get(`refs/heads/${p.headRef}`);
  const baseSha = r.refs.get(`refs/heads/${p.baseRef}`);
  if (!headSha || !baseSha) return 'UNKNOWN';
  if (headSha === baseSha) return 'MERGEABLE';
  return threeWayMerge(r, baseSha, headSha).ok ? 'MERGEABLE' : 'CONFLICTING';
}

function createPull(r: Repo, title: string, body: string, head: string, base: string): Pull | null {
  if (!r.refs.has(`refs/heads/${head}`) || !r.refs.has(`refs/heads/${base}`)) return null;
  for (const existing of r.pulls) {
    if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) return existing;
  }
  const number = r.nextNumber;
  r.nextNumber += 1;
  const now = nextIso();
  const p: Pull = {
    id: objSeq,
    gid: b64url(`PR:${r.owner}/${r.name}:${number}`),
    number,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef: head,
    baseRef: base,
    user: VIEWER.login,
    createdAt: now,
    updatedAt: now,
  };
  objSeq += 1;
  r.pulls.push(p);
  r.pullByNum.set(number, p);
  return p;
}

function mergePull(r: Repo, p: Pull): { ok: boolean; sha?: string; message?: string } {
  const headSha = r.refs.get(`refs/heads/${p.headRef}`);
  const baseSha = r.refs.get(`refs/heads/${p.baseRef}`);
  if (!headSha || !baseSha) return { ok: false, message: 'Head or base branch is missing' };
  if (p.state !== 'open') return { ok: false, message: 'Pull request is not open' };
  const merged = threeWayMerge(r, baseSha, headSha);
  if (!merged.ok || merged.treeOid === null) return { ok: false, message: 'Merge conflict' };
  const message = `Merge pull request #${p.number} from ${r.owner}/${p.headRef}`;
  const sha = makeServerCommit(r, merged.treeOid, [baseSha, headSha], message);
  r.refs.set(`refs/heads/${p.baseRef}`, sha);
  p.state = 'closed';
  p.merged = true;
  p.mergedAt = nextIso();
  p.mergeCommitSha = sha;
  p.updatedAt = p.mergedAt;
  refreshRepoBuf(r);
  return { ok: true, sha, message };
}

/** Changed files between two trees, with line counts. */
function diffFiles(r: Repo, baseTree: string, headTree: string): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const baseFlat = flattenTree(r, baseTree);
  const headFlat = flattenTree(r, headTree);
  const paths = new Set<string>([...baseFlat.keys(), ...headFlat.keys()]);
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const lineCount = (oid: string): number => {
    const obj = r.objects.get(oid);
    if (!obj) return 0;
    const text = obj.data.toString('utf8');
    if (text === '') return 0;
    return text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
  };
  for (const path of [...paths].sort()) {
    const b = baseFlat.get(path);
    const h = headFlat.get(path);
    if (b === h) continue;
    if (b === undefined && h !== undefined) {
      const adds = lineCount(h);
      out.push({ filename: path, status: 'added', additions: adds, deletions: 0, changes: adds });
    } else if (h === undefined && b !== undefined) {
      const dels = lineCount(b);
      out.push({ filename: path, status: 'removed', additions: 0, deletions: dels, changes: dels });
    } else if (b !== undefined && h !== undefined) {
      const adds = lineCount(h);
      const dels = lineCount(b);
      out.push({ filename: path, status: 'modified', additions: adds, deletions: dels, changes: adds + dels });
    }
  }
  return out;
}

// ------------------------------------------------------------------ git HTTP

const GIT_CAPS_V0_UPLOAD =
  'side-band-64k thin-pack ofs-delta shallow multi_ack symref=HEAD:refs/heads/main agent=forge2/1.0';
const GIT_CAPS_V0_RECEIVE =
  'report-status report-status-v2 side-band-64k delete-refs ofs-delta thin-pack agent=forge2/1.0';

function refsSorted(r: Repo): Array<[string, string]> {
  return [...r.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function peeledFor(r: Repo, ref: string, oid: string): string | null {
  const peeled = peelToCommit(r, oid);
  if (peeled === null || peeled === oid) return null;
  return peeled;
}

function v0Advertisement(r: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const caps = service === 'git-upload-pack' ? GIT_CAPS_V0_UPLOAD : GIT_CAPS_V0_RECEIVE;
  const entries = refsSorted(r);
  const defaultRef = `refs/heads/${r.defaultBranch}`;
  const headOid = r.refs.get(defaultRef) ?? ZERO_OID;
  parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
  if (entries.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    for (const [ref, oid] of entries) {
      // capabilities ride on the HEAD line only — later lines are plain
      // "<oid> <ref>", exactly as git emits them
      parts.push(pktLine(`${oid} ${ref}\n`));
      const peeled = peeledFor(r, ref, oid);
      if (peeled !== null) parts.push(pktLine(`${peeled} ${ref}^{}\n`));
    }
  }
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow\n'),
    pktLine('object-format=sha1\n'),
    pktLine('agent=forge2/1.0\n'),
    PKT_FLUSH,
  ]);
}

interface LsRefsLine {
  oid: string;
  ref: string;
  symref?: string;
  peeled?: string;
}

function lsRefsLines(r: Repo, opts: { unborn: boolean; peel: boolean; symrefs: boolean; prefix?: string }): Buffer {
  const chunks: Buffer[] = [];
  const headOid = r.refs.get(`refs/heads/${r.defaultBranch}`) ?? ZERO_OID;
  const isUnborn = headOid === ZERO_OID;
  // v2 ls-refs lines are "<oid> <ref> *(SP <attribute>)" with peeled/symref as
  // same-line attributes; unborn refs start with the literal word "unborn"
  const headLine = isUnborn && opts.unborn
    ? `unborn HEAD${opts.symrefs ? ` symref-target:refs/heads/${r.defaultBranch}` : ''}`
    : `${headOid} HEAD${opts.symrefs ? ` symref-target:refs/heads/${r.defaultBranch}` : ''}`;
  const entries: string[] = [headLine];
  for (const [ref, oid] of refsSorted(r)) {
    let line = `${oid} ${ref}`;
    if (opts.peel) {
      const peeled = peeledFor(r, ref, oid);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    entries.push(line);
  }
  for (const line of entries) {
    const refName = line.split(' ')[1] as string;
    if (opts.prefix && !refName.startsWith(opts.prefix)) continue;
    chunks.push(pktLine(`${line}\n`));
  }
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

const MAX_SIDEBAND = 65515; // 65520 - 5 bytes (length + band byte)

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += MAX_SIDEBAND) {
    const slice = pack.subarray(off, off + MAX_SIDEBAND);
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(pktLine(payload));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/**
 * Compute the object set for a fetch: everything reachable from `wants`, minus
 * anything reachable from `haves` (and their ancestors), plus shallow logic.
 */
interface FetchPlan {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
}

/** Objects reachable from `commits` without descending into other commits. */
function collectFromCommits(r: Repo, commits: Set<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...commits];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = r.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = commitOf(obj);
      queue.push(c.tree);
      for (const p of c.parents) if (commits.has(p)) queue.push(p);
    } else if (obj.type === 'tree') {
      for (const e of treeOf(obj)) if (e.mode !== '160000') queue.push(e.oid);
    } else if (obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})$/m.exec(obj.data.toString('utf8'));
      if (m && commits.has(m[1] as string)) queue.push(m[1] as string);
    }
  }
  return seen;
}

function fetchPlan(r: Repo, wants: string[], haves: string[], deepen: number | null, shallowSet: string[]): FetchPlan {
  const reachable = collectReachable(r, wants);
  if (haves.length > 0) {
    // never exclude history past a shallow boundary: the requester holds the
    // boundary commit itself, but not its ancestors
    const excluded = collectReachable(r, haves, new Set(shallowSet));
    for (const oid of excluded) reachable.delete(oid);
  }
  const shallow = new Set<string>(shallowSet);
  const unshallow: string[] = [];
  if (deepen !== null) {
    // BFS commit depth from the peeled wants (depth 0 = the want itself).
    // Commits with depth < deepen are included; the shallow boundary of this
    // fetch is the deepest included generation (depth == deepen - 1): those
    // commits are sent, their parents are not.
    const depthOf = new Map<string, number>();
    const queue: Array<[string, number]> = [];
    for (const w of wants) {
      const peeled = peelToCommit(r, w);
      if (peeled !== null) queue.push([peeled, 0]);
    }
    while (queue.length) {
      const [oid, d] = queue.shift() as [string, number];
      if (depthOf.has(oid)) continue;
      const obj = r.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      depthOf.set(oid, d);
      for (const p of commitOf(obj).parents) queue.push([p, d + 1]);
    }
    const included = new Set<string>();
    const newShallow = new Set<string>();
    for (const [oid, d] of depthOf) {
      if (d < deepen) included.add(oid);
      if (d === deepen - 1) newShallow.add(oid);
    }
    // depth-limited reachability: follow trees/blobs fully, but never descend
    // into a commit outside `included` (its tree/blobs belong to the boundary)
    const kept = collectFromCommits(r, included);
    for (const oid of [...reachable]) if (!kept.has(oid)) reachable.delete(oid);
    // the boundary moves: previously-shallow commits that are now included but
    // no longer at the edge are unshallow; the new edge is shallow
    for (const oid of shallow) {
      if (included.has(oid) && !newShallow.has(oid)) {
        unshallow.push(oid);
        shallow.delete(oid);
      }
    }
    for (const oid of newShallow) shallow.add(oid);
  }
  const objects: GitObject[] = [];
  for (const oid of reachable) {
    const obj = r.objects.get(oid);
    if (obj) objects.push(obj);
  }
  return { objects, shallow: [...shallow].sort(), unshallow: unshallow.sort() };
}

function fetchResponseV2(r: Repo, wants: string[], haves: string[], deepen: number | null, shallowSet: string[]): Buffer {
  const plan = fetchPlan(r, wants, haves, deepen, shallowSet);
  const chunks: Buffer[] = [];
  // Sections run header, content lines, flush — no delim after the header:
  // the client's section parser treats a delim as the end of the section.
  // acknowledgments
  chunks.push(pktLine('acknowledgments\n'));
  if (haves.length === 0) chunks.push(pktLine('NAK\n'));
  for (const oid of haves) chunks.push(pktLine(`ACK ${oid}\n`));
  chunks.push(PKT_FLUSH);
  // shallow-info
  chunks.push(pktLine('shallow-info\n'));
  for (const oid of plan.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
  chunks.push(PKT_FLUSH);
  // wanted-refs
  chunks.push(pktLine('wanted-refs\n'));
  for (const want of wants) {
    for (const [ref, oid] of refsSorted(r)) {
      if (oid === want) chunks.push(pktLine(`${want} ${ref}\n`));
    }
  }
  chunks.push(PKT_FLUSH);
  // packfile
  chunks.push(pktLine('packfile\n'));
  chunks.push(sidebandPack(writePack(plan.objects)));
  return Buffer.concat(chunks);
}

function fetchResponseV0(r: Repo, wants: string[], haves: string[], deepen: number | null, shallowSet: string[]): Buffer {
  const plan = fetchPlan(r, wants, haves, deepen, shallowSet);
  const chunks: Buffer[] = [];
  if (haves.length === 0) {
    chunks.push(pktLine('NAK\n'));
  } else {
    for (const oid of haves) chunks.push(pktLine(`ACK ${oid}\n`));
  }
  for (const oid of plan.shallow) chunks.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) chunks.push(pktLine(`unshallow ${oid}\n`));
  chunks.push(sidebandPack(writePack(plan.objects)));
  return Buffer.concat(chunks);
}

/** Parse v0 upload-pack request body (want/shallow/deepen sections then have/done). */
function parseV0FetchBody(buf: Buffer): { wants: string[]; haves: string[]; deepen: number | null; shallow: string[] } {
  const pkts = decodePktLines(buf);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let deepen: number | null = null;
  let phase = 0; // 0 = want section, 1 = have section
  for (const pkt of pkts) {
    if (pkt.kind === 'flush') { phase = 1; continue; }
    if (pkt.kind !== 'data') continue;
    const line = pkt.payload.toString('utf8').trim();
    const nul = line.indexOf('\0');
    const text = nul >= 0 ? line.slice(0, nul) : line;
    const [cmd, arg] = text.split(' ');
    if (phase === 0) {
      if (cmd === 'want' && arg) wants.push(arg);
      else if (cmd === 'shallow' && arg) shallow.push(arg);
      else if (cmd === 'deepen' && arg) deepen = parseInt(arg, 10);
      else if (cmd === 'filter') continue;
    } else {
      if (cmd === 'have' && arg) haves.push(arg);
      else if (cmd === 'done') break;
    }
  }
  return { wants, haves, deepen, shallow };
}

interface V2FetchRequest {
  wants: string[];
  haves: string[];
  deepen: number | null;
  shallow: string[];
  lsRefsOpts: { unborn: boolean; peel: boolean; symrefs: boolean; prefix?: string };
}

/** Parse a v2 request body: first pkt-line is the command, the rest are key/value args. */
function parseV2Body(buf: Buffer): { command: string; args: Record<string, string>; argsList: string[] } {
  const pkts = decodePktLines(buf);
  const dataLines = pkts.filter((p): p is { kind: 'data'; payload: Buffer } => p.kind === 'data').map((p) => p.payload.toString('utf8').trimEnd());
  if (dataLines.length === 0) throw new Error('empty v2 request');
  const first = dataLines[0] as string;
  const eq = first.indexOf('=');
  const command = eq >= 0 ? first.slice(eq + 1) : first;
  const args: Record<string, string> = {};
  const argsList: string[] = [];
  for (const line of dataLines.slice(1)) {
    const i = line.indexOf('=');
    if (i < 0) {
      // bare capability flags (peel, symrefs, unborn, thin-pack, ...)
      args[line] = '';
      argsList.push(line);
      continue;
    }
    const key = line.slice(0, i);
    const value = line.slice(i + 1);
    args[key] = value;
    argsList.push(line);
  }
  return { command, args, argsList };
}

function parseV2FetchArgs(body: Buffer): V2FetchRequest {
  const { argsList } = parseV2Body(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let deepen: number | null = null;
  let lsPrefix: string | undefined;
  const lsOpts = { unborn: false, peel: false, symrefs: false };
  // v2 fetch/ls-refs arguments are space-separated ("want <oid>", "deepen 1"),
  // not key=value — only the command line itself uses '='
  for (const line of argsList) {
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const value = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'want') wants.push(value);
    else if (key === 'have') haves.push(value);
    else if (key === 'shallow') shallow.push(value);
    else if (key === 'deepen') deepen = parseInt(value, 10);
    else if (key === 'ref-prefix') lsPrefix = value;
    else if (key === 'peel') lsOpts.peel = true;
    else if (key === 'symrefs') lsOpts.symrefs = true;
    else if (key === 'unborn') lsOpts.unborn = true;
  }
  return { wants, haves, deepen, shallow, lsRefsOpts: { ...lsOpts, prefix: lsPrefix } };
}

/**
 * Handle a receive-pack (push) body. Applies fast-forward refs, reports per-ref
 * status on sideband band 1, and returns the response Buffer. Pack objects are
 * stored in the repo regardless of ref outcome.
 */
function handleReceivePack(r: Repo, body: Buffer): Buffer {
  // Parse command pkt-lines one by one; the raw pack starts immediately after
  // the flush pkt-line (it is NOT pkt-line framed, so the body must never be
  // decoded as pkt-lines in one go).
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let offset = 0;
  let packStart = -1;
  while (offset + 4 <= body.length) {
    const head = body.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line header ${JSON.stringify(head)}`);
    const len = parseInt(head, 16);
    if (len === 0) { packStart = offset + 4; break; }
    if (len === 1 || len === 2) { offset += 4; continue; }
    if (len < 4 || offset + len > body.length) throw new Error('truncated pkt-line in push');
    const line = body.subarray(offset + 4, offset + len).toString('utf8').trimEnd();
    const nul = line.indexOf('\0');
    const text = nul >= 0 ? line.slice(0, nul) : line;
    const parts = text.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
    offset += len;
  }
  if (packStart < 0) throw new Error('push has no pack section');
  const packBytes = body.subarray(packStart);
  let stored = false;
  if (packBytes.length === 0) {
    // delete-only pushes carry no pack at all (git sends none there either)
    stored = true;
  } else {
    try {
      const objs = readPack(packBytes);
      for (const obj of objs) storeObject(r, obj);
      stored = true;
    } catch {
      stored = false;
    }
  }
  const reportLines: string[] = ['unpack ok'];
  for (const cmd of commands) {
    const current = r.refs.get(cmd.ref) ?? ZERO_OID;
    if (!stored) {
      reportLines.push(`ng ${cmd.ref} unpack failed`);
      continue;
    }
    if (current !== cmd.oldOid && cmd.oldOid !== ZERO_OID) {
      reportLines.push(`ng ${cmd.ref} non-fast-forward`);
      continue;
    }
    if (cmd.newOid === ZERO_OID) {
      r.refs.delete(cmd.ref);
      reportLines.push(`ok ${cmd.ref}`);
      continue;
    }
    if (current !== ZERO_OID && !isAncestor(r, current, cmd.newOid)) {
      reportLines.push(`ng ${cmd.ref} non-fast-forward`);
      continue;
    }
    r.refs.set(cmd.ref, cmd.newOid);
    reportLines.push(`ok ${cmd.ref}`);
  }
  refreshRepoBuf(r);
  const chunks: Buffer[] = [PKT_FLUSH];
  for (const line of reportLines) {
    const payload = Buffer.concat([Buffer.from([1]), Buffer.from(`${line}\n`, 'utf8')]);
    chunks.push(pktLine(payload));
  }
  chunks.push(PKT_FLUSH);
  return Buffer.concat(chunks);
}

// ------------------------------------------------------------------ HTTP helpers

function shopToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

function authOk(req: IncomingMessage): boolean {
  const expected = shopToken();
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length).trim();
  if (token === '') return false;
  if (expected === '') return true;
  return token === expected;
}

function sendBuf(res: ServerResponse, status: number, body: Buffer, extra: Record<string, string> = {}): void {
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, value: unknown, extra: Record<string, string> = {}): void {
  sendBuf(res, status, Buffer.from(JSON.stringify(value), 'utf8'), extra);
}

function sendErr(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJson(body: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (body.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(body.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asString(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}

function asBool(v: unknown, fallback = false): boolean {
  return typeof v === 'boolean' ? v : fallback;
}

function paginate<T>(items: T[], page: number, perPage: number): { page: T[]; hasNext: boolean; totalPages: number } {
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  return { page: items.slice(start, start + perPage), hasNext: page < totalPages, totalPages };
}

function linkHeader(base: string, page: number, perPage: number, totalPages: number, extra: string): string {
  const parts: string[] = [];
  const q = (p: number): string => `${base}?${extra ? `${extra}&` : ''}page=${p}&per_page=${perPage}`;
  if (page < totalPages) parts.push(`<${q(page + 1)}>; rel="next"`);
  parts.push(`<${q(totalPages)}>; rel="last"`);
  if (page > 1) parts.push(`<${q(1)}>; rel="first"`);
  return parts.join(', ');
}

function viewerJson(): Record<string, unknown> {
  return {
    login: VIEWER.login,
    id: VIEWER.id,
    node_id: b64url(`U:${VIEWER.login}`),
    type: 'User',
    name: VIEWER.name,
    email: VIEWER.email,
    avatar_url: `https://example.invalid/avatars/${VIEWER.login}`,
    html_url: `https://example.invalid/${VIEWER.login}`,
    url: '/api/v3/user',
    site_admin: false,
  };
}

function commitJson(r: Repo, oid: string): Record<string, unknown> | null {
  const obj = r.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  const c = commitOf(obj);
  const authorLine = (line: string): { name: string; email: string; date: string } => {
    const m = /^(.*) <(.*)> (\d+) \+0000$/.exec(line);
    if (!m) return { name: line, email: '', date: nextIso() };
    return { name: m[1] as string, email: m[2] as string, date: new Date(Number(m[3]) * 1000).toISOString() };
  };
  return {
    sha: oid,
    node_id: b64url(`C:${oid}`),
    commit: {
      message: c.message,
      author: authorLine(c.author),
      committer: authorLine(c.committer),
      tree: { sha: c.tree, url: `/api/v3/repos/${r.owner}/${r.name}/git/trees/${c.tree}` },
    },
    author: viewerUser(),
    committer: viewerUser(),
    parents: c.parents.map((p) => ({ sha: p, url: `/api/v3/repos/${r.owner}/${r.name}/commits/${p}` })),
    html_url: `https://example.invalid/${r.owner}/${r.name}/commit/${oid}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/commits/${oid}`,
  };
}

function listCommits(r: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    const obj = r.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    seen.add(oid);
    out.push(oid);
    for (const p of commitOf(obj).parents) queue.push(p);
  }
  return out;
}

// ------------------------------------------------------------------ REST v3

type Handler = (req: IncomingMessage, res: ServerResponse, url: URL, body: Buffer) => Promise<boolean>;

async function handleRest(req: IncomingMessage, res: ServerResponse, url: URL, body: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const path = url.pathname;
  if (!path.startsWith('/api/v3')) return false;
  if (!authOk(req)) { sendErr(res, 401, 'Requires authentication'); return true; }
  const origin = `http://${req.headers.host ?? '127.0.0.1'}`;

  const seg = path.split('/').filter((s) => s !== '');
  // seg[0]='api', seg[1]='v3'

  // GET /api/v3/  (root)
  if (method === 'GET' && seg.length === 2) {
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://example.invalid/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}',
      commit_search_url: '/api/v3/search/commits?q={query}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      followers_url: '/api/v3/user/followers',
      following_url: '/api/v3/user/following{/other_user}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: 'https://example.invalid/hub',
      issue_search_url: '/api/v3/search/issues?q={query}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/user/keys',
      label_search_url: '/api/v3/search/labels?q={query}',
      notifications_url: '/api/v3/notifications',
      organization_repositories_url: '/api/v3/orgs/{org}/repos',
      organization_url: '/api/v3/orgs/{org}',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}',
      current_user_repositories_url: '/api/v3/user/repos',
      starred_url: '/api/v3/user/starred{/owner}{/repo}',
      starred_gists_url: '/api/v3/gists/starred',
      user_url: '/api/v3/users/{user}',
      user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos',
      user_search_url: '/api/v3/search/users?q={query}',
    }, { 'x-oauth-scopes': 'repo, read:org', 'x-accepted-oauth-scopes': 'repo' });
    return true;
  }

  // GET /api/v3/meta (suite calls the versioned path)
  if (method === 'GET' && seg.length === 3 && seg[2] === 'meta') {
    sendJson(res, 200, { installed_version: SERVER_VERSION });
    return true;
  }

  // GET /api/v3/user
  if (method === 'GET' && seg.length === 3 && seg[2] === 'user') {
    sendJson(res, 200, viewerJson());
    return true;
  }

  // POST /api/v3/user/repos
  if (method === 'POST' && seg.length === 4 && seg[2] === 'user' && seg[3] === 'repos') {
    const parsed = parseJson(body);
    if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
    const input = isRecord(parsed.value) ? parsed.value : {};
    const name = asString(input.name);
    if (!name) { sendErr(res, 422, 'Validation Failed'); return true; }
    if (findRepo(VIEWER.login, name)) {
      sendJson(res, 422, { message: 'Validation Failed', errors: [{ resource: 'Repository', code: 'custom', field: 'name', message: 'name already exists on this account' }] });
      return true;
    }
    const r = createRepo(VIEWER.login, name, asBool(input.private), asString(input.description));
    sendBuf(res, 201, r.repoBuf);
    return true;
  }

  // GET /api/v3/user/repos
  if (method === 'GET' && seg.length === 4 && seg[2] === 'user' && seg[3] === 'repos') {
    const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
    const perPage = Math.max(1, parseInt(url.searchParams.get('per_page') ?? '30', 10) || 30);
    const mine = [...repos.values()].filter((r) => r.owner === VIEWER.login).sort((a, b) => a.id - b.id);
    const { page: items, totalPages } = paginate(mine, page, perPage);
    sendJson(res, 200, items.map((r) => repoJson(r)), {
      link: linkHeader(`${origin}/api/v3/user/repos`, page, perPage, totalPages, ''),
    });
    return true;
  }

  // /api/v3/repos/{owner}/{repo}/...
  if (seg.length >= 5 && seg[2] === 'repos') {
    const owner = decodeURIComponent(seg[3] as string);
    const repoName = decodeURIComponent(seg[4] as string);
    const r = findRepo(owner, repoName);
    const rest = seg.slice(5);

    // GET /repos/{o}/{r}
    if (method === 'GET' && rest.length === 0) {
      if (!r) { sendErr(res, 404, 'Not Found'); return true; }
      sendBuf(res, 200, r.repoBuf);
      return true;
    }
    // PATCH /repos/{o}/{r}
    if (method === 'PATCH' && rest.length === 0) {
      if (!r) { sendErr(res, 404, 'Not Found'); return true; }
      const parsed = parseJson(body);
      if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
      const input = isRecord(parsed.value) ? parsed.value : {};
      if (typeof input.description === 'string') r.description = input.description;
      if (typeof input.default_branch === 'string') r.defaultBranch = input.default_branch;
      refreshRepoBuf(r);
      sendBuf(res, 200, r.repoBuf);
      return true;
    }
    // DELETE /repos/{o}/{r}
    if (method === 'DELETE' && rest.length === 0) {
      if (!r) { sendErr(res, 404, 'Not Found'); return true; }
      repos.delete(repoKey(owner, repoName));
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return true;
    }
    if (!r) { sendErr(res, 404, 'Not Found'); return true; }

    // GET /branches
    if (method === 'GET' && rest.length === 1 && rest[0] === 'branches') {
      const list = [...r.refs.entries()]
        .filter(([ref]) => ref.startsWith('refs/heads/'))
        .map(([ref, oid]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: oid, url: `/api/v3/repos/${owner}/${repoName}/commits/${oid}` }, protected: false }));
      sendJson(res, 200, list);
      return true;
    }
    // GET /branches/{branch}
    if (method === 'GET' && rest.length === 2 && rest[0] === 'branches') {
      const branch = decodeURIComponent(rest[1] as string);
      const oid = r.refs.get(`refs/heads/${branch}`);
      if (!oid) { sendErr(res, 404, 'Branch not found'); return true; }
      sendJson(res, 200, { name: branch, commit: { sha: oid, url: `/api/v3/repos/${owner}/${repoName}/commits/${oid}` }, protected: false });
      return true;
    }
    // GET /commits[?sha=]
    if (method === 'GET' && rest.length === 1 && rest[0] === 'commits') {
      const shaParam = url.searchParams.get('sha');
      const tip = shaParam ? (r.refs.get(`refs/heads/${shaParam}`) ?? (HEX40.test(shaParam) ? shaParam : undefined)) : defaultTip(r);
      if (!tip) { sendJson(res, 200, []); return true; }
      const list = listCommits(r, tip).map((oid) => commitJson(r, oid)).filter((c): c is Record<string, unknown> => c !== null);
      sendJson(res, 200, list);
      return true;
    }
    // GET /git/refs  (list all refs)
    if (method === 'GET' && rest.length === 2 && rest[0] === 'git' && rest[1] === 'refs') {
      const list = [...r.refs.entries()].map(([ref, oid]) => ({
        ref, node_id: b64url(`RF:${ref}`), url: `/api/v3/repos/${owner}/${repoName}/git/refs/${encodeURIComponent(ref)}`,
        object: { sha: oid, type: 'commit', url: `/api/v3/repos/${owner}/${repoName}/git/commits/${oid}` },
      }));
      sendJson(res, 200, list);
      return true;
    }
    // GET /git/refs/heads/{branch}
    if (method === 'GET' && rest.length === 4 && rest[0] === 'git' && rest[1] === 'refs' && rest[2] === 'heads') {
      const branch = decodeURIComponent(rest[3] as string);
      const oid = r.refs.get(`refs/heads/${branch}`);
      if (!oid) { sendErr(res, 404, 'Not Found'); return true; }
      sendJson(res, 200, {
        ref: `refs/heads/${branch}`, node_id: b64url(`RF:refs/heads/${branch}`),
        url: `/api/v3/repos/${owner}/${repoName}/git/refs/heads/${branch}`,
        object: { sha: oid, type: 'commit', url: `/api/v3/repos/${owner}/${repoName}/git/commits/${oid}` },
      });
      return true;
    }
    // POST /git/refs
    if (method === 'POST' && rest.length === 2 && rest[0] === 'git' && rest[1] === 'refs') {
      const parsed = parseJson(body);
      if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const ref = asString(input.ref);
      const sha = asString(input.sha);
      if (!ref || !HEX40.test(sha)) { sendErr(res, 422, 'Validation Failed'); return true; }
      if (r.refs.has(ref)) { sendErr(res, 422, 'Reference already exists'); return true; }
      const target = r.objects.get(sha);
      if (!target) { sendErr(res, 422, 'Validation Failed'); return true; }
      r.refs.set(ref, sha);
      sendJson(res, 201, {
        ref, node_id: b64url(`RF:${ref}`), url: `/api/v3/repos/${owner}/${repoName}/git/refs/${encodeURIComponent(ref)}`,
        object: { sha, type: target.type, url: `/api/v3/repos/${owner}/${repoName}/git/commits/${sha}` },
      });
      return true;
    }
    // PATCH /git/refs/heads/{branch}
    if (method === 'PATCH' && rest.length === 4 && rest[0] === 'git' && rest[1] === 'refs' && rest[2] === 'heads') {
      const branch = decodeURIComponent(rest[3] as string);
      const oid = r.refs.get(`refs/heads/${branch}`);
      if (!oid) { sendErr(res, 404, 'Not Found'); return true; }
      const parsed = parseJson(body);
      if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const sha = asString(input.sha);
      if (!HEX40.test(sha) || !r.objects.has(sha)) { sendErr(res, 422, 'Validation Failed'); return true; }
      r.refs.set(`refs/heads/${branch}`, sha);
      sendJson(res, 200, {
        ref: `refs/heads/${branch}`, node_id: b64url(`RF:refs/heads/${branch}`),
        url: `/api/v3/repos/${owner}/${repoName}/git/refs/heads/${branch}`,
        object: { sha, type: 'commit', url: `/api/v3/repos/${owner}/${repoName}/git/commits/${sha}` },
      });
      return true;
    }
    // contents
    if (rest.length >= 1 && rest[0] === 'contents') {
      const relPath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      if (method === 'GET') {
        const tip = defaultTip(r);
        if (!tip) { sendErr(res, 404, 'Not Found'); return true; }
        const treeOid = commitTree(r, tip);
        if (!treeOid) { sendErr(res, 404, 'Not Found'); return true; }
        const segments = relPath === '' ? [] : relPath.split('/');
        if (segments.length === 0) {
          const entries = listDir(r, treeOid, []);
          if (!entries) { sendErr(res, 404, 'Not Found'); return true; }
          sendJson(res, 200, entries.map((e) => contentEntry(r, owner, repoName, '', e)));
          return true;
        }
        const blobOid = getBlobAt(r, treeOid, segments);
        if (blobOid !== null) {
          const obj = r.objects.get(blobOid) as GitObject;
          sendJson(res, 200, {
            name: segments[segments.length - 1], path: relPath, sha: blobOid, size: obj.data.length,
            type: 'file', encoding: 'base64', content: obj.data.toString('base64'),
            url: `/api/v3/repos/${owner}/${repoName}/contents/${encodeURIComponent(relPath)}`,
            html_url: `https://example.invalid/${owner}/${repoName}/blob/${r.defaultBranch}/${relPath}`,
          });
          return true;
        }
        const entries = listDir(r, treeOid, segments);
        if (entries !== null) {
          sendJson(res, 200, entries.map((e) => contentEntry(r, owner, repoName, relPath, e)));
          return true;
        }
        sendErr(res, 404, 'Not Found');
        return true;
      }
      if (method === 'PUT') {
        const parsed = parseJson(body);
        if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const message = asString(input.message, `Update ${relPath}`);
        const contentB64 = asString(input.content);
        if (contentB64 === '') { sendErr(res, 422, 'Validation Failed'); return true; }
        const branch = asString(input.branch, r.defaultBranch);
        let tip = r.refs.get(`refs/heads/${branch}`);
        let parents: string[] = [];
        let treeOid: string | null = null;
        if (!tip) {
          const defTip = defaultTip(r);
          if (defTip) {
            tip = defTip;
            r.refs.set(`refs/heads/${branch}`, tip);
            treeOid = commitTree(r, tip);
            parents = [tip];
          } else {
            // empty repository: this PUT creates the root commit
            treeOid = null;
            parents = [];
          }
        } else {
          treeOid = commitTree(r, tip);
          parents = [tip];
        }
        if (treeOid === undefined) { sendErr(res, 422, 'Validation Failed'); return true; }
        const segments = relPath.split('/');
        const existingOid = treeOid === null ? null : getBlobAt(r, treeOid, segments);
        const givenSha = asString(input.sha);
        if (existingOid !== null) {
          if (givenSha !== '' && givenSha !== existingOid) {
            sendJson(res, 409, { message: 'sha does not match' });
            return true;
          }
        } else if (givenSha !== '') {
          sendJson(res, 409, { message: 'sha does not match' });
          return true;
        }
        const blob = makeObject('blob', b64decodeLoose(contentB64));
        storeObject(r, blob);
        const newTree = setPath(r, treeOid, segments, blob.oid);
        const newCommit = makeServerCommit(r, newTree, parents, message);
        r.refs.set(`refs/heads/${branch}`, newCommit);
        refreshRepoBuf(r);
        sendJson(res, existingOid !== null ? 200 : 201, {
          content: {
            name: segments[segments.length - 1], path: relPath, sha: blob.oid, size: blob.data.length,
            type: 'file', encoding: 'base64', content: contentB64,
            url: `/api/v3/repos/${owner}/${repoName}/contents/${encodeURIComponent(relPath)}`,
          },
          commit: { sha: newCommit, message, url: `/api/v3/repos/${owner}/${repoName}/commits/${newCommit}` },
        });
        return true;
      }
      if (method === 'DELETE') {
        const parsed = parseJson(body);
        if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const message = asString(input.message, `Delete ${relPath}`);
        const branch = asString(input.branch, r.defaultBranch);
        const tip = r.refs.get(`refs/heads/${branch}`);
        if (!tip) { sendErr(res, 404, 'Not Found'); return true; }
        const treeOid = commitTree(r, tip);
        if (!treeOid) { sendErr(res, 404, 'Not Found'); return true; }
        const segments = relPath.split('/');
        const existingOid = getBlobAt(r, treeOid, segments);
        if (existingOid === null) { sendErr(res, 404, 'Not Found'); return true; }
        const givenSha = asString(input.sha);
        if (givenSha !== '' && givenSha !== existingOid) {
          sendJson(res, 409, { message: 'sha does not match' });
          return true;
        }
        const newTree = setPath(r, treeOid, segments, null);
        const newCommit = makeServerCommit(r, newTree, [tip], message);
        r.refs.set(`refs/heads/${branch}`, newCommit);
        refreshRepoBuf(r);
        sendJson(res, 200, { commit: { sha: newCommit, message, url: `/api/v3/repos/${owner}/${repoName}/commits/${newCommit}` } });
        return true;
      }
      return false;
    }
    // POST /labels
    if (method === 'POST' && rest.length === 1 && rest[0] === 'labels') {
      const parsed = parseJson(body);
      if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
      const input = isRecord(parsed.value) ? parsed.value : {};
      const name = asString(input.name);
      const color = asString(input.color, 'ededed').replace(/^#/, '');
      if (!name) { sendErr(res, 422, 'Validation Failed'); return true; }
      const existing = r.labels.get(name);
      if (existing) {
        sendJson(res, 201, { id: objSeq, name: existing.name, color: existing.color, description: '' });
        return true;
      }
      const label: Label = { name, color };
      r.labels.set(name, label);
      sendJson(res, 201, { id: objSeq, name, color, description: '' });
      return true;
    }
    // GET /labels
    if (method === 'GET' && rest.length === 1 && rest[0] === 'labels') {
      sendJson(res, 200, [...r.labels.values()].map((l) => ({ id: objSeq, name: l.name, color: l.color, description: '' })));
      return true;
    }
    // issues
    if (rest.length >= 1 && rest[0] === 'issues') {
      // GET /issues/{n}/comments  | POST /issues/{n}/comments
      if (rest.length === 3 && rest[2] === 'comments') {
        const n = parseInt(rest[1] as string, 10);
        const issue = r.issueByNum.get(n);
        if (!issue) { sendErr(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((c) => commentJson(r, issue, c)));
          return true;
        }
        if (method === 'POST') {
          const parsed = parseJson(body);
          if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
          const input = isRecord(parsed.value) ? parsed.value : {};
          const cBody = asString(input.body);
          if (!cBody) { sendErr(res, 422, 'Validation Failed'); return true; }
          const now = nextIso();
          const comment: Comment = { id: objSeq, gid: b64url(`C:${r.owner}/${r.name}:${issue.number}:${issue.comments.length + 1}`), body: cBody, user: VIEWER.login, createdAt: now, updatedAt: now };
          objSeq += 1;
          issue.comments.push(comment);
          issue.updatedAt = now;
          refreshIssueBuf(r, issue);
          sendJson(res, 201, commentJson(r, issue, comment));
          return true;
        }
        return false;
      }
      // GET /issues/{n} | PATCH /issues/{n}
      if (rest.length === 2) {
        const n = parseInt(rest[1] as string, 10);
        const issue = r.issueByNum.get(n);
        if (!issue) { sendErr(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          sendBuf(res, 200, issue.buf);
          return true;
        }
        if (method === 'PATCH') {
          const parsed = parseJson(body);
          if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
          const input = isRecord(parsed.value) ? parsed.value : {};
          if (typeof input.title === 'string') issue.title = input.title;
          if (typeof input.body === 'string') issue.body = input.body;
          if (input.state === 'closed' || input.state === 'open') {
            issue.state = input.state;
            issue.closedAt = input.state === 'closed' ? nextIso() : null;
          }
          issue.updatedAt = nextIso();
          refreshIssueBuf(r, issue);
          refreshRepoBuf(r);
          sendBuf(res, 200, issue.buf);
          return true;
        }
        return false;
      }
      // GET /issues (list)
      if (rest.length === 1 && method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        const sort = url.searchParams.get('sort') ?? 'created';
        const direction = url.searchParams.get('direction') ?? 'desc';
        const labelsParam = url.searchParams.get('labels');
        let list = [...r.issues];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        if (labelsParam) {
          const wanted = labelsParam.split(',');
          list = list.filter((i) => wanted.every((w) => i.labels.some((l) => l.name === w)));
        }
        list.sort((a, b) => {
          const ka = sort === 'updated' ? a.updatedAt : a.createdAt;
          const kb = sort === 'updated' ? b.updatedAt : b.createdAt;
          const cmp = ka < kb ? -1 : ka > kb ? 1 : a.number - b.number;
          return direction === 'asc' ? cmp : -cmp;
        });
        const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
        const perPage = Math.max(1, parseInt(url.searchParams.get('per_page') ?? '30', 10) || 30);
        const { page: items, totalPages } = paginate(list, page, perPage);
        sendJson(res, 200, items.map((i) => issueJson(i, owner, repoName)), {
          link: linkHeader(`${origin}/api/v3/repos/${owner}/${repoName}/issues`, page, perPage, totalPages, `state=${state}`),
        });
        return true;
      }
      // POST /issues
      if (rest.length === 1 && method === 'POST') {
        const parsed = parseJson(body);
        if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const title = asString(input.title);
        if (!title) { sendErr(res, 422, 'Validation Failed'); return true; }
        const labelNames = Array.isArray(input.labels) ? input.labels.map((l) => asString(l)) : [];
        const labels: Label[] = [];
        for (const name of labelNames) {
          const found = r.labels.get(name);
          if (!found) {
            sendJson(res, 422, { message: 'Validation Failed', errors: [{ resource: 'Issue', code: 'custom', field: 'labels', message: `Label does not exist: ${name}` }] });
            return true;
          }
          labels.push(found);
        }
        const issue = createIssue(r, title, asString(input.body), labels);
        sendBuf(res, 201, issue.buf);
        return true;
      }
      return false;
    }
    // pulls
    if (rest.length >= 1 && rest[0] === 'pulls') {
      // GET /pulls/{n}/files
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        const n = parseInt(rest[1] as string, 10);
        const p = r.pullByNum.get(n);
        if (!p) { sendErr(res, 404, 'Not Found'); return true; }
        const headSha = r.refs.get(`refs/heads/${p.headRef}`);
        const baseSha = r.refs.get(`refs/heads/${p.baseRef}`);
        if (!headSha || !baseSha) { sendJson(res, 200, []); return true; }
        const headTree = commitTree(r, headSha);
        const baseTree = commitTree(r, baseSha);
        if (!headTree || !baseTree) { sendJson(res, 200, []); return true; }
        const files = diffFiles(r, baseTree, headTree).map((f) => ({
          ...f,
          sha: ((): string => {
            const oid = getBlobAt(r, headTree, f.filename.split('/'));
            return oid ?? '';
          })(),
          patch: '',
          blob_url: `https://example.invalid/${owner}/${repoName}/blob/${headSha}/${f.filename}`,
          raw_url: `https://example.invalid/${owner}/${repoName}/raw/${headSha}/${f.filename}`,
          contents_url: `/api/v3/repos/${owner}/${repoName}/contents/${encodeURIComponent(f.filename)}`,
        }));
        sendJson(res, 200, files);
        return true;
      }
      // PUT /pulls/{n}/merge
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        const n = parseInt(rest[1] as string, 10);
        const p = r.pullByNum.get(n);
        if (!p) { sendErr(res, 404, 'Not Found'); return true; }
        if (p.state !== 'open') { sendJson(res, 405, { message: 'Pull Request is not mergeable' }); return true; }
        const result = mergePull(r, p);
        if (!result.ok) { sendJson(res, 405, { message: result.message ?? 'Merge conflict' }); return true; }
        sendJson(res, 200, { sha: result.sha, merged: true, message: result.message });
        return true;
      }
      // GET /pulls/{n} | PATCH /pulls/{n}
      if (rest.length === 2) {
        const n = parseInt(rest[1] as string, 10);
        const p = r.pullByNum.get(n);
        if (!p) { sendErr(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          sendJson(res, 200, pullJson(r, p));
          return true;
        }
        if (method === 'PATCH') {
          const parsed = parseJson(body);
          if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
          const input = isRecord(parsed.value) ? parsed.value : {};
          if (typeof input.title === 'string') p.title = input.title;
          if (typeof input.body === 'string') p.body = input.body;
          if (input.state === 'closed' || input.state === 'open') p.state = input.state;
          p.updatedAt = nextIso();
          sendJson(res, 200, pullJson(r, p));
          return true;
        }
        return false;
      }
      // GET /pulls (list)
      if (rest.length === 1 && method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        let list = [...r.pulls];
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.number - a.number);
        sendJson(res, 200, list.map((p) => pullJson(r, p)));
        return true;
      }
      // POST /pulls
      if (rest.length === 1 && method === 'POST') {
        const parsed = parseJson(body);
        if (!parsed.ok) { sendErr(res, 400, 'Problems parsing JSON'); return true; }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const title = asString(input.title);
        const headRaw = asString(input.head);
        const baseRaw = asString(input.base);
        const head = headRaw.includes(':') ? (headRaw.split(':').pop() as string) : headRaw;
        const base = baseRaw.includes(':') ? (baseRaw.split(':').pop() as string) : baseRaw;
        if (!title || !head || !base) { sendErr(res, 422, 'Validation Failed'); return true; }
        if (!r.refs.has(`refs/heads/${head}`) || !r.refs.has(`refs/heads/${base}`)) {
          sendJson(res, 422, { message: 'Validation Failed', errors: [{ resource: 'PullRequest', code: 'custom', field: 'head', message: 'Head branch does not exist' }] });
          return true;
        }
        for (const existing of r.pulls) {
          if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
            sendJson(res, 422, { message: 'Validation Failed', errors: [{ resource: 'PullRequest', code: 'custom', field: 'base', message: 'A pull request already exists for this branch' }] });
            return true;
          }
        }
        const p = createPull(r, title, asString(input.body), head, base);
        if (!p) { sendErr(res, 422, 'Validation Failed'); return true; }
        sendJson(res, 201, pullJson(r, p));
        return true;
      }
      return false;
    }
  }

  return false;
}

function contentEntry(r: Repo, owner: string, repoName: string, dir: string, e: TreeEntry): Record<string, unknown> {
  const path = dir === '' ? e.name : `${dir}/${e.name}`;
  const isDir = e.mode === '40000';
  const size = isDir ? 0 : (r.objects.get(e.oid)?.data.length ?? 0);
  return {
    name: e.name, path, sha: e.oid, size, type: isDir ? 'dir' : 'file',
    url: `/api/v3/repos/${owner}/${repoName}/contents/${encodeURIComponent(path)}`,
    html_url: `https://example.invalid/${owner}/${repoName}/${isDir ? 'tree' : 'blob'}/${r.defaultBranch}/${path}`,
  };
}

function commentJson(r: Repo, issue: Issue, c: Comment): Record<string, unknown> {
  return {
    id: c.id,
    node_id: c.gid,
    body: c.body,
    user: viewerUser(),
    created_at: c.createdAt,
    updated_at: c.updatedAt,
    html_url: `https://example.invalid/${r.owner}/${r.name}/issues/${issue.number}#issuecomment-${c.id}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/issues/comments/${c.id}`,
    issue_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${issue.number}`,
  };
}

// ------------------------------------------------------------------ GraphQL

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue } | { __var: string };

interface GqlField {
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  children: GqlField[] | null;
  fragmentType: string | null;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  varDefs: Record<string, { type: string; defaultValue?: GqlValue }>;
  fields: GqlField[];
}

class GqlParser {
  private pos = 0;
  private readonly src: string;
  constructor(src: string) {
    this.src = src;
  }

  private skipWs(): void {
    for (;;) {
      while (this.pos < this.src.length && /\s/.test(this.src[this.pos] as string)) this.pos += 1;
      if (this.src.startsWith('#', this.pos)) {
        while (this.pos < this.src.length && this.src[this.pos] !== '\n') this.pos += 1;
        continue;
      }
      if (this.src.startsWith(',', this.pos)) { this.pos += 1; continue; }
      break;
    }
  }
  private peek(): string {
    this.skipWs();
    return this.src[this.pos] ?? '';
  }
  private expect(ch: string): void {
    this.skipWs();
    if (this.src[this.pos] !== ch) throw new Error(`expected ${ch} at ${this.pos}`);
    this.pos += 1;
  }
  private readName(): string {
    this.skipWs();
    const start = this.pos;
    while (this.pos < this.src.length && /[_A-Za-z0-9]/.test(this.src[this.pos] as string)) this.pos += 1;
    if (this.pos === start) throw new Error(`expected name at ${this.pos}`);
    return this.src.slice(start, this.pos);
  }
  private readString(): string {
    this.skipWs();
    if (this.src[this.pos] !== '"') throw new Error(`expected string at ${this.pos}`);
    this.pos += 1;
    let out = '';
    for (;;) {
      const ch = this.src[this.pos] as string;
      if (ch === '"') { this.pos += 1; return out; }
      if (ch === '\\') {
        const esc = this.src[this.pos + 1] as string;
        const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/' };
        out += map[esc] ?? esc;
        this.pos += 2;
        continue;
      }
      if (ch === undefined) throw new Error('unterminated string');
      out += ch;
      this.pos += 1;
    }
  }
  private readNumber(): number {
    this.skipWs();
    const start = this.pos;
    while (this.pos < this.src.length && /[0-9eE+-.]/.test(this.src[this.pos] as string)) this.pos += 1;
    return Number(this.src.slice(start, this.pos));
  }
  private readValue(): GqlValue {
    this.skipWs();
    const ch = this.src[this.pos] as string;
    if (ch === '"') return this.readString();
    if (ch === '[') {
      this.pos += 1;
      const arr: GqlValue[] = [];
      while (this.peek() !== ']') arr.push(this.readValue());
      this.expect(']');
      return arr;
    }
    if (ch === '{') {
      this.pos += 1;
      const obj: { [key: string]: GqlValue } = {};
      while (this.peek() !== '}') {
        const key = this.readName();
        this.expect(':');
        obj[key] = this.readValue();
      }
      this.expect('}');
      return obj;
    }
    if (ch === '$') {
      this.pos += 1;
      return { __var: this.readName() };
    }
    if (ch === '-' || /[0-9]/.test(ch)) return this.readNumber();
    const word = this.readName();
    if (word === 'true') return true;
    if (word === 'false') return false;
    if (word === 'null') return null;
    return word; // enum value, kept as its name string
  }
  private readArgs(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    this.skipWs();
    if (this.src[this.pos] !== '(') return args;
    this.pos += 1;
    while (this.peek() !== ')') {
      const name = this.readName();
      this.expect(':');
      args[name] = this.readValue();
    }
    this.expect(')');
    return args;
  }
  private readSelectionSet(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}') {
      fields.push(this.readField());
    }
    this.expect('}');
    return fields;
  }
  private readField(): GqlField {
    this.skipWs();
    if (this.src.startsWith('...', this.pos)) {
      this.pos += 3;
      this.skipWs();
      let fragmentType: string | null = null;
      if (this.src.startsWith('on', this.pos) && !/[_A-Za-z0-9]/.test(this.src[this.pos + 2] as string)) {
        this.pos += 2;
        fragmentType = this.readName();
      }
      const children = this.peek() === '{' ? this.readSelectionSet() : [];
      return { name: '__fragment', alias: null, args: {}, children, fragmentType };
    }
    const first = this.readName();
    let alias: string | null = null;
    let name = first;
    this.skipWs();
    if (this.src[this.pos] === ':') {
      this.pos += 1;
      alias = first;
      name = this.readName();
    }
    const args = this.readArgs();
    const children = this.peek() === '{' ? this.readSelectionSet() : null;
    return { name, alias, args, children, fragmentType: null };
  }
  parse(): GqlOperation {
    this.skipWs();
    let kind: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    const varDefs: Record<string, { type: string; defaultValue?: GqlValue }> = {};
    if (this.src.startsWith('query', this.pos) || this.src.startsWith('mutation', this.pos)) {
      kind = this.src.startsWith('mutation', this.pos) ? 'mutation' : 'query';
      this.pos += kind.length;
      this.skipWs();
      if (/[_A-Za-z]/.test(this.peek())) name = this.readName();
      this.skipWs();
      if (this.src[this.pos] === '(') {
        this.pos += 1;
        while (this.peek() !== ')') {
          this.expect('$');
          const varName = this.readName();
          this.expect(':');
          const typeStart = this.pos;
          while (this.pos < this.src.length && !/[=),]/.test(this.src[this.pos] as string)) this.pos += 1;
          const type = this.src.slice(typeStart, this.pos).trim();
          let defaultValue: GqlValue | undefined;
          this.skipWs();
          if (this.src[this.pos] === '=') {
            this.pos += 1;
            defaultValue = this.readValue();
          }
          varDefs[varName] = { type, defaultValue };
        }
        this.expect(')');
      }
    }
    const fields = this.readSelectionSet();
    return { kind, name, varDefs, fields };
  }
}

function resolveVars(value: GqlValue, variables: Record<string, GqlValue>): GqlValue {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if ('__var' in value) {
      const v = variables[(value as { __var: string }).__var];
      return v === undefined ? null : v;
    }
    const out: { [key: string]: GqlValue } = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveVars(v, variables);
    return out;
  }
  if (Array.isArray(value)) return value.map((v) => resolveVars(v, variables));
  return value;
}

function gqlStr(v: GqlValue): string {
  return typeof v === 'string' ? v : '';
}
function gqlNum(v: GqlValue): number {
  return typeof v === 'number' ? v : 0;
}
function gqlBool(v: GqlValue): boolean {
  return v === true;
}
function gqlArr(v: GqlValue): GqlValue[] {
  return Array.isArray(v) ? v : [];
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', 'search'],
  Viewer: ['login', 'id', 'databaseId', 'name', 'email', 'avatarUrl'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  User: ['login', 'id', 'databaseId', 'name', 'email'],
  Ref: ['name'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'author', 'createdAt', 'updatedAt', 'closedAt', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'state', 'body', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'files'],
  PullRequestFile: ['path', 'additions', 'deletions', 'changeType'],
  PullRequestFileConnection: ['nodes', 'edges', 'totalCount', 'pageInfo'],
  PullRequestFileEdge: ['node', 'cursor'],
  IssueConnection: ['nodes', 'edges', 'totalCount', 'pageInfo'],
  IssueEdge: ['node', 'cursor'],
  PullRequestConnection: ['nodes', 'edges', 'totalCount', 'pageInfo'],
  PullRequestEdge: ['node', 'cursor'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  Label: ['id', 'name', 'color'],
  IssueComment: ['id', 'body', 'author', 'createdAt'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge', 'comment'],
  IssueCommentEdge: ['node', 'cursor'],
  SearchType: [],
  IssueState: [],
  PullRequestState: [],
};

function fieldTypeName(parentType: string, field: string): string {
  switch (`${parentType}.${field}`) {
    case 'Query.viewer': return 'Viewer';
    case 'Query.repository': return 'Repository';
    case 'Query.node': return 'Node';
    case 'Repository.owner': return 'User';
    case 'Repository.defaultBranchRef': return 'Ref';
    case 'Repository.issue': return 'Issue';
    case 'Repository.issues': return 'IssueConnection';
    case 'Repository.pullRequests': return 'PullRequestConnection';
    case 'Repository.pullRequest': return 'PullRequest';
    case 'Issue.author': return 'User';
    case 'Issue.labels': return 'Label';
    case 'Issue.comments': return 'IssueComment';
    case 'IssueConnection.nodes': return 'Issue';
    case 'IssueConnection.edges': return 'IssueEdge';
    case 'IssueConnection.pageInfo': return 'PageInfo';
    case 'IssueEdge.node': return 'Issue';
    case 'PullRequestConnection.nodes': return 'PullRequest';
    case 'PullRequestConnection.edges': return 'PullRequestEdge';
    case 'PullRequestConnection.pageInfo': return 'PageInfo';
    case 'PullRequestEdge.node': return 'PullRequest';
    case 'PullRequest.author': return 'User';
    case 'PullRequest.files': return 'PullRequestFileConnection';
    case 'PullRequestFileConnection.nodes': return 'PullRequestFile';
    case 'PullRequestFileConnection.edges': return 'PullRequestFileEdge';
    case 'PullRequestFileConnection.pageInfo': return 'PageInfo';
    case 'PullRequestFileEdge.node': return 'PullRequestFile';
    case 'Mutation.createIssue': return 'CreateIssuePayload';
    case 'Mutation.closeIssue': return 'CloseIssuePayload';
    case 'Mutation.createPullRequest': return 'CreatePullRequestPayload';
    case 'Mutation.mergePullRequest': return 'MergePullRequestPayload';
    case 'Mutation.addComment': return 'AddCommentPayload';
    case 'CreateIssuePayload.issue': return 'Issue';
    case 'CloseIssuePayload.issue': return 'Issue';
    case 'CreatePullRequestPayload.pullRequest': return 'PullRequest';
    case 'MergePullRequestPayload.pullRequest': return 'PullRequest';
    case 'AddCommentPayload.commentEdge': return 'IssueCommentEdge';
    case 'AddCommentPayload.comment': return 'IssueComment';
    case 'IssueCommentEdge.node': return 'IssueComment';
    default: return 'Scalar';
  }
}

interface GqlContext {
  errors: Array<{ message: string }>;
  variables: Record<string, GqlValue>;
}

function gqlIssueObj(r: Repo, i: Issue): Record<string, unknown> {
  return {
    __type: 'Issue',
    id: i.gid,
    number: i.number,
    title: i.title,
    state: i.state === 'open' ? 'OPEN' : 'CLOSED',
    body: i.body,
    author: { __type: 'User', login: VIEWER.login, id: VIEWER.id, databaseId: VIEWER.id, name: VIEWER.name, email: VIEWER.email },
    createdAt: i.createdAt,
    updatedAt: i.updatedAt,
    closedAt: i.closedAt,
    labels: i.labels.map((l) => ({ __type: 'Label', id: b64url(`L:${l.name}`), name: l.name, color: l.color })),
    comments: i.comments.map((c) => ({ __type: 'IssueComment', id: c.gid, body: c.body, author: { __type: 'User', login: c.user, id: VIEWER.id, databaseId: VIEWER.id, name: VIEWER.name, email: VIEWER.email }, createdAt: c.createdAt })),
  };
}

function gqlPullObj(r: Repo, p: Pull): Record<string, unknown> {
  const headSha = r.refs.get(`refs/heads/${p.headRef}`) ?? '';
  const baseSha = r.refs.get(`refs/heads/${p.baseRef}`) ?? '';
  const headTree = headSha ? commitTree(r, headSha) : null;
  const baseTree = baseSha ? commitTree(r, baseSha) : null;
  const fileNodes = headTree && baseTree ? diffFiles(r, baseTree, headTree).map((f) => ({ __type: 'PullRequestFile', path: f.filename, additions: f.additions, deletions: f.deletions, changeType: f.status.toUpperCase() })) : [];
  const files = {
    __type: 'PullRequestFileConnection',
    nodes: fileNodes,
    edges: fileNodes.map((n) => ({ __type: 'PullRequestFileEdge', node: n, cursor: null })),
    totalCount: fileNodes.length,
    pageInfo: { __type: 'PageInfo', hasNextPage: false, endCursor: null, hasPreviousPage: false, startCursor: null },
  };
  return {
    __type: 'PullRequest',
    id: p.gid,
    number: p.number,
    title: p.title,
    state: p.state === 'open' ? 'OPEN' : 'CLOSED',
    body: p.body,
    headRefName: p.headRef,
    baseRefName: p.baseRef,
    mergeable: mergeableOf(r, p),
    merged: p.merged,
    author: { __type: 'User', login: VIEWER.login, id: VIEWER.id, databaseId: VIEWER.id, name: VIEWER.name, email: VIEWER.email },
    files,
  };
}

function gqlRepoObj(r: Repo): Record<string, unknown> {
  return {
    __type: 'Repository',
    id: r.gid,
    databaseId: r.id,
    name: r.name,
    nameWithOwner: `${r.owner}/${r.name}`,
    owner: { __type: 'User', login: r.owner, id: VIEWER.id, databaseId: VIEWER.id, name: VIEWER.name, email: VIEWER.email },
    defaultBranchRef: { __type: 'Ref', name: r.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    __repo: r,
  };
}

function resolveField(ctx: GqlContext, parentType: string, parent: unknown, field: GqlField): unknown {
  const args: Record<string, GqlValue> = {};
  for (const [k, v] of Object.entries(field.args)) args[k] = resolveVars(v, ctx.variables);

  if (parentType === 'Query') {
    if (field.name === '__typename') return 'Query';
    if (field.name === '__type') {
      const typeName = gqlStr(args.name);
      if (typeName === 'SearchType') {
        return { __type: '__Type', name: 'SearchType', enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER'].map((v) => ({ name: v })) };
      }
      if (typeName === 'Issue' || typeName === 'PullRequest' || typeName === 'Repository') {
        const fields = GQL_TYPE_FIELDS[typeName] ?? [];
        return { __type: '__Type', name: typeName, fields: fields.map((f) => ({ __type: '__Field', name: f })) };
      }
      return null;
    }
    if (field.name === 'viewer') {
      return { __type: 'Viewer', login: VIEWER.login, id: VIEWER.id, databaseId: VIEWER.id, name: VIEWER.name, email: VIEWER.email, avatarUrl: `https://example.invalid/avatars/${VIEWER.login}` };
    }
    if (field.name === 'repository') {
      const r = findRepo(gqlStr(args.owner), gqlStr(args.name));
      return r ? gqlRepoObj(r) : null;
    }
    if (field.name === 'node') {
      const id = gqlStr(args.id);
      if (id === '') return null;
      // global ids are base64url of "X:..." — decode and route
      try {
        const decoded = Buffer.from(id, 'base64url').toString('utf8');
        if (decoded.startsWith('R:')) {
          const full = decoded.slice(2);
          const slash = full.indexOf('/');
          const r = findRepo(full.slice(0, slash), full.slice(slash + 1));
          return r ? gqlRepoObj(r) : null;
        }
      } catch { /* fall through */ }
      return null;
    }
    if (field.name === 'search') {
      return { __type: 'SearchResult', nodes: [], edges: [], totalCount: 0 };
    }
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Query".` });
    return undefined;
  }

  if (parentType === '__Type') {
    const rec = parent as Record<string, unknown>;
    if (field.name === 'name') return rec.name;
    if (field.name === 'fields') return rec.fields ?? null;
    if (field.name === 'enumValues') return rec.enumValues ?? null;
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "__Type".` });
    return undefined;
  }

  if (parentType === 'Repository') {
    const rec = parent as Record<string, unknown>;
    const r = rec.__repo as Repo;
    if (field.name === '__typename') return 'Repository';
    if (field.name === 'issue') {
      const issue = r.issueByNum.get(gqlNum(args.number));
      return issue ? gqlIssueObj(r, issue) : null;
    }
    if (field.name === 'issues') {
      const states = gqlArr(args.states).map((s) => (typeof s === 'string' ? s : ''));
      let list = [...r.issues];
      if (states.length > 0) list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      list.sort((a, b) => (a.number < b.number ? 1 : -1)); // CREATED_AT DESC
      const first = args.first !== undefined ? gqlNum(args.first) : list.length;
      const after = gqlStr(args.after);
      let start = 0;
      if (after) {
        try {
          const decoded = Buffer.from(after, 'base64url').toString('utf8');
          const m = /^c:(\d+)$/.exec(decoded);
          if (m) {
            const idx = list.findIndex((i) => i.number === Number(m[1]));
            if (idx >= 0) start = idx + 1;
          }
        } catch { /* ignore */ }
      }
      const slice = list.slice(start, start + first);
      const endCursor = slice.length > 0 ? Buffer.from(`c:${slice[slice.length - 1]?.number ?? 0}`, 'utf8').toString('base64url') : null;
      return {
        __type: 'IssueConnection',
        nodes: slice.map((i) => gqlIssueObj(r, i)),
        edges: slice.map((i) => ({ __type: 'IssueEdge', node: gqlIssueObj(r, i), cursor: Buffer.from(`c:${i.number}`, 'utf8').toString('base64url') })),
        totalCount: list.length,
        pageInfo: { __type: 'PageInfo', hasNextPage: start + slice.length < list.length, endCursor, hasPreviousPage: start > 0, startCursor: slice.length > 0 ? Buffer.from(`c:${slice[0]?.number ?? 0}`, 'utf8').toString('base64url') : null },
      };
    }
    if (field.name === 'pullRequest') {
      const p = r.pullByNum.get(gqlNum(args.number));
      return p ? gqlPullObj(r, p) : null;
    }
    if (field.name === 'pullRequests') {
      const states = gqlArr(args.states).map((s) => (typeof s === 'string' ? s : ''));
      let list = [...r.pulls];
      if (states.length > 0) list = list.filter((p) => states.includes(p.state === 'open' ? 'OPEN' : 'CLOSED'));
      list.sort((a, b) => b.number - a.number);
      const first = args.first !== undefined ? gqlNum(args.first) : list.length;
      const slice = list.slice(0, first);
      return {
        __type: 'PullRequestConnection',
        nodes: slice.map((p) => gqlPullObj(r, p)),
        edges: slice.map((p) => ({ __type: 'PullRequestEdge', node: gqlPullObj(r, p), cursor: Buffer.from(`c:${p.number}`, 'utf8').toString('base64url') })),
        totalCount: list.length,
        pageInfo: { __type: 'PageInfo', hasNextPage: slice.length < list.length, endCursor: slice.length > 0 ? Buffer.from(`c:${slice[slice.length - 1]?.number ?? 0}`, 'utf8').toString('base64url') : null, hasPreviousPage: false, startCursor: null },
      };
    }
    // scalar / object fields of the repository record itself
    if (field.name in rec && field.name !== '__repo') return rec[field.name];
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Repository".` });
    return undefined;
  }

  if (parentType === 'Mutation') {
    if (field.name === 'createIssue') {
      const input = isRecord(args.input) ? (args.input as Record<string, GqlValue>) : {};
      const repoId = gqlStr(input.repositoryId);
      let r: Repo | undefined;
      try {
        const decoded = Buffer.from(repoId, 'base64url').toString('utf8');
        if (decoded.startsWith('R:')) {
          const full = decoded.slice(2);
          const slash = full.indexOf('/');
          r = findRepo(full.slice(0, slash), full.slice(slash + 1));
        }
      } catch { /* ignore */ }
      if (!r) { ctx.errors.push({ message: 'Repository not found' }); return null; }
      const issue = createIssue(r, gqlStr(input.title), gqlStr(input.body), []);
      return { __type: 'CreateIssuePayload', issue: gqlIssueObj(r, issue) };
    }
    if (field.name === 'closeIssue') {
      const input = isRecord(args.input) ? (args.input as Record<string, GqlValue>) : {};
      const issueId = gqlStr(input.issueId);
      try {
        const decoded = Buffer.from(issueId, 'base64url').toString('utf8');
        const m = /^I:(.+)\/([^/]+):(\d+)$/.exec(decoded);
        if (m) {
          const r = findRepo(m[1] as string, m[2] as string);
          const issue = r?.issueByNum.get(Number(m[3]));
          if (issue) {
            issue.state = 'closed';
            issue.closedAt = nextIso();
            issue.updatedAt = nextIso();
            refreshIssueBuf(r as Repo, issue);
            return { __type: 'CloseIssuePayload', issue: gqlIssueObj(r as Repo, issue) };
          }
        }
      } catch { /* ignore */ }
      ctx.errors.push({ message: 'Issue not found' });
      return null;
    }
    if (field.name === 'createPullRequest') {
      const input = isRecord(args.input) ? (args.input as Record<string, GqlValue>) : {};
      const repoId = gqlStr(input.repositoryId);
      let r: Repo | undefined;
      try {
        const decoded = Buffer.from(repoId, 'base64url').toString('utf8');
        if (decoded.startsWith('R:')) {
          const full = decoded.slice(2);
          const slash = full.indexOf('/');
          r = findRepo(full.slice(0, slash), full.slice(slash + 1));
        }
      } catch { /* ignore */ }
      if (!r) { ctx.errors.push({ message: 'Repository not found' }); return null; }
      const head = gqlStr(input.headRefName);
      const base = gqlStr(input.baseRefName);
      if (!r.refs.has(`refs/heads/${head}`) || !r.refs.has(`refs/heads/${base}`)) {
        ctx.errors.push({ message: 'Head or base branch not found' });
        return null;
      }
      for (const existing of r.pulls) {
        if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
          ctx.errors.push({ message: 'A pull request already exists for this branch' });
          return null;
        }
      }
      const p = createPull(r, gqlStr(input.title), gqlStr(input.body), head, base);
      if (!p) { ctx.errors.push({ message: 'Could not create pull request' }); return null; }
      return { __type: 'CreatePullRequestPayload', pullRequest: gqlPullObj(r, p) };
    }
    if (field.name === 'mergePullRequest') {
      const input = isRecord(args.input) ? (args.input as Record<string, GqlValue>) : {};
      const prId = gqlStr(input.pullRequestId);
      try {
        const decoded = Buffer.from(prId, 'base64url').toString('utf8');
        const m = /^PR:(.+)\/([^/]+):(\d+)$/.exec(decoded);
        if (m) {
          const r = findRepo(m[1] as string, m[2] as string);
          const p = r?.pullByNum.get(Number(m[3]));
          if (p && r) {
            if (p.state !== 'open') { ctx.errors.push({ message: 'Pull request is not open' }); return null; }
            const result = mergePull(r, p);
            if (!result.ok) { ctx.errors.push({ message: result.message ?? 'Merge conflict' }); return null; }
            return { __type: 'MergePullRequestPayload', pullRequest: gqlPullObj(r, p) };
          }
        }
      } catch { /* ignore */ }
      ctx.errors.push({ message: 'Pull request not found' });
      return null;
    }
    if (field.name === 'addComment') {
      const input = isRecord(args.input) ? (args.input as Record<string, GqlValue>) : {};
      const subjectId = gqlStr(input.subjectId);
      try {
        const decoded = Buffer.from(subjectId, 'base64url').toString('utf8');
        const m = /^I:(.+)\/([^/]+):(\d+)$/.exec(decoded);
        if (m) {
          const r = findRepo(m[1] as string, m[2] as string);
          const issue = r?.issueByNum.get(Number(m[3]));
          if (issue && r) {
            const now = nextIso();
            const comment: Comment = { id: objSeq, gid: b64url(`C:${r.owner}/${r.name}:${issue.number}:${issue.comments.length + 1}`), body: gqlStr(input.body), user: VIEWER.login, createdAt: now, updatedAt: now };
            objSeq += 1;
            issue.comments.push(comment);
            issue.updatedAt = now;
            refreshIssueBuf(r, issue);
            const commentObj = { __type: 'IssueComment', id: comment.gid, body: comment.body, author: { __type: 'User', login: VIEWER.login, id: VIEWER.id, databaseId: VIEWER.id, name: VIEWER.name, email: VIEWER.email }, createdAt: now };
            return { __type: 'AddCommentPayload', commentEdge: { __type: 'IssueCommentEdge', node: commentObj, cursor: null }, comment: commentObj };
          }
        }
      } catch { /* ignore */ }
      ctx.errors.push({ message: 'Subject not found' });
      return null;
    }
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Mutation".` });
    return undefined;
  }

  // generic scalar / object field resolution
  if (parent !== null && typeof parent === 'object') {
    const rec = parent as Record<string, unknown>;
    if (field.name === '__typename') return rec.__type ?? parentType;
    if (field.name in rec) return rec[field.name];
  }
  ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${parentType}".` });
  return undefined;
}

function executeFields(ctx: GqlContext, parentType: string, parent: unknown, fields: GqlField[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    if (field.name === '__fragment') {
      if (field.fragmentType !== null && field.fragmentType !== parentType) continue;
      const nested = executeFields(ctx, parentType, parent, field.children ?? []);
      Object.assign(out, nested);
      continue;
    }
    const value = resolveField(ctx, parentType, parent, field);
    const key = field.alias ?? field.name;
    if (value === undefined) {
      out[key] = null;
      continue;
    }
    if (field.children !== null && value !== null && typeof value === 'object') {
      // the runtime __type of the value wins (e.g. node(id:) fragments on the
      // concrete type); fall back to the static schema mapping
      const runtimeType = (value as Record<string, unknown>).__type;
      const childType = typeof runtimeType === 'string' ? runtimeType : fieldTypeName(parentType, field.name);
      if (Array.isArray(value)) {
        out[key] = value.map((v) => {
          if (v !== null && typeof v === 'object') {
            const vt = (v as Record<string, unknown>).__type;
            return executeFields(ctx, typeof vt === 'string' ? vt : childType, v, field.children as GqlField[]);
          }
          return v;
        });
      } else {
        out[key] = executeFields(ctx, childType, value, field.children);
      }
    } else {
      out[key] = value;
    }
  }
  return out;
}

function executeGql(doc: unknown, variables: Record<string, GqlValue>): { data: Record<string, unknown> | null; errors?: Array<{ message: string }> } {
  const ctx: GqlContext = { errors: [], variables };
  let op: GqlOperation;
  try {
    op = new GqlParser(typeof doc === 'string' ? doc : '').parse();
  } catch (e) {
    return { data: null, errors: [{ message: `Syntax Error: ${(e as Error).message}` }] };
  }
  // validate top-level fields exist on the root type
  const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
  const known = new Set([...(GQL_TYPE_FIELDS[rootType] ?? []), '__typename', '__type']);
  let hasUnknown = false;
  for (const f of op.fields) {
    if (f.name === '__fragment') continue;
    if (!known.has(f.name)) {
      ctx.errors.push({ message: `Cannot query field "${f.name}" on type "${rootType}".` });
      hasUnknown = true;
    }
  }
  if (hasUnknown) return { data: null, errors: ctx.errors };
  const data = executeFields(ctx, rootType, null, op.fields);
  if (ctx.errors.length > 0) return { data: null, errors: ctx.errors };
  return { data };
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<boolean> {
  if (!authOk(req)) { sendErr(res, 401, 'Requires authentication'); return true; }
  const parsed = parseJson(body);
  if (!parsed.ok) {
    sendJson(res, 400, { data: null, errors: [{ message: 'Problems parsing JSON' }] });
    return true;
  }
  const payload = parsed.value;
  const runOne = (doc: unknown): Record<string, unknown> => {
    if (!isRecord(doc) || typeof doc.query !== 'string') {
      return { data: null, errors: [{ message: 'Must provide query string.' }] };
    }
    const variables = isRecord(doc.variables) ? (doc.variables as Record<string, GqlValue>) : {};
    const result = executeGql(doc.query, variables);
    return result.errors ? { data: result.data, errors: result.errors } : { data: result.data };
  };
  if (Array.isArray(payload)) {
    sendJson(res, 200, payload.map(runOne));
    return true;
  }
  sendJson(res, 200, runOne(payload));
  return true;
}

// ------------------------------------------------------------------ MCP

const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
      additionalProperties: false,
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
      additionalProperties: false,
    },
  },
];

const TOOLS_LIST_CACHED = { tools: MCP_TOOLS };

function pickArg(args: Record<string, unknown>, names: string[]): unknown {
  for (const n of names) {
    const v = args[n];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

function mcpToolResult(id: unknown, value: unknown): Record<string, unknown> {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    result: {
      content: [{ type: 'text', text }],
      structuredContent: typeof value === 'object' && value !== null ? value : { result: value },
      isError: false,
    },
  };
}

function mcpToolError(id: unknown, message: string): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: id ?? null,
    result: {
      content: [{ type: 'text', text: `Error: ${message}` }],
      isError: true,
    },
  };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<boolean> {
  if (!authOk(req)) { sendErr(res, 401, 'Requires authentication'); return true; }
  const mirror: Record<string, string> = {};
  const mcpMethod = req.headers['mcp-method'];
  const mcpName = req.headers['mcp-name'];
  if (typeof mcpMethod === 'string') mirror['mcp-method'] = mcpMethod;
  if (typeof mcpName === 'string') mirror['mcp-name'] = mcpName;
  const sendRpc = (status: number, value: unknown): void => {
    res.writeHead(status, { 'content-type': JSON_TYPE, 'x-github-request-id': nextRequestId(), ...mirror });
    res.end(JSON.stringify(value));
  };
  if (body.length === 0) {
    sendRpc(400, mcpError(null, -32700, 'Parse error'));
    return true;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    sendRpc(400, mcpError(null, -32700, 'Parse error'));
    return true;
  }
  if (!isRecord(payload) || typeof payload.method !== 'string') {
    sendRpc(400, mcpError(null, -32600, 'Invalid Request'));
    return true;
  }
  const id = payload.id ?? null;
  const method = payload.method as string;
  const params = isRecord(payload.params) ? payload.params : {};

  if (method === 'notifications/initialized') {
    res.writeHead(202, { 'x-github-request-id': nextRequestId(), ...mirror });
    res.end();
    return true;
  }

  if (method === 'server/discover') {
    const serverInfo = { name: SERVER_NAME, version: SERVER_VERSION };
    sendRpc(200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2026-07-28',
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
        capabilities: { tools: {} },
        serverInfo,
      },
      _meta: {
        'io.modelcontextprotocol/serverInfo': serverInfo,
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      },
    });
    return true;
  }

  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2026-07-28';
    const serverInfo = { name: SERVER_NAME, version: SERVER_VERSION };
    sendRpc(200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: requested,
        capabilities: { tools: {} },
        serverInfo,
      },
      _meta: {
        'io.modelcontextprotocol/serverInfo': serverInfo,
        'io.modelcontextprotocol/protocolVersion': requested,
      },
    });
    return true;
  }

  if (method === 'ping') {
    sendRpc(200, { jsonrpc: '2.0', id, result: {} });
    return true;
  }

  if (method === 'tools/list') {
    sendRpc(200, { jsonrpc: '2.0', id, result: TOOLS_LIST_CACHED });
    return true;
  }

  if (method === 'tools/call') {
    const name = asString(params.name);
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (!tool) { sendRpc(200, mcpError(id, -32602, `Unknown tool: ${name}`)); return true; }
    const required = (tool.inputSchema.required as string[]) ?? [];
    for (const reqProp of required) {
      const synonyms: Record<string, string[]> = {
        owner: ['owner', 'owner_login', 'ownerLogin', 'login'],
        repo: ['repo', 'repo_name', 'repoName', 'repository', 'name'],
        name: ['name', 'repo', 'repo_name'],
        pull_number: ['pull_number', 'pullNumber', 'number', 'pull_request_number'],
      };
      const value = pickArg(args, synonyms[reqProp] ?? [reqProp]);
      if (value === undefined) { sendRpc(200, mcpToolError(id, `Missing required argument: ${reqProp}`)); return true; }
    }
    try {
      const owner = asString(pickArg(args, ['owner', 'owner_login', 'ownerLogin', 'login']));
      const repoName = asString(pickArg(args, ['repo', 'repo_name', 'repoName', 'repository']));
      if (name === 'create_repo') {
        const repoLabel = asString(pickArg(args, ['name', 'repo', 'repo_name']));
        if (findRepo(VIEWER.login, repoLabel)) { sendRpc(200, mcpToolError(id, 'Repository already exists')); return true; }
        const r = createRepo(VIEWER.login, repoLabel, asBool(args.private), asString(args.description));
        sendRpc(200, mcpToolResult(id, repoJson(r)));
        return true;
      }
      const r = findRepo(owner, repoName);
      if (!r) { sendRpc(200, mcpToolError(id, 'Repository not found')); return true; }
      if (name === 'get_repo') {
        sendRpc(200, mcpToolResult(id, repoJson(r)));
        return true;
      }
      if (name === 'create_issue') {
        const issue = createIssue(r, asString(args.title), asString(args.body), []);
        sendRpc(200, mcpToolResult(id, issueJson(issue, r.owner, r.name)));
        return true;
      }
      if (name === 'list_issues') {
        const state = asString(args.state, 'open');
        let list = [...r.issues];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        sendRpc(200, mcpToolResult(id, list.map((i) => issueJson(i, r.owner, r.name))));
        return true;
      }
      if (name === 'create_pull_request') {
        const head = asString(args.head);
        const base = asString(args.base);
        if (!r.refs.has(`refs/heads/${head}`) || !r.refs.has(`refs/heads/${base}`)) {
          sendRpc(200, mcpToolError(id, 'Head or base branch not found'));
          return true;
        }
        for (const existing of r.pulls) {
          if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
            sendRpc(200, mcpToolError(id, 'A pull request already exists for this branch'));
            return true;
          }
        }
        const p = createPull(r, asString(args.title), asString(args.body), head, base);
        if (!p) { sendRpc(200, mcpToolError(id, 'Could not create pull request')); return true; }
        sendRpc(200, mcpToolResult(id, pullJson(r, p)));
        return true;
      }
      if (name === 'merge_pull_request') {
        const n = Number(pickArg(args, ['pull_number', 'pullNumber', 'number', 'pull_request_number']));
        const p = r.pullByNum.get(n);
        if (!p) { sendRpc(200, mcpToolError(id, 'Pull request not found')); return true; }
        if (p.state !== 'open') { sendRpc(200, mcpToolError(id, 'Pull request is not open')); return true; }
        const result = mergePull(r, p);
        if (!result.ok) { sendRpc(200, mcpToolError(id, result.message ?? 'Merge conflict')); return true; }
        sendRpc(200, mcpToolResult(id, { sha: result.sha, merged: true, message: result.message }));
        return true;
      }
      sendRpc(200, mcpError(id, -32602, `Unknown tool: ${name}`));
      return true;
    } catch (e) {
      sendRpc(200, mcpToolError(id, (e as Error).message));
      return true;
    }
  }

  sendRpc(200, mcpError(id, -32601, `Method not found: ${method}`));
  return true;
}

// ------------------------------------------------------------------ git HTTP dispatch

function gitContentType(service: 'git-upload-pack' | 'git-receive-pack'): string {
  return `application/x-${service}-advertisement`;
}

async function handleGit(req: IncomingMessage, res: ServerResponse, url: URL, body: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const m = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(url.pathname);
  if (!m) return false;
  const owner = decodeURIComponent(m[1] as string);
  const repoName = decodeURIComponent(m[2] as string);
  const action = m[3] as string;
  const r = findRepo(owner, repoName);
  if (!r) { sendErr(res, 404, 'Not Found'); return true; }

  try {
    if (method === 'GET' && action === 'info/refs') {
      const service = url.searchParams.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendErr(res, 400, 'Missing service parameter');
        return true;
      }
      const wantsV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
      const adv = wantsV2 ? v2Advertisement() : v0Advertisement(r, service);
      res.writeHead(200, {
        'content-type': gitContentType(service),
        'x-github-request-id': nextRequestId(),
        'cache-control': 'no-cache',
      });
      res.end(adv);
      return true;
    }
    if (method === 'POST' && action === 'git-upload-pack') {
      const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2' || body.subarray(4, 12).toString('ascii').startsWith('command=');
      if (isV2) {
        const { command } = parseV2Body(body);
        if (command === 'ls-refs') {
          const { argsList } = parseV2Body(body);
          const opts = { unborn: false, peel: false, symrefs: false, prefix: undefined as string | undefined };
          for (const line of argsList) {
            if (line === 'peel') opts.peel = true;
            else if (line === 'symrefs') opts.symrefs = true;
            else if (line === 'unborn') opts.unborn = true;
            else if (line.startsWith('ref-prefix ')) opts.prefix = line.slice('ref-prefix '.length);
          }
          const out = lsRefsLines(r, opts);
          res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': nextRequestId(), 'cache-control': 'no-cache' });
          res.end(out);
          return true;
        }
        if (command === 'fetch') {
          const parsed = parseV2FetchArgs(body);
          const out = fetchResponseV2(r, parsed.wants, parsed.haves, parsed.deepen, parsed.shallow);
          res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': nextRequestId(), 'cache-control': 'no-cache' });
          res.end(out);
          return true;
        }
        sendErr(res, 400, `Unsupported v2 command: ${command}`);
        return true;
      }
      const parsed = parseV0FetchBody(body);
      const out = fetchResponseV0(r, parsed.wants, parsed.haves, parsed.deepen, parsed.shallow);
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': nextRequestId(), 'cache-control': 'no-cache' });
      res.end(out);
      return true;
    }
    if (method === 'POST' && action === 'git-receive-pack') {
      const out = handleReceivePack(r, body);
      res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'x-github-request-id': nextRequestId(), 'cache-control': 'no-cache' });
      res.end(out);
      return true;
    }
  } catch (e) {
    sendErr(res, 400, (e as Error).message);
    return true;
  }
  sendErr(res, 405, 'Method Not Allowed');
  return true;
}

// ------------------------------------------------------------------ server

export function createApp(): Server {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const body = req.method === 'GET' || req.method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
      const path = url.pathname;

      if (path === '/healthz') {
        sendJson(res, 200, { ok: true });
        return;
      }
      if (path === '/meta') {
        sendJson(res, 200, { installed_version: SERVER_VERSION });
        return;
      }
      if (path === '/api/graphql' && req.method === 'POST') {
        await handleGraphql(req, res, body);
        return;
      }
      if (path === '/mcp' && req.method === 'POST') {
        await handleMcp(req, res, body);
        return;
      }
      if (await handleGit(req, res, url, body)) return;
      if (path.startsWith('/api/v3')) {
        if (await handleRest(req, res, url, body)) return;
      }
      sendErr(res, 404, 'Not Found');
    } catch (e) {
      if (!res.headersSent) sendErr(res, 500, (e as Error).message);
      else res.end();
    }
  });
  server.keepAliveTimeout = 5000;
  return server;
}

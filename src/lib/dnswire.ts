// Minimal DNS wire-format client over TCP, used to query authoritative
// nameservers directly (SOA serial, AA flag) — something DoH cannot do.
import { TcpConn } from "./tcp";

export interface DirectAnswer {
  rcode: number;
  aa: boolean;
  soaSerial?: number;
  answerCount: number;
}

function encodeName(name: string): number[] {
  const out: number[] = [];
  for (const label of name.replace(/\.$/, "").split(".")) {
    const b = new TextEncoder().encode(label);
    out.push(b.length, ...b);
  }
  out.push(0);
  return out;
}

export function buildQuery(name: string, qtype: number, id = Math.floor(Math.random() * 65535)): Uint8Array {
  const q = [
    id >> 8, id & 255,
    0x00, 0x00, // flags: standard query, RD=0
    0, 1, 0, 0, 0, 0, 0, 0, // QD=1
    ...encodeName(name),
    qtype >> 8, qtype & 255,
    0, 1, // IN
  ];
  const out = new Uint8Array(q.length + 2);
  out[0] = q.length >> 8;
  out[1] = q.length & 255;
  out.set(q, 2);
  return out;
}

/** Skip a (possibly compressed) name; returns offset after it. */
function skipName(b: Uint8Array, off: number): number {
  while (off < b.length) {
    const len = b[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;
    off += len + 1;
  }
  throw new Error("bad name");
}

export function parseResponse(b: Uint8Array, qtype: number): DirectAnswer {
  if (b.length < 12) throw new Error("short DNS response");
  const flags = (b[2] << 8) | b[3];
  const qd = (b[4] << 8) | b[5];
  const an = (b[6] << 8) | b[7];
  const res: DirectAnswer = { rcode: flags & 0x0f, aa: !!(flags & 0x0400), answerCount: an };
  let off = 12;
  for (let i = 0; i < qd; i++) off = skipName(b, off) + 4;
  for (let i = 0; i < an; i++) {
    off = skipName(b, off);
    const type = (b[off] << 8) | b[off + 1];
    const rdlen = (b[off + 8] << 8) | b[off + 9];
    const rd = off + 10;
    if (type === qtype && type === 6) {
      let p = skipName(b, rd); // mname
      p = skipName(b, p); // rname
      res.soaSerial = ((b[p] << 24) >>> 0) + (b[p + 1] << 16) + (b[p + 2] << 8) + b[p + 3];
    }
    off = rd + rdlen;
  }
  return res;
}

export async function queryDirect(serverIp: string, name: string, qtype: number, timeoutMs = 5000, port = 53): Promise<DirectAnswer> {
  const conn = await TcpConn.open(serverIp, port, timeoutMs);
  try {
    await conn.write(buildQuery(name, qtype));
    const lenB = await conn.readExact(2);
    if (!lenB) throw new Error("no response");
    const body = await conn.readExact((lenB[0] << 8) | lenB[1]);
    if (!body) throw new Error("truncated response");
    return parseResponse(body, qtype);
  } finally {
    conn.close();
  }
}

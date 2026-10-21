// Hand-rolled TLS ClientHello so we can see what the server actually sends:
// with TLS 1.2 the Certificate message travels in clear text, which gives us the
// exact chain (incl. a missing intermediate) — information `fetch` never exposes.
import { TcpConn, socketError } from "./tcp";

export const TLS10 = 0x0301, TLS11 = 0x0302, TLS12 = 0x0303, TLS13 = 0x0304;

export const VERSION_NAME: Record<number, string> = {
  [TLS10]: "TLS 1.0", [TLS11]: "TLS 1.1", [TLS12]: "TLS 1.2", [TLS13]: "TLS 1.3",
};

const ALERTS: Record<number, string> = {
  0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
  42: "bad_certificate", 47: "illegal_parameter", 50: "decode_error", 70: "protocol_version",
  71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
  109: "missing_extension", 112: "unrecognized_name",
};

const CIPHERS_12 = [
  0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014,
  0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
];
const CIPHERS_13 = [0x1301, 0x1302, 0x1303];

export const CIPHER_NAME: Record<number, string> = {
  0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256",
  0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
  0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384", 0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
  0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0xcca8: "ECDHE-RSA-CHACHA20-POLY1305",
  0xc009: "ECDHE-ECDSA-AES128-SHA", 0xc013: "ECDHE-RSA-AES128-SHA",
  0xc00a: "ECDHE-ECDSA-AES256-SHA", 0xc014: "ECDHE-RSA-AES256-SHA",
  0x009c: "AES128-GCM-SHA256", 0x009d: "AES256-GCM-SHA384",
  0x002f: "AES128-SHA", 0x0035: "AES256-SHA", 0x000a: "DES-CBC3-SHA",
};

const u16 = (n: number) => [n >> 8, n & 255];
const u24 = (n: number) => [n >> 16, (n >> 8) & 255, n & 255];
const vec8 = (b: number[]) => [b.length, ...b];
const vec16 = (b: number[]) => [...u16(b.length), ...b];
const ext = (type: number, body: number[]) => [...u16(type), ...vec16(body)];
const rand = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)));

export function buildClientHello(sni: string, version: number): Uint8Array {
  const legacyVersion = Math.min(version, TLS12);
  const ciphers = version === TLS13 ? [...CIPHERS_13, ...CIPHERS_12] : CIPHERS_12;
  const host = Array.from(new TextEncoder().encode(sni));

  const exts: number[] = [
    ...ext(0x0000, vec16([0x00, ...vec16(host)])), // server_name
    ...ext(0x000a, vec16([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18])), // supported_groups
    ...ext(0x000b, vec8([0x00])), // ec_point_formats
    ...ext(0x000d, vec16([ // signature_algorithms
      0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
      0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
    ])),
    ...ext(0x0005, [0x01, 0x00, 0x00, 0x00, 0x00]), // status_request (OCSP)
    ...ext(0x0017, []), // extended_master_secret
    ...ext(0xff01, [0x00]), // renegotiation_info
  ];
  if (version === TLS13) {
    exts.push(
      ...ext(0x002b, vec8([0x03, 0x04])), // supported_versions: 1.3 only
      ...ext(0x002d, vec8([0x01])), // psk_key_exchange_modes
      ...ext(0x0033, vec16([0x00, 0x1d, ...vec16(rand(32))])), // key_share x25519
    );
  }

  const hello = [
    ...u16(legacyVersion),
    ...rand(32),
    ...vec8(rand(32)), // session id
    ...vec16(ciphers.flatMap(u16)),
    ...vec8([0x00]), // null compression
    ...vec16(exts),
  ];
  const hs = [0x01, ...u24(hello.length), ...hello];
  return new Uint8Array([0x16, 0x03, 0x01, ...u16(hs.length), ...hs]);
}

export interface HandshakeResult {
  /** server accepted and answered with a ServerHello */
  ok: boolean;
  version?: number;
  cipher?: number;
  certs: Uint8Array[];
  ocspStapled: boolean;
  alert?: string;
  error?: string;
}

export async function probeTls(host: string, sni: string, version: number, port = 443, timeoutMs = 6000): Promise<HandshakeResult> {
  const res: HandshakeResult = { ok: false, certs: [], ocspStapled: false };
  let conn: TcpConn;
  try {
    conn = await TcpConn.open(host, port, timeoutMs);
  } catch (e) {
    res.error = socketError(e);
    return res;
  }
  try {
    await conn.write(buildClientHello(sni, version));
    let hs = new Uint8Array(0);
    for (let records = 0; records < 64; records++) {
      const hdr = await conn.readExact(5);
      if (!hdr) { if (!res.ok) res.error = "spojení ukončeno serverem"; break; }
      const type = hdr[0];
      const len = (hdr[3] << 8) | hdr[4];
      const body = await conn.readExact(len);
      if (!body) { res.error = "zkrácený TLS záznam"; break; }

      if (type === 0x15) { // alert
        res.alert = ALERTS[body[1]] ?? `alert ${body[1]}`;
        break;
      }
      if (type !== 0x16) break; // CCS / encrypted data: nothing readable any more

      const merged = new Uint8Array(hs.length + body.length);
      merged.set(hs); merged.set(body, hs.length); hs = merged;

      let done = false;
      while (hs.length >= 4) {
        const mt = hs[0];
        const ml = (hs[1] << 16) | (hs[2] << 8) | hs[3];
        if (hs.length < 4 + ml) break;
        const msg = hs.subarray(4, 4 + ml);
        if (mt === 2) {
          parseServerHello(msg, res);
          if (res.version === TLS13) done = true; // everything after is encrypted
        } else if (mt === 11) {
          res.certs = parseCertificateMsg(msg);
        } else if (mt === 22) {
          res.ocspStapled = true;
        } else if (mt === 14) {
          done = true; // ServerHelloDone
        }
        hs = hs.slice(4 + ml);
      }
      if (done) break;
    }
  } catch (e) {
    if (!res.ok) res.error = socketError(e);
  } finally {
    conn.close();
  }
  return res;
}

function parseServerHello(m: Uint8Array, res: HandshakeResult): void {
  let p = 0;
  res.version = (m[p] << 8) | m[p + 1]; p += 2;
  p += 32; // random
  p += 1 + m[p]; // session id
  res.cipher = (m[p] << 8) | m[p + 1]; p += 2;
  p += 1; // compression
  res.ok = true;
  if (p + 2 > m.length) return;
  const extEnd = p + 2 + ((m[p] << 8) | m[p + 1]);
  p += 2;
  while (p + 4 <= extEnd) {
    const t = (m[p] << 8) | m[p + 1];
    const l = (m[p + 2] << 8) | m[p + 3];
    if (t === 0x002b && l === 2) res.version = (m[p + 4] << 8) | m[p + 5];
    p += 4 + l;
  }
}

function parseCertificateMsg(m: Uint8Array): Uint8Array[] {
  const certs: Uint8Array[] = [];
  const total = (m[0] << 16) | (m[1] << 8) | m[2];
  let p = 3;
  const end = Math.min(3 + total, m.length);
  while (p + 3 <= end) {
    const l = (m[p] << 16) | (m[p + 1] << 8) | m[p + 2];
    p += 3;
    certs.push(m.slice(p, p + l));
    p += l;
  }
  return certs;
}

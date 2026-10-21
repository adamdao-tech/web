// Small DER / X.509 parser — just the fields the checker needs.

interface TLV { tag: number; start: number; end: number; hdr: number }

function tlv(b: Uint8Array, off: number): TLV {
  const tag = b[off];
  let len = b[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p++];
  }
  return { tag, start: p, end: p + len, hdr: off };
}

function children(b: Uint8Array, t: TLV): TLV[] {
  const out: TLV[] = [];
  let p = t.start;
  while (p < t.end) {
    const c = tlv(b, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

function oid(b: Uint8Array, t: TLV): string {
  const v = b.subarray(t.start, t.end);
  const parts = [Math.floor(v[0] / 40), v[0] % 40];
  let n = 0;
  for (let i = 1; i < v.length; i++) {
    n = n * 128 + (v[i] & 0x7f);
    if (!(v[i] & 0x80)) { parts.push(n); n = 0; }
  }
  return parts.join(".");
}

function str(b: Uint8Array, t: TLV): string {
  const v = b.subarray(t.start, t.end);
  if (t.tag === 0x1e) { // BMPString
    let s = "";
    for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
    return s;
  }
  return new TextDecoder().decode(v);
}

function time(b: Uint8Array, t: TLV): Date {
  const s = str(b, t);
  const m = t.tag === 0x17
    ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/)
    : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
  if (!m) return new Date(NaN);
  let y = Number(m[1]);
  if (t.tag === 0x17) y += y < 50 ? 2000 : 1900;
  return new Date(Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)));
}

const NAME_ATTR: Record<string, string> = {
  "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
};

export const SIG_ALG: Record<string, string> = {
  "1.2.840.113549.1.1.5": "sha1WithRSA",
  "1.2.840.113549.1.1.11": "sha256WithRSA",
  "1.2.840.113549.1.1.12": "sha384WithRSA",
  "1.2.840.113549.1.1.13": "sha512WithRSA",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.3.101.112": "Ed25519",
};

const CURVES: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521",
};

export interface Cert {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  subjectRaw: string;
  issuerRaw: string;
  serial: string;
  notBefore: Date;
  notAfter: Date;
  sigAlg: string;
  keyType: string;
  keyBits?: number;
  dnsNames: string[];
  ipAddresses: string[];
  isCA: boolean;
  selfSigned: boolean;
  caIssuers: string[];
  ocsp: string[];
  sha256: string;
}

function parseName(b: Uint8Array, t: TLV): Record<string, string> {
  const out: Record<string, string> = {};
  for (const set of children(b, t)) {
    for (const atv of children(b, set)) {
      const [o, v] = children(b, atv);
      const key = NAME_ATTR[oid(b, o)];
      if (key && !(key in out)) out[key] = str(b, v);
    }
  }
  return out;
}

const hex = (v: Uint8Array) => Array.from(v, (x) => x.toString(16).padStart(2, "0")).join("");

export async function parseCert(der: Uint8Array): Promise<Cert> {
  const root = tlv(der, 0);
  const [tbsT, sigAlgT] = children(der, root);
  const tbs = children(der, tbsT);
  let i = 0;
  if (tbs[0].tag === 0xa0) i++; // version
  const serialT = tbs[i++];
  i++; // signature alg (inner)
  const issuerT = tbs[i++];
  const validityT = tbs[i++];
  const subjectT = tbs[i++];
  const spkiT = tbs[i++];
  const extT = tbs.slice(i).find((t) => t.tag === 0xa3);

  const [nb, na] = children(der, validityT);
  const issuerRaw = hex(der.subarray(issuerT.hdr, issuerT.end));
  const subjectRaw = hex(der.subarray(subjectT.hdr, subjectT.end));

  const cert: Cert = {
    subject: parseName(der, subjectT),
    issuer: parseName(der, issuerT),
    subjectRaw,
    issuerRaw,
    serial: hex(der.subarray(serialT.start, serialT.end)).replace(/^00/, ""),
    notBefore: time(der, nb),
    notAfter: time(der, na),
    sigAlg: SIG_ALG[oid(der, children(der, sigAlgT)[0])] ?? oid(der, children(der, sigAlgT)[0]),
    keyType: "unknown",
    dnsNames: [],
    ipAddresses: [],
    isCA: false,
    selfSigned: issuerRaw === subjectRaw,
    caIssuers: [],
    ocsp: [],
    sha256: "",
  };

  // Public key
  const [algSeq, keyBits] = children(der, spkiT);
  const algParts = children(der, algSeq);
  const keyOid = oid(der, algParts[0]);
  if (keyOid === "1.2.840.113549.1.1.1") {
    cert.keyType = "RSA";
    const rsa = tlv(der, keyBits.start + 1); // skip "unused bits" byte
    const mod = children(der, rsa)[0];
    let len = mod.end - mod.start;
    if (der[mod.start] === 0) len--;
    cert.keyBits = len * 8;
  } else if (keyOid === "1.2.840.10045.2.1") {
    const curve = algParts[1] && algParts[1].tag === 0x06 ? CURVES[oid(der, algParts[1])] : undefined;
    cert.keyType = `EC ${curve ?? ""}`.trim();
    cert.keyBits = curve === "P-384" ? 384 : curve === "P-521" ? 521 : 256;
  } else if (keyOid === "1.3.101.112") {
    cert.keyType = "Ed25519";
  }

  // Extensions
  if (extT) {
    const seq = children(der, extT)[0];
    for (const e of children(der, seq)) {
      const parts = children(der, e);
      const id = oid(der, parts[0]);
      const val = parts[parts.length - 1]; // OCTET STRING
      const inner = tlv(der, val.start);
      if (id === "2.5.29.17") {
        for (const gn of children(der, inner)) {
          if (gn.tag === 0x82) cert.dnsNames.push(new TextDecoder().decode(der.subarray(gn.start, gn.end)));
          if (gn.tag === 0x87) cert.ipAddresses.push(Array.from(der.subarray(gn.start, gn.end)).join("."));
        }
      } else if (id === "2.5.29.19") {
        const bc = children(der, inner);
        cert.isCA = bc.length > 0 && bc[0].tag === 0x01 && der[bc[0].start] !== 0;
      } else if (id === "1.3.6.1.5.5.7.1.1") {
        for (const ad of children(der, inner)) {
          const [m, loc] = children(der, ad);
          const method = oid(der, m);
          if (loc.tag !== 0x86) continue;
          const uri = new TextDecoder().decode(der.subarray(loc.start, loc.end));
          if (method === "1.3.6.1.5.5.7.48.2") cert.caIssuers.push(uri);
          if (method === "1.3.6.1.5.5.7.48.1") cert.ocsp.push(uri);
        }
      }
    }
  }

  const digest = await crypto.subtle.digest("SHA-256", der);
  cert.sha256 = hex(new Uint8Array(digest)).toUpperCase().match(/../g)!.join(":");
  return cert;
}

export function nameLabel(n: Record<string, string>): string {
  return n.CN ?? n.O ?? n.OU ?? "?";
}

/** Does the cert cover `host`? Handles single-label wildcards. */
export function certCovers(names: string[], host: string): boolean {
  const h = host.toLowerCase();
  return names.some((n) => {
    const name = n.toLowerCase();
    if (name === h) return true;
    if (name.startsWith("*.")) {
      const suffix = name.slice(1); // ".example.com"
      return h.endsWith(suffix) && !h.slice(0, -suffix.length).includes(".") && h.length > suffix.length;
    }
    return false;
  });
}

// Workers cannot open raw TCP sockets to Cloudflare's own IP space, so sites behind the
// orange-cloud proxy (and Cloudflare nameservers) are detected up front.
// Source: https://www.cloudflare.com/ips-v4
const RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
  "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
].map((c) => {
  const [ip, bits] = c.split("/");
  return { net: ipToInt(ip), mask: Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0 };
});

function ipToInt(ip: string): number {
  return ip.split(".").reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0);
}

export function isCloudflareIp(ip: string): boolean {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const n = ipToInt(ip);
  return RANGES.some((r) => ((n & r.mask) >>> 0) === ((r.net & r.mask) >>> 0));
}

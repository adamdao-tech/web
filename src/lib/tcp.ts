import { connect } from "cloudflare:sockets";

/** Thin buffered wrapper around a Workers TCP socket. */
export class TcpConn {
  private buf = new Uint8Array(0);
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private eof = false;

  private constructor(private socket: Socket, private deadline: number) {
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
  }

  static async open(host: string, port: number, timeoutMs = 6000): Promise<TcpConn> {
    const deadline = Date.now() + timeoutMs;
    const socket = connect({ hostname: host, port }, { allowHalfOpen: false });
    await withTimeout(socket.opened, deadline, "connect timeout");
    return new TcpConn(socket, deadline);
  }

  async write(data: Uint8Array): Promise<void> {
    await withTimeout(this.writer.write(data), this.deadline, "write timeout");
  }

  /** Read exactly n bytes; returns null on EOF before n bytes arrived. */
  async readExact(n: number): Promise<Uint8Array | null> {
    while (this.buf.length < n) {
      if (this.eof) return null;
      const r = await withTimeout(this.reader.read(), this.deadline, "read timeout");
      if (r.done) { this.eof = true; continue; }
      const merged = new Uint8Array(this.buf.length + r.value.length);
      merged.set(this.buf);
      merged.set(r.value, this.buf.length);
      this.buf = merged;
    }
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }

  close(): void {
    try { this.reader.releaseLock(); } catch { /* ignore */ }
    try { this.writer.releaseLock(); } catch { /* ignore */ }
    this.socket.close().catch(() => {});
  }
}

function withTimeout<T>(p: Promise<T>, deadline: number, msg: string): Promise<T> {
  const ms = Math.max(1, deadline - Date.now());
  let t: ReturnType<typeof setTimeout>;
  return Promise.race([
    p,
    new Promise<T>((_, rej) => { t = setTimeout(() => rej(new Error(msg)), ms); }),
  ]).finally(() => clearTimeout(t));
}

/** Map socket errors to a short Czech-friendly reason. */
export function socketError(e: unknown): string {
  const m = (e as Error)?.message ?? String(e);
  if (/proxy request failed|cannot connect to the specified address/i.test(m)) return "nelze se připojit";
  if (/timeout/i.test(m)) return "timeout";
  if (/refused/i.test(m)) return "connection refused";
  return m;
}

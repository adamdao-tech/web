export type Status = "ok" | "warn" | "fail" | "info" | "skip";

export interface Check {
  /** stable id, e.g. "dns.caa" */
  id: string;
  /** short label shown in the UI */
  name: string;
  status: Status;
  /** one-line value / verdict */
  value?: string;
  /** extra technical note */
  detail?: string;
  /** raw lines (records, headers, chain…) shown when expanded */
  items?: string[];
}

export interface ModuleResult {
  module: string;
  title: string;
  domain: string;
  durationMs: number;
  checks: Check[];
}

export type Collector = Check[];

export function add(
  out: Collector,
  id: string,
  name: string,
  status: Status,
  value?: string,
  detail?: string,
  items?: string[],
): void {
  const c: Check = { id, name, status };
  if (value !== undefined) c.value = value;
  if (detail !== undefined) c.detail = detail;
  if (items && items.length) c.items = items;
  out.push(c);
}

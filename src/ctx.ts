import { Dns } from "./lib/doh";

export interface Ctx {
  /** hostname as entered (normalized) */
  domain: string;
  /** zone apex, e.g. example.cz for www.example.cz */
  zone: string;
  /** hostname without a leading www. */
  base: string;
  dns: Dns;
}

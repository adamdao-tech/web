import { Dns } from "./lib/doh";

export interface Ctx {
  /** hostname as entered (normalized) */
  domain: string;
  /** zone apex, e.g. example.cz for www.example.cz */
  zone: string;
  /** hostname without a leading www. */
  base: string;
  dns: Dns;
  /** Spamhaus Data Query Service key (Worker secret SPAMHAUS_DQS_KEY) */
  dqsKey?: string;
}

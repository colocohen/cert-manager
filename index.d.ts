import { EventEmitter } from 'node:events';

// --- Certificate ---

export interface Certificate {
  cert: string;
  ca: string[];
  key: string;
  csr: string;
  expiresAt: Date | null;
}

// --- createOrder ---

export interface OrderOptions {
  domain: string;
  email: string;
  wildcard?: boolean;
  altNames?: string[];
  provider?: 'letsencrypt' | 'zerossl';
  staging?: boolean;
  accountKey?: string | null;
  privateKey?: string | null;
  csr?: string | null;
  eab?: { kid: string; hmacKey: string } | null;
  csrFields?: {
    country?: string;
    state?: string;
    locality?: string;
    organization?: string;
    organizationUnit?: string;
  };
  keyType?: 'ecdsa' | 'rsa';
  keyCurve?: 'P-256' | 'P-384';
  keySize?: number;
  preflight?: boolean;
  autoVerify?: boolean;
  autoVerifyInterval?: number;
  autoVerifyRetries?: number;
  autoStart?: boolean;
}

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
}

export interface VerifyInfo {
  attempt: number;
  total: number;
  found: number;
  expected: number;
  results: Array<{ domain: string; found: boolean }>;
}

export interface ValidatingInfo {
  attempt: number;
  statuses: string[];
}

export interface CompletingInfo {
  results: Array<{
    identifier: string;
    url: string;
    status: string;
    httpStatus: number | null;
    error: string | null;
  }>;
}

export interface AccountInfo {
  url: string;
  key: string;
}

export interface Order {
  on(event: 'dns', listener: (records: DnsRecord[], done: () => void) => void): void;
  on(event: 'certificate', listener: (cert: Certificate) => void): void;
  on(event: 'account', listener: (account: AccountInfo) => void): void;
  on(event: 'verify', listener: (info: VerifyInfo) => void): void;
  on(event: 'validating', listener: (info: ValidatingInfo) => void): void;
  on(event: 'completing', listener: (info: CompletingInfo) => void): void;
  on(event: 'state', listener: (newState: string, oldState: string) => void): void;
  on(event: 'error', listener: (err: Error, step: string) => void): void;
  on(event: string, listener: (...args: any[]) => void): void;

  start(): void;
  abort(): void;
  set_context(opts: Record<string, any>): void;
  getState(): string;
  getDomain(): string;
  getAccountKey(): string | null;
  getPrivateKey(): string | null;
  getCsr(): Buffer | string | null;
}

// --- manager ---

export interface ManagerOptions {
  dir: string;
  email: string;
  provider?: 'letsencrypt' | 'zerossl';
  staging?: boolean;
  eab?: { kid: string; hmacKey: string } | null;
  renewBeforeDays?: number;
  checkInterval?: number;
  retryInterval?: number;
}

export interface AddOptions {
  wildcard?: boolean;
  email?: string;
}

export interface CsvRow {
  domain: string;
  status: string;
  issued_at: string;
  expires_at: string;
  renew_after: string;
  last_attempt: string;
  last_error: string;
}

export interface CertData {
  domain: string;
  wildcard: boolean;
  email: string;
  cert?: string;
  ca?: string[];
  key?: string;
  csr?: string;
  status: 'active' | 'pending' | 'error';
  issued_at?: Date;
  expires_at?: Date;
}

export interface Manager {
  on(event: 'dns', listener: (domain: string, records: DnsRecord[], done: () => void) => void): void;
  on(event: 'certificate', listener: (domain: string, cert: Certificate) => void): void;
  on(event: 'renewing', listener: (domain: string, daysLeft: number | null) => void): void;
  on(event: 'error', listener: (domain: string, err: Error) => void): void;
  on(event: string, listener: (...args: any[]) => void): void;
  off(event: string, listener: (...args: any[]) => void): void;

  add(domain: string, opts?: AddOptions): void;
  remove(domain: string): void;
  get(domain: string, callback: (err: Error | null, data: CertData | null) => void): void;
  list(callback: (err: Error | null, rows: CsvRow[]) => void): void;
  renewNow(domain: string): void;
  status(): string | null;
  start(): void;
  stop(): void;
}

// --- Exports ---

export function createOrder(options: OrderOptions): Order;
export function manager(options: ManagerOptions): Manager;

export const PROVIDERS: Record<string, { staging: string; production: string }>;

declare const autossl: {
  createOrder: typeof createOrder;
  manager: typeof manager;
  Order: new (options: OrderOptions) => Order;
  Manager: new (options: ManagerOptions) => Manager;
  PROVIDERS: typeof PROVIDERS;
};

export default autossl;

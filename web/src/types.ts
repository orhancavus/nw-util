export type NetworkContext = {
  address: string;
  network: string;
  interface: string | null;
  gateway: string | null;
};

export type Capabilities = {
  version: string;
  platform: string;
  nmap: boolean;
  mdns: boolean;
  local_only: boolean;
};

export type Device = {
  id: string;
  type: string;
  emoji: string;
  name: string;
  status: string;
  ip: string;
  mac: string | null;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  services: string[];
  alias: string | null;
  latency_ms: number | null;
  neighbor_state: string | null;
  responsive: boolean;
  is_self: boolean;
  is_gateway: boolean;
};

export type ScanResult = {
  context: NetworkContext;
  devices: Device[];
  device_count: number;
};

export type Job<T = unknown> = {
  id: string;
  kind: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelling' | 'cancelled';
  phase: string;
  error: string | null;
  result?: T;
};

export type ScanSettings = {
  network: string | null;
  timeout: number;
  workers: number;
  max_hosts: number;
  deep: boolean;
  discover: boolean;
  mdns_timeout: number;
  record_history: boolean;
};

export type HistoryRecord = {
  id: string;
  first_seen: string;
  last_seen: string;
  ips: string[];
  macs: string[];
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  type: string;
  alias: string | null;
};

export type Finding = { severity: 'high' | 'medium' | 'info'; message: string };
export type ServiceProfile = {
  port: number;
  protocol: string;
  name: string;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  confidence: number | null;
  cpes: string[];
};
export type SecurityProfile = {
  ip: string;
  scanner: string;
  services: ServiceProfile[];
  probable_operating_systems: Array<{
    name: string;
    accuracy: number | null;
    device_type: string | null;
    source: string;
    cpes: string[];
  }>;
  findings: Finding[];
  os_detection_note: string | null;
};

export type WatchEvent = {
  id: number;
  change: string;
  device: Device;
  timestamp: string;
};

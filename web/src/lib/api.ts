// Typed client for the pcapviz REST API. Same-origin in production (embedded
// binary); proxied to :8080 in dev by Vite.

export interface AppInfo {
  kind: string;
  dnsName?: string;
  httpMethod?: string;
  httpHost?: string;
  httpURI?: string;
  httpStatus?: number;
  tlsSNI?: string;
}

export interface Packet {
  num: number;
  time: string;
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  proto: string;
  length: number;
  info: string;
  app?: AppInfo;
}

export interface Page {
  items: Packet[];
  total: number;
  offset: number;
  limit: number;
}

export interface Field {
  name: string;
  value: string;
}
export interface Layer {
  name: string;
  fields: Field[];
}
export interface Detail {
  num: number;
  layers: Layer[];
  hexDump: string;
}

export interface ProtoCount {
  proto: string;
  packets: number;
  bytes: number;
}
export interface Talker {
  addr: string;
  packets: number;
  bytes: number;
}
export interface Conversation {
  a: string;
  b: string;
  proto: string;
  packets: number;
  bytes: number;
}
export interface TimeBucket {
  time: string;
  packets: number;
  bytes: number;
}
export interface Stats {
  totalPackets: number;
  totalBytes: number;
  start: string;
  end: string;
  protocols: ProtoCount[];
  topTalkers: Talker[];
  conversations: Conversation[];
  timeline: TimeBucket[];
}

export interface Status {
  count: number;
  loaded: boolean;
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      if (body.error) msg = body.error;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export function getStatus(): Promise<Status> {
  return fetch("/api/status").then((r) => json<Status>(r));
}

export function listPackets(filter: string, offset: number, limit: number): Promise<Page> {
  const q = new URLSearchParams({ offset: String(offset), limit: String(limit) });
  if (filter) q.set("filter", filter);
  return fetch(`/api/packets?${q}`).then((r) => json<Page>(r));
}

export function getDetail(num: number): Promise<Detail> {
  return fetch(`/api/packets/${num}`).then((r) => json<Detail>(r));
}

export function getStats(): Promise<Stats> {
  return fetch("/api/stats").then((r) => json<Stats>(r));
}

export function uploadFile(file: File): Promise<{ count: number }> {
  const fd = new FormData();
  fd.append("file", file);
  return fetch("/api/upload", { method: "POST", body: fd }).then((r) => json(r));
}

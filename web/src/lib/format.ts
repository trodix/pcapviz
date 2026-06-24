// Small formatting helpers shared across components.

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function clock(iso: string): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

const protoColors: Record<string, string> = {
  DNS: "#3b82f6",
  HTTP: "#22c55e",
  TLS: "#a855f7",
  TCP: "#0ea5e9",
  UDP: "#14b8a6",
  ICMP: "#f97316",
  ICMPv6: "#f97316",
  ARP: "#eab308",
  IPv4: "#64748b",
  IPv6: "#64748b",
};

export function protoColor(proto: string): string {
  return protoColors[proto] ?? "#94a3b8";
}

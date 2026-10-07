// lib/dns-wire.mjs
var TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };
function dnsQuestion(name, type = "A") {
  const code = TYPES[String(type).toUpperCase()] || Number(type);
  const labels = name.replace(/\.$/, "").split(".");
  if (!Number.isInteger(code) || code < 1 || code > 65535 || name.length > 254 || labels.some((l) => !l.length || l.length > 63 || !/^[a-zA-Z0-9_-]+$/.test(l))) throw new RangeError("Invalid DNS name or record type");
  const id = crypto.getRandomValues(new Uint8Array(2));
  return new Uint8Array([...id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels.flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0, code >> 8, code & 255, 0, 1]);
}
function dnsJson(bytes, question) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const requireBytes = (offset, size) => {
    if (offset < 0 || offset + size > bytes.length) throw new Error("Truncated DNS response");
  };
  requireBytes(0, 12);
  if (!(bytes[2] & 128) || bytes[0] !== question[0] || bytes[1] !== question[1]) throw new Error("Invalid DNS response ID or flags");
  function nameAt(offset) {
    const labels = [], seen = /* @__PURE__ */ new Set();
    let next;
    while (true) {
      requireBytes(offset, 1);
      if (seen.has(offset) || seen.size > 128) throw new Error("Invalid DNS compression");
      seen.add(offset);
      const length = bytes[offset++];
      if (!length) return { name: labels.join(".") + ".", next: next ?? offset };
      if ((length & 192) === 192) {
        requireBytes(offset, 1);
        next ??= offset + 1;
        offset = (length & 63) << 8 | bytes[offset];
        continue;
      }
      if (length > 63) throw new Error("Invalid DNS label");
      requireBytes(offset, length);
      labels.push(new TextDecoder().decode(bytes.subarray(offset, offset + length)));
      offset += length;
    }
  }
  let cursor = 12;
  const questions = [], answers = [];
  for (let i = 0; i < view.getUint16(4); i++) {
    const q = nameAt(cursor);
    cursor = q.next;
    requireBytes(cursor, 4);
    questions.push({ name: q.name, type: view.getUint16(cursor) });
    cursor += 4;
  }
  for (let i = 0; i < view.getUint16(6); i++) {
    const name = nameAt(cursor);
    cursor = name.next;
    requireBytes(cursor, 10);
    const type = view.getUint16(cursor), TTL = view.getUint32(cursor + 4), size = view.getUint16(cursor + 8);
    cursor += 10;
    requireBytes(cursor, size);
    const dataBytes = bytes.subarray(cursor, cursor + size);
    let data;
    if (type === 1 && size === 4) data = [...dataBytes].join(".");
    else if (type === 28 && size === 16) data = Array.from({ length: 8 }, (_, n) => view.getUint16(cursor + n * 2).toString(16)).join(":");
    else if ([2, 5, 12].includes(type)) data = nameAt(cursor).name;
    else if (type === 15 && size >= 3) data = `${view.getUint16(cursor)} ${nameAt(cursor + 2).name}`;
    else if (type === 16) {
      const text = [];
      for (let n = 0; n < size; ) {
        const length = dataBytes[n++];
        if (n + length > size) throw new Error("Truncated TXT record");
        text.push(JSON.stringify(new TextDecoder().decode(dataBytes.subarray(n, n + length))));
        n += length;
      }
      data = text.join(" ");
    } else data = [...dataBytes].map((n) => n.toString(16).padStart(2, "0")).join("");
    answers.push({ name: name.name, type, TTL, data });
    cursor += size;
  }
  return { Status: bytes[3] & 15, TC: !!(bytes[2] & 2), RD: !!(bytes[2] & 1), RA: !!(bytes[3] & 128), AD: !!(bytes[3] & 32), CD: !!(bytes[3] & 16), Question: questions, Answer: answers };
}
async function queryDnsJson(url, name, type, fetchImpl = fetch) {
  const question = dnsQuestion(name, type);
  const response = await fetchImpl(url, { method: "POST", headers: { "Content-Type": "application/dns-message", Accept: "application/dns-message" }, body: question, signal: AbortSignal.timeout(1e4) });
  if (!response.ok) throw new Error(`DNS upstream HTTP ${response.status}`);
  return dnsJson(new Uint8Array(await response.arrayBuffer()), question);
}

// lib/client-dns.mjs
var DNS_DEFAULTS = Object.freeze({ mode: "real", resolver: "panel", route: "direct", bootstrap: "1.1.1.1", ipv6: false, tun: false, blockQuic: false, exclusions: "localhost\nlan\nlocal", domains: "", domainResolver: "https://1.1.1.1/dns-query", forceProxy: "", gatewayFallbacks: "" });
var domainList = (value) => [...new Set(String(value).split(/[\s,]+/).filter(Boolean).map((v) => v.toLowerCase().replace(/^\*?\./, "")))];
var isIP = (value) => /^(\d{1,3}\.){3}\d{1,3}$/.test(value) ? value.split(".").every((n) => +n <= 255) : value.includes(":") && (() => {
  try {
    return !!new URL(`http://[${value}]/`).hostname;
  } catch {
    return false;
  }
})();
function parseResolver(value) {
  if (value === "panel") return { type: "panel" };
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("DNS resolver must use https://, tls://, tcp://, udp://, quic:// or h3://.");
  }
  const type = { "https:": "https", "tls:": "tls", "tcp:": "tcp", "udp:": "udp", "quic:": "quic", "h3:": "h3" }[url.protocol];
  if (!type || !url.hostname || url.username || url.password || url.hash || url.port && (+url.port < 1 || +url.port > 65535)) throw new Error("Invalid DNS resolver URL. Credentials and fragments are not supported.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!isIP(host) && (host.length > 253 || !host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)))) throw new Error("Invalid DNS resolver hostname.");
  if (!["https", "h3"].includes(type) && (url.pathname && url.pathname !== "/" || url.search)) throw new Error("Only HTTPS/HTTP3 DNS supports a path or query.");
  return { type, server: url.hostname.replace(/^\[|\]$/g, ""), server_port: +(url.port || { https: 443, h3: 443, tls: 853, quic: 853, tcp: 53, udp: 53 }[type]), ...["https", "h3"].includes(type) ? { path: (url.pathname === "/" ? "/dns-query" : url.pathname || "/dns-query") + url.search } : {} };
}
function normalizeDns(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid client DNS settings.");
  const p = Object.fromEntries(Object.entries(DNS_DEFAULTS).map(([k, v]) => [k, input[k] ?? v]));
  for (const k of ["ipv6", "tun", "blockQuic"]) if (typeof p[k] !== "boolean") throw new Error(`Invalid DNS ${k} toggle.`);
  if (!["real", "fake-ip"].includes(p.mode) || !["direct", "proxy"].includes(p.route)) throw new Error("Invalid DNS mode or route.");
  for (const k of ["resolver", "bootstrap", "domainResolver"]) {
    if (typeof p[k] !== "string" || p[k].length > 2048) throw new Error(`Invalid DNS ${k}.`);
    p[k] = p[k].trim();
  }
  if (!isIP(p.bootstrap)) throw new Error("Bootstrap DNS must be an IPv4 or IPv6 address.");
  for (const k of ["exclusions", "domains", "forceProxy"]) {
    if (typeof p[k] !== "string" || p[k].length > 8192) throw new Error(`Invalid DNS ${k} list.`);
    const list = domainList(p[k]);
    if (list.length > 100 || list.some((d) => d.length > 253 || !d.split(".").every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)))) throw new Error("Enter domain suffixes only, one per line (no URLs or paths).");
    p[k] = list.join("\n");
  }
  for (const k of ["resolver", "domainResolver"]) {
    const r = parseResolver(p[k]);
    if (p.route === "proxy" && (k === "resolver" || p.domains) && r.type === "panel") throw new Error("For proxy-routed DNS, enter an external HTTPS/TLS/TCP resolver instead of panel to avoid connecting the Worker back to itself.");
    if (p.route === "proxy" && (k === "resolver" || p.domains) && ["udp", "quic", "h3"].includes(r.type)) throw new Error("Worker tunnels carry TCP. Use HTTPS, TLS or TCP DNS for proxy-routed DNS; UDP/QUIC/HTTP3 require direct DNS.");
  }
  if (typeof p.gatewayFallbacks !== "string" || p.gatewayFallbacks.length > 4096) throw new Error("Invalid gateway fallback list.");
  const fallback = [...new Set(p.gatewayFallbacks.split(/\s+/).filter(Boolean))];
  if (fallback.length > 3) throw new Error("Use at most three gateway fallback resolvers.");
  fallback.forEach(validateDoh);
  p.gatewayFallbacks = fallback.join("\n");
  return p;
}
function validateDoh(value) {
  if (value && parseResolver(value).type !== "https") throw new Error("The panel DNS gateway requires an HTTPS DoH URL. Configure other transports under Client DNS.");
  return value;
}
function readDns(stored) {
  return normalizeDns(stored ? JSON.parse(stored) : {});
}
function dnsFromForm(form) {
  const p = {};
  for (const [k, v] of Object.entries(DNS_DEFAULTS)) p[k] = typeof v === "boolean" ? form.get(`clientDns_${k}`) === "on" : String(form.get(`clientDns_${k}`) ?? v);
  return normalizeDns(p);
}
function server(value, tag2, p, host) {
  let r = parseResolver(value);
  if (r.type === "panel") r = { type: "https", server: host, path: "/dns-query" };
  return { ...r, tag: tag2, ...!isIP(r.server) ? { domain_resolver: "bootstrap-dns" } : {}, ...p.route === "proxy" ? { detour: "select" } : {} };
}
function singboxDns(p, host) {
  const servers = [{ type: "udp", tag: "bootstrap-dns", server: p.bootstrap }, server(p.resolver, "remote-dns", p, host)];
  const rules = [];
  if (p.domains) {
    servers.push(server(p.domainResolver, "domain-dns", p, host));
    rules.push({ domain_suffix: domainList(p.domains), action: "route", server: "domain-dns" });
  }
  if (p.mode === "fake-ip") {
    servers.push({ type: "fakeip", tag: "fake-dns", inet4_range: "198.18.0.0/15", ...p.ipv6 ? { inet6_range: "fc00::/18" } : {} });
    if (p.exclusions) rules.push({ domain_suffix: domainList(p.exclusions), action: "route", server: "remote-dns" });
    rules.push({ query_type: p.ipv6 ? ["A", "AAAA"] : ["A"], action: "route", server: "fake-dns" });
  }
  return { servers, rules, final: "remote-dns", strategy: p.ipv6 ? "prefer_ipv4" : "ipv4_only" };
}
function singboxDnsExtras(config2, p) {
  if (p.tun) config2.inbounds.push({ type: "tun", tag: "tun-in", address: ["172.19.0.1/30", ...p.ipv6 ? ["fdfe:dcba:9876::1/126"] : []], auto_route: true, strict_route: true, stack: "mixed" });
  const extra = [];
  if (p.blockQuic) extra.push({ network: "udp", port: 443, action: "reject" });
  if (p.forceProxy) extra.push({ domain_suffix: domainList(p.forceProxy), outbound: "select" });
  config2.route.rules.splice(2, 0, ...extra);
}
function clashDns(p, host) {
  const endpoint = (v) => v === "panel" ? `https://${host}/dns-query` : v.replace(/^h3:\/\//, "https://") + (v.startsWith("h3://") ? "#h3=true" : "");
  const d = { enable: true, listen: "127.0.0.1:1053", ipv6: p.ipv6, "enhanced-mode": p.mode === "fake-ip" ? "fake-ip" : "redir-host", "default-nameserver": [p.bootstrap], "proxy-server-nameserver": [p.bootstrap], nameserver: [endpoint(p.resolver) + (p.route === "proxy" ? "#PROXY" : "")] };
  if (p.mode === "fake-ip") {
    d["fake-ip-range"] = "198.18.0.1/16";
    if (p.ipv6) d["fake-ip-range6"] = "fc00::/18";
    d["fake-ip-filter"] = domainList(p.exclusions + "\n" + p.domains).flatMap((d2) => [d2, `+.${d2}`]);
  }
  if (p.domains) d["nameserver-policy"] = Object.fromEntries(domainList(p.domains).map((d2) => [`+.${d2}`, endpoint(p.domainResolver) + (p.route === "proxy" ? "#PROXY" : "")]));
  return `dns: ${JSON.stringify(d)}
${p.tun ? "tun: " + JSON.stringify({ enable: true, stack: "mixed", "auto-route": true, "strict-route": true, "auto-detect-interface": true, "dns-hijack": ["any:53", "tcp://any:53"] }) + "\n" : ""}`;
}
function clashDnsRules(p) {
  return (p.blockQuic ? "\n  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT" : "") + domainList(p.forceProxy).map((d) => `
  - DOMAIN-SUFFIX,${d},PROXY`).join("");
}
var html = (v) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
function dnsControls(p) {
  const select = (k, label, options) => `<div class="form-group"><label class="form-label" for="clientDns_${k}">${label}</label><select class="form-control" id="clientDns_${k}" name="clientDns_${k}">${options.map(([v, t]) => `<option value="${v}" ${p[k] === v ? "selected" : ""}>${t}</option>`).join("")}</select></div>`;
  const field = (k, label, hint, area = false) => `<div class="form-group"><label class="form-label" for="clientDns_${k}">${label}</label>${area ? `<textarea rows="3"` : '<input type="text"'} class="form-control code-input" id="clientDns_${k}" name="clientDns_${k}" ${area ? `>${html(p[k])}</textarea>` : `value="${html(p[k])}" />`}<p class="card-desc">${hint}</p></div>`;
  return `<div class="card" style="margin-bottom:20px"><div class="card-title">Client DNS &amp; site routing</div><p class="card-desc">Applies to full Mihomo/Clash, Sing-box and Xray JSON subscriptions. Individual VLESS/Trojan/SS links cannot carry these settings; native-only profiles use their own DNS settings. Fake IP needs TUN or client DNS interception. It preserves domain names for routing, but does not change the country or reputation of your exit IP.</p><p class="card-desc">Xray exposes DNS at 127.0.0.1:1053. Enable VPN/TUN in your Xray client app. For h3 resolver URLs, Xray uses HTTPS over TCP at the same endpoint, which must support ordinary DoH. QUIC DNS connects directly; TLS DNS uses a verified TLS connection.</p><form action="/panel/settings/protocols" method="POST"><input type="hidden" name="clientDnsSettings" value="1" />
  ${select("mode", "DNS answer mode", [["real", "Real IP"], ["fake-ip", "Fake IP (Fake DNS)"]])}
  ${field("resolver", "Client DNS resolver", "Use panel, https://1.1.1.1/dns-query, tls://1.1.1.1, tcp://1.1.1.1, udp://1.1.1.1, quic://dns.adguard-dns.com or h3://dns.google/dns-query. The resolver must support the selected transport.")}
  ${select("route", "DNS connection route", [["direct", "Direct from device"], ["proxy", "Through selected proxy (HTTPS / TLS / TCP)"]])}
  ${field("bootstrap", "Bootstrap DNS IP", "Resolves proxy and resolver hostnames directly to avoid DNS loops. Use an address reachable from your device.")}
  ${["ipv6", "tun", "blockQuic"].map((k, i) => `<label style="display:block;margin:12px 0"><input type="checkbox" name="clientDns_${k}" ${p[k] ? "checked" : ""} /> ${["Enable IPv6 DNS answers", "Enable TUN for Mihomo/Sing-box (requires client VPN/admin permission)", "Reject UDP port 443 to encourage HTTPS over TCP"][i]}</label>`).join("")}
  ${field("exclusions", "Fake IP exclusions", "Domain suffixes, one per line. These receive real addresses.", true)}
  ${field("domains", "Domains using a separate resolver", "Domain suffixes, one per line. Overrides Fake IP for these domains. Useful with a trusted Smart DNS service; access depends on that service.", true)}
  ${field("domainResolver", "Resolver for those domains", "Same URL formats as the main resolver. Uses the DNS connection route selected above.")}
  ${field("forceProxy", "Always send these domains through the selected proxy", "Domain suffixes, one per line, applied before country bypass rules. For Google services you can include google.com, googleapis.com and gstatic.com. Choose a working proxy in your client; selecting DIRECT still connects directly.", true)}
  ${field("gatewayFallbacks", "Panel gateway fallback resolvers", "Optional HTTPS DoH URLs, one per line (maximum three). The panel retries these in order if its primary upstream times out, fails to connect or returns an HTTP error. Queries may be sent to these providers. Applies to /dns-query and /dns-json.", true)}
  <p class="card-desc">For IP-based regional blocks, configure a tested external exit under Routing &amp; Chain. The panel gateway below accepts HTTPS DoH upstreams; other DNS transports run in your client. Browser-specific Secure DNS may bypass client DNS policies.</p><button class="btn btn-primary" type="submit">Save client DNS &amp; routing</button></form></div>`;
}

// lib/dns-fallback.mjs
async function fetchDnsWithFallback(primary, fallbacks, init, fetchImpl = fetch, dnsParam) {
  const urls = [.../* @__PURE__ */ new Set([primary, ...fallbacks.split(/\s+/).filter(Boolean)])];
  let lastError;
  for (const endpoint of urls) {
    try {
      const url = new URL(endpoint);
      if (dnsParam !== void 0) url.searchParams.set("dns", dnsParam);
      const response = await fetchImpl(url.toString(), { ...init, signal: AbortSignal.timeout(5e3) });
      if (response.ok) return response;
      await response.body?.cancel();
      lastError = new Error(`DNS upstream HTTP ${response.status}`);
    } catch (error3) {
      lastError = error3;
    }
  }
  throw lastError || new Error("No DNS upstream available");
}

// lib/xray-dns.mjs
var domains = (text) => text.split("\n").filter(Boolean).map((d) => `domain:${d}`);
var literal = (host) => host.includes(":") || /^(\d+\.){3}\d+$/.test(host);
var authority = (host) => host.includes(":") ? `[${host}]` : host;
function applyXrayDns(config2, policy, panelHost) {
  const proxies = config2.outbounds.filter((o) => ["vless", "trojan", "shadowsocks"].includes(o.protocol));
  if (!proxies.length) throw new Error("Xray export requires a proxy outbound.");
  const proxyTag = proxies[0].tag;
  const bootstrapHosts = /* @__PURE__ */ new Set();
  const addHost = (host) => {
    if (host && !literal(host)) bootstrapHosts.add(`full:${host}`);
  };
  for (const outbound of proxies) {
    for (const remote of outbound.settings.vnext || outbound.settings.servers || []) addHost(remote.address);
    outbound.streamSettings.sockopt = { ...outbound.streamSettings.sockopt, domainStrategy: policy.ipv6 ? "UseIP" : "UseIPv4" };
  }
  const routeRules = [{ type: "field", inboundTag: ["dns-bootstrap"], outboundTag: "dns-bootstrap-out" }];
  config2.outbounds.push(
    { tag: "dns-bootstrap-out", protocol: "freedom", settings: {} },
    { tag: "dns-direct-out", protocol: "freedom", settings: {}, streamSettings: { sockopt: { domainStrategy: policy.ipv6 ? "UseIP" : "UseIPv4" } } },
    { tag: "dns-out", protocol: "dns", settings: { nonIPQuery: "reject" } }
  );
  function resolver(value, tag2) {
    const r = parseResolver(value === "panel" ? `https://${panelHost}/dns-query` : value);
    addHost(r.server);
    const hostPort = `${authority(r.server)}:${r.server_port}`;
    let address;
    let outboundTag = policy.route === "proxy" ? proxyTag : "dns-direct-out";
    if (r.type === "udp") address = r.server;
    else if (r.type === "quic") address = `quic+local://${hostPort}`;
    else if (r.type === "https" || r.type === "h3") address = `https://${hostPort}${r.path}`;
    else address = `tcp://${hostPort}`;
    if (r.type === "tls") {
      outboundTag = `${tag2}-tls-out`;
      config2.outbounds.push({
        tag: outboundTag,
        protocol: "freedom",
        settings: {},
        streamSettings: {
          network: "tcp",
          security: "tls",
          tlsSettings: { serverName: r.server, allowInsecure: false },
          sockopt: { domainStrategy: policy.ipv6 ? "UseIP" : "UseIPv4", ...policy.route === "proxy" ? { dialerProxy: proxyTag } : {} }
        }
      });
    }
    routeRules.push({ type: "field", inboundTag: [tag2], outboundTag });
    return { address, ...r.type === "udp" ? { port: r.server_port } : {}, tag: tag2 };
  }
  const primary = resolver(policy.resolver, "dns-primary");
  const servers = [];
  if (policy.domains) servers.push({ ...resolver(policy.domainResolver, "dns-domain"), domains: domains(policy.domains), skipFallback: true, finalQuery: true });
  if (policy.mode === "fake-ip") {
    if (policy.exclusions) servers.push({ ...primary, domains: domains(policy.exclusions), skipFallback: true, finalQuery: true });
    servers.push({ address: "fakedns" });
    config2.fakedns = [{ ipPool: "198.18.0.0/15", poolSize: 65535 }, ...policy.ipv6 ? [{ ipPool: "fc00::/18", poolSize: 65535 }] : []];
  } else servers.push(primary);
  if (bootstrapHosts.size) servers.unshift({ address: policy.bootstrap, port: 53, tag: "dns-bootstrap", domains: [...bootstrapHosts], skipFallback: true, finalQuery: true });
  config2.dns = { servers, queryStrategy: policy.ipv6 ? "UseIP" : "UseIPv4", disableFallbackIfMatch: true, tag: "dns-primary" };
  const userInbounds = config2.inbounds.map((i) => i.tag);
  for (const inbound of config2.inbounds) {
    inbound.sniffing = policy.mode === "fake-ip" ? { enabled: true, destOverride: ["fakedns"], metadataOnly: true } : { enabled: true, destOverride: ["http", "tls"], routeOnly: true };
  }
  config2.inbounds.push({ tag: "dns-in", listen: "127.0.0.1", port: 1053, protocol: "dokodemo-door", settings: { address: policy.bootstrap, port: 53, network: "tcp,udp" } });
  routeRules.push(
    { type: "field", inboundTag: ["dns-in"], outboundTag: "dns-out" },
    { type: "field", inboundTag: userInbounds, port: "53", outboundTag: "dns-out" }
  );
  if (policy.blockQuic) routeRules.push({ type: "field", network: "udp", port: "443", outboundTag: "block" });
  if (policy.forceProxy) routeRules.push({ type: "field", domain: domains(policy.forceProxy), outboundTag: proxyTag });
  if (policy.mode === "fake-ip") routeRules.push({ type: "field", ip: ["198.18.0.0/15", ...policy.ipv6 ? ["fc00::/18"] : []], outboundTag: proxyTag });
  config2.routing.rules.unshift(...routeRules);
}

// lib/subscription-native.mjs
function mergeNativeSubscription(config2, raw) {
  if (!raw) return config2;
  const native = JSON.parse(raw);
  if (!native || !Array.isArray(native.outbounds)) throw new Error("Invalid NATIVE_CLIENT_CONFIG: expected outbounds");
  const entries = [...native.outbounds, ...native.endpoints || []];
  const tags = new Set(entries.map((entry) => entry.tag));
  if (tags.size !== entries.length || entries.some((entry) => !entry.tag || !entry.type)) throw new Error("Native entries need unique tags and types");
  const rename = (tag2) => {
    if (!tags.has(tag2)) throw new Error("Native configuration has an unresolved outbound reference");
    return `native-${tag2}`;
  };
  const copy = (entry) => ({
    ...entry,
    tag: rename(entry.tag),
    ...entry.detour ? { detour: rename(entry.detour) } : {},
    ...entry.outbounds ? { outbounds: entry.outbounds.map(rename) } : {},
    ...entry.default ? { default: rename(entry.default) } : {}
  });
  const selector = native.outbounds.find((entry) => entry.tag === native.route?.final && entry.type === "selector") || native.outbounds.find((entry) => entry.type === "selector");
  const selected = selector?.outbounds || entries.filter((entry) => !["direct", "block", "dns", "shadowtls", "selector", "urltest"].includes(entry.type)).map((entry) => entry.tag);
  config2.outbounds.push(...native.outbounds.map(copy));
  config2.endpoints.push(...(native.endpoints || []).map(copy));
  config2.outbounds.find((entry) => entry.tag === "select").outbounds.push(...selected.map(rename));
  return config2;
}

// lib/ss-websocket.mjs
import { Buffer } from "node:buffer";
import { createHash, hkdfSync, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
var SS_METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
var salts = /* @__PURE__ */ new Map();
function masterKey(password, length) {
  let previous = Buffer.alloc(0), key = Buffer.alloc(0);
  while (key.length < length) {
    previous = createHash("md5").update(Buffer.concat([previous, Buffer.from(password)])).digest();
    key = Buffer.concat([key, previous]);
  }
  return key.subarray(0, length);
}
function ssCipher(method, password, salt) {
  if (!SS_METHODS.includes(method)) throw new Error("Unsupported Shadowsocks cipher");
  const size = method === "aes-128-gcm" ? 16 : 32;
  const key = Buffer.from(hkdfSync("sha1", masterKey(password, size), salt, "ss-subkey", size));
  const nonce = Buffer.alloc(12);
  const algorithm = method === "chacha20-ietf-poly1305" ? "chacha20-poly1305" : method;
  const advance = () => {
    for (let i = 0; i < nonce.length; i++) {
      nonce[i] = nonce[i] + 1 & 255;
      if (nonce[i]) return;
    }
    throw new Error("Nonce exhausted");
  };
  return {
    encrypt(data) {
      const cipher = createCipheriv(algorithm, key, nonce, { authTagLength: 16 });
      const result = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
      advance();
      return result;
    },
    decrypt(data) {
      const cipher = createDecipheriv(algorithm, key, nonce, { authTagLength: 16 });
      cipher.setAuthTag(data.subarray(-16));
      const result = Buffer.concat([cipher.update(data.subarray(0, -16)), cipher.final()]);
      advance();
      return result;
    }
  };
}
function ssEncoder(method, password) {
  let salt = randomBytes(method === "aes-128-gcm" ? 16 : 32);
  const cipher = ssCipher(method, password, salt);
  return (data) => {
    const chunks = [salt];
    salt = Buffer.alloc(0);
    for (let offset = 0; offset < data.length; offset += 16383) {
      const part = data.subarray(offset, offset + 16383), length = Buffer.alloc(2);
      length.writeUInt16BE(part.length);
      chunks.push(cipher.encrypt(length), cipher.encrypt(part));
    }
    return Buffer.concat(chunks);
  };
}
function ssDecoder(method, password, onSalt = () => {
}) {
  let pending = Buffer.alloc(0), cipher, size, saltToCheck;
  const saltSize = method === "aes-128-gcm" ? 16 : 32;
  return (data) => {
    pending = Buffer.concat([pending, data]);
    const chunks = [];
    if (!cipher) {
      if (pending.length < saltSize) return chunks;
      const salt = pending.subarray(0, saltSize);
      saltToCheck = salt;
      cipher = ssCipher(method, password, salt);
      pending = pending.subarray(saltSize);
    }
    while (true) {
      if (size === void 0) {
        if (pending.length < 18) break;
        size = cipher.decrypt(pending.subarray(0, 18)).readUInt16BE();
        pending = pending.subarray(18);
        if (saltToCheck) {
          onSalt(saltToCheck);
          saltToCheck = null;
        }
        if (size > 16383) throw new Error("Invalid Shadowsocks chunk length");
      }
      if (pending.length < size + 16) break;
      chunks.push(cipher.decrypt(pending.subarray(0, size + 16)));
      pending = pending.subarray(size + 16);
      size = void 0;
    }
    return chunks;
  };
}
function serveShadowsocks(ws, settings, connect2, earlyData) {
  return new Promise((resolve) => {
    let socket, writer, closed = false, header = Buffer.alloc(0), queued = 0;
    const timer = setTimeout(() => close(), 1e4);
    const close = () => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      try {
        Promise.resolve(socket?.close()).catch(() => {
        });
      } catch {
      }
      try {
        ws.close(1e3, "Closed");
      } catch {
      }
      resolve();
    };
    const encode2 = ssEncoder(settings.ssMethod, settings.ssPassword);
    const decode2 = ssDecoder(settings.ssMethod, settings.ssPassword, (salt) => {
      const now = Date.now();
      for (const [key2, expiry] of salts) if (expiry < now) salts.delete(key2);
      const key = createHash("sha256").update(settings.ssPassword).update(salt).digest("hex");
      if (salts.has(key) || salts.size >= 1e4) throw new Error("Replay or capacity limit");
      salts.set(key, now + 6e5);
    });
    async function process(data) {
      if (closed) return;
      for (const chunk of decode2(Buffer.from(data))) {
        if (!writer) {
          header = Buffer.concat([header, chunk]);
          if (!header.length) continue;
          const type = header[0];
          if (type === 3 && header.length < 2) continue;
          const length = type === 1 ? 4 : type === 4 ? 16 : type === 3 ? header[1] : -1;
          if (length < 1) throw new Error("Invalid destination");
          const start = type === 3 ? 2 : 1, end = start + length;
          if (header.length < end + 2) continue;
          const address = header.subarray(start, end);
          const host = type === 1 ? [...address].join(".") : type === 3 ? address.toString() : Array.from({ length: 8 }, (_, i) => address.readUInt16BE(i * 2).toString(16)).join(":");
          const port = header.readUInt16BE(end);
          if (!port) throw new Error("Invalid destination port");
          const payload = header.subarray(end + 2);
          header = Buffer.alloc(0);
          const open = async (viaRelay) => {
            if (socket) {
              try {
                writer?.releaseLock();
              } catch {
              }
              try {
                socket.close();
              } catch {
              }
            }
            try {
              socket = await connect2(host, port, viaRelay);
            } catch (error3) {
              if (!viaRelay && connect2.canRelay) return open(true);
              throw error3;
            }
            if (viaRelay || !connect2.canRelay) socket.closed?.catch(close);
            if (closed) {
              await socket.close();
              return;
            }
            clearTimeout(timer);
            writer = socket.writable.getWriter();
            void (async () => {
              const reader = socket.readable.getReader();
              let received = false;
              try {
                while (!closed) {
                  const { value, done } = await reader.read();
                  if (done) break;
                  received = true;
                  ws.send(encode2(value));
                }
              } catch (error3) {
                if (received || viaRelay || !connect2.canRelay) throw error3;
              } finally {
                reader.releaseLock();
              }
              if (!received && !viaRelay && connect2.canRelay && !closed) return open(true);
              close();
            })().catch(close);
            if (payload.length) await writer.write(payload);
          };
          await open(false);
        } else await writer.write(chunk);
      }
    }
    let queue = Promise.resolve();
    const receive = (data) => {
      const size = data.byteLength ?? data.size ?? data.length ?? 0;
      queued += size;
      if (queued > 1048576) {
        close();
        return;
      }
      queue = queue.then(async () => process(data instanceof Blob ? await data.arrayBuffer() : data)).catch((error3) => {
        console.warn("Shadowsocks session failed:", error3.message);
        close();
      }).finally(() => {
        queued -= size;
      });
    };
    ws.addEventListener("message", (event) => receive(event.data));
    ws.addEventListener("close", close);
    ws.addEventListener("error", close);
    if (earlyData?.length) receive(earlyData);
  });
}

// worker.js
import net from "node:net";
import tls from "node:tls";
import { Readable, Writable } from "node:stream";
import { Writable as Writable2 } from "node:stream";
import { EventEmitter } from "node:events";
import { Socket } from "node:net";
import { Socket as Socket2 } from "node:net";
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var sockets_exports = {};
__export(sockets_exports, {
  connect: () => connect,
  default: () => sockets_default
});
function connect(address, options = {}) {
  let hostname, port, secure = options.secureTransport === "on";
  if (typeof address === "string") {
    const parts = address.split(":");
    hostname = parts[0];
    port = parseInt(parts[1] || "80", 10);
  } else if (typeof address === "object" && address !== null) {
    hostname = String(address.hostname || address.host || "127.0.0.1").replace(/^\[|\]$/g, "");
    port = typeof address.port === "number" ? address.port : parseInt(address.port || "80", 10);
    secure ||= address.secureTransport === "on" || address.secureTransport === "starttls";
  } else {
    throw new Error("Invalid address argument for connect()");
  }
  let sock;
  if (secure) {
    sock = tls.connect({ host: hostname, port, rejectUnauthorized: false });
  } else {
    sock = net.createConnection({ host: hostname, port });
  }
  sock.setNoDelay(true);
  const opened = new Promise((resolve, reject) => {
    sock.once("connect", () => resolve({ remoteAddress: sock.remoteAddress, remotePort: sock.remotePort }));
    sock.once("secureConnect", () => resolve({ remoteAddress: sock.remoteAddress, remotePort: sock.remotePort }));
    sock.once("error", (err) => reject(err));
  });
  const closed = new Promise((resolve) => {
    sock.once("close", (hadError) => resolve({ hadError }));
    sock.once("end", () => resolve({ hadError: false }));
  });
  const readable = Readable.toWeb(sock);
  const writable = Writable.toWeb(sock);
  return {
    opened,
    closed,
    readable,
    writable,
    close: /* @__PURE__ */ __name(() => {
      try {
        sock.destroy();
      } catch (_) {
      }
    }, "close"),
    startTls: /* @__PURE__ */ __name((tlsOptions = {}) => {
      const tlsSocket = tls.connect({
        socket: sock,
        host: hostname,
        rejectUnauthorized: false,
        ...tlsOptions
      });
      return {
        readable: Readable.toWeb(tlsSocket),
        writable: Writable.toWeb(tlsSocket)
      };
    }, "startTls")
  };
}
var sockets_default;
var init_sockets = __esm({
  "../lib/sockets.mjs"() {
    init_functionsRoutes_0_6698010974737841();
    __name(connect, "connect");
    sockets_default = { connect };
  }
});
function createNotImplementedError(name) {
  return new Error(`[unenv] ${name} is not implemented yet!`);
}
function notImplemented(name) {
  const fn = /* @__PURE__ */ __name2(() => {
    throw createNotImplementedError(name);
  }, "fn");
  return Object.assign(fn, { __unenv__: true });
}
function notImplementedClass(name) {
  return class {
    __unenv__ = true;
    constructor() {
      throw new Error(`[unenv] ${name} is not implemented yet!`);
    }
  };
}
function getKV(env2) {
  return env2.BK_KV ?? env2.WD_KV;
}
function generateRandomToken(length = 16) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}
function generateRandomPassword(length = 12) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  let result = "";
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}
function invalidateSettingsCache() {
  cachedSettings = null;
  cachedSettingsTimestamp = 0;
}
async function getOrInitSettings(env2) {
  const now = Date.now();
  if (cachedSettings && now - cachedSettingsTimestamp < CACHE_TTL_MS) {
    return cachedSettings;
  }
  const kv = getKV(env2);
  let vlessUuid = null;
  let trojanPassword = null;
  let proxyPath = null;
  let proxyIp = null;
  let relayIp = null;
  let nat64Str = null;
  let subToken = null;
  let dnsDoH = null;
  let allowLANConnectionStr = null;
  let fragmentEnabledStr = null;
  let fragmentPackets = null;
  let fragmentLength = null;
  let fragmentInterval = null;
  let routingPresetStr = null;
  let warpPrivateKey = null;
  let warpPeerPublicKey = null;
  let warpIPv6 = null;
  let warpReserved = null;
  let warpProEnabledStr = null;
  let warpAmneziaVersion = null;
  let warpNoiseCount = null;
  let warpNoiseMin = null;
  let warpNoiseMax = null;
  let warpNoiseDelay = null;
  let warpAmneziaS1 = null;
  let warpAmneziaS2 = null;
  let warpAmneziaH1 = null;
  let warpAmneziaH2 = null;
  let warpAmneziaH3 = null;
  let warpAmneziaH4 = null;
  let chainEnabledStr = null;
  let chainTypeStr = null;
  let chainAddress = null;
  let chainPortStr = null;
  let chainAuth = null;
  let chainPath = null;
  let chainSecurityStr = null;
  let chainTransportStr = null;
  let chainSni = null;
  let chainHost = null;
  let nodeShareToken = null;
  let domainFrontingEnabledStr = null;
  let frontingSni = null;
  let frontingHost = null;
  let frontingCleanIps = null;
  let staticIpList = null;
  let openvpnEnabledStr = null;
  let openvpnPort = null;
  let openvpnProto = null;
  let openvpnCipher = null;
  let anytlsFingerprint = null;
  let anytlsAlpn = null;
  let xhttpEnabledStr = null;
  let xhttpPath = null;
  let xhttpMode = null;
  let httpUpgradeEnabledStr = null;
  let ssEnabledStr = null;
  let ssPassword = null;
  let ssMethod = null;
  let dnsCustom = null;
  let clientDnsSettings = null;
  let kvReadFailed = false;
  if (kv) {
    try {
      [
        vlessUuid,
        trojanPassword,
        proxyPath,
        proxyIp,
        relayIp,
        nat64Str,
        subToken,
        dnsDoH,
        allowLANConnectionStr,
        fragmentEnabledStr,
        fragmentPackets,
        fragmentLength,
        fragmentInterval,
        routingPresetStr,
        warpPrivateKey,
        warpPeerPublicKey,
        warpIPv6,
        warpReserved,
        warpProEnabledStr,
        warpAmneziaVersion,
        warpNoiseCount,
        warpNoiseMin,
        warpNoiseMax,
        warpNoiseDelay,
        warpAmneziaS1,
        warpAmneziaS2,
        warpAmneziaH1,
        warpAmneziaH2,
        warpAmneziaH3,
        warpAmneziaH4,
        chainEnabledStr,
        chainTypeStr,
        chainAddress,
        chainPortStr,
        chainAuth,
        chainPath,
        chainSecurityStr,
        chainTransportStr,
        chainSni,
        chainHost,
        nodeShareToken,
        domainFrontingEnabledStr,
        frontingSni,
        frontingHost,
        frontingCleanIps,
        staticIpList,
        openvpnEnabledStr,
        openvpnPort,
        openvpnProto,
        openvpnCipher,
        anytlsFingerprint,
        anytlsAlpn,
        xhttpEnabledStr,
        xhttpPath,
        xhttpMode,
        httpUpgradeEnabledStr,
        ssEnabledStr,
        ssPassword,
        ssMethod,
        dnsCustom,
        clientDnsSettings
      ] = await Promise.all([
        kv.get(KV_KEYS.vlessUuid),
        kv.get(KV_KEYS.trojanPassword),
        kv.get(KV_KEYS.proxyPath),
        kv.get(KV_KEYS.proxyIp),
        kv.get(KV_KEYS.relayIp),
        kv.get(KV_KEYS.nat64Prefixes),
        kv.get(KV_KEYS.subToken),
        kv.get(KV_KEYS.dnsDoH),
        kv.get(KV_KEYS.allowLANConnection),
        kv.get(KV_KEYS.fragmentEnabled),
        kv.get(KV_KEYS.fragmentPackets),
        kv.get(KV_KEYS.fragmentLength),
        kv.get(KV_KEYS.fragmentInterval),
        kv.get(KV_KEYS.routingPreset),
        kv.get(KV_KEYS.warpPrivateKey),
        kv.get(KV_KEYS.warpPeerPublicKey),
        kv.get(KV_KEYS.warpIPv6),
        kv.get(KV_KEYS.warpReserved),
        kv.get(KV_KEYS.warpProEnabled),
        kv.get(KV_KEYS.warpAmneziaVersion),
        kv.get(KV_KEYS.warpNoiseCount),
        kv.get(KV_KEYS.warpNoiseMin),
        kv.get(KV_KEYS.warpNoiseMax),
        kv.get(KV_KEYS.warpNoiseDelay),
        kv.get(KV_KEYS.warpAmneziaS1),
        kv.get(KV_KEYS.warpAmneziaS2),
        kv.get(KV_KEYS.warpAmneziaH1),
        kv.get(KV_KEYS.warpAmneziaH2),
        kv.get(KV_KEYS.warpAmneziaH3),
        kv.get(KV_KEYS.warpAmneziaH4),
        kv.get(KV_KEYS.chainEnabled),
        kv.get(KV_KEYS.chainType),
        kv.get(KV_KEYS.chainAddress),
        kv.get(KV_KEYS.chainPort),
        kv.get(KV_KEYS.chainAuth),
        kv.get(KV_KEYS.chainPath),
        kv.get(KV_KEYS.chainSecurity),
        kv.get(KV_KEYS.chainTransport),
        kv.get(KV_KEYS.chainSni),
        kv.get(KV_KEYS.chainHost),
        kv.get(KV_KEYS.nodeShareToken),
        kv.get(KV_KEYS.domainFrontingEnabled),
        kv.get(KV_KEYS.frontingSni),
        kv.get(KV_KEYS.frontingHost),
        kv.get(KV_KEYS.frontingCleanIps),
        kv.get(KV_KEYS.staticIpList),
        kv.get(KV_KEYS.openvpnEnabled),
        kv.get(KV_KEYS.openvpnPort),
        kv.get(KV_KEYS.openvpnProto),
        kv.get(KV_KEYS.openvpnCipher),
        kv.get(KV_KEYS.anytlsFingerprint),
        kv.get(KV_KEYS.anytlsAlpn),
        kv.get(KV_KEYS.xhttpEnabled),
        kv.get(KV_KEYS.xhttpPath),
        kv.get(KV_KEYS.xhttpMode),
        kv.get(KV_KEYS.httpUpgradeEnabled),
        kv.get(KV_KEYS.ssEnabled),
        kv.get(KV_KEYS.ssPassword),
        kv.get(KV_KEYS.ssMethod),
        kv.get(KV_KEYS.dnsCustom),
        kv.get(KV_KEYS.clientDnsSettings)
      ]);
    } catch (err) {
      kvReadFailed = true;
      console.warn("Could not read settings from KV:", err);
    }
  }
  if (kvReadFailed) {
    if (cachedSettings) {
      cachedSettingsTimestamp = now - CACHE_TTL_MS + 60000;
      return cachedSettings;
    }
    throw new Error("Settings storage (KV) is temporarily unavailable - quota or network error. Retry later.");
  }
  const missingKeysToPersist = [];
  if (!vlessUuid || vlessUuid.trim().length === 0) {
    vlessUuid = crypto.randomUUID();
    missingKeysToPersist.push({ key: KV_KEYS.vlessUuid, value: vlessUuid });
  }
  if (!trojanPassword || trojanPassword.trim().length === 0) {
    trojanPassword = `wd_${generateRandomPassword(16)}`;
    missingKeysToPersist.push({ key: KV_KEYS.trojanPassword, value: trojanPassword });
  }
  if (!subToken || subToken.trim().length === 0) {
    subToken = generateRandomToken(16);
    missingKeysToPersist.push({ key: KV_KEYS.subToken, value: subToken });
  }
  if (!nodeShareToken || nodeShareToken.trim().length === 0) {
    nodeShareToken = generateRandomToken(24);
    missingKeysToPersist.push({ key: KV_KEYS.nodeShareToken, value: nodeShareToken });
  }
  if (missingKeysToPersist.length > 0 && kv) {
    for (const item of missingKeysToPersist) {
      try {
        await kv.put(item.key, item.value);
      } catch (saveErr) {
        console.warn(`Failed to persist initial key ${item.key} to KV:`, saveErr?.message || saveErr);
        if (saveErr?.message?.toLowerCase().includes("limit exceeded") || saveErr?.message?.toLowerCase().includes("quota")) {
          console.error("Cloudflare KV daily put limit exceeded during first-run initialization.");
          break;
        }
      }
    }
  }
  const effectiveProxyPath = proxyPath && proxyPath.trim().length > 0 ? proxyPath.trim().startsWith("/") ? proxyPath.trim() : `/${proxyPath.trim()}` : APP_CONFIG.defaultProxyPath;
  const effectiveDnsDoH = dnsDoH && dnsDoH.trim().length > 0 ? dnsDoH.trim() : APP_CONFIG.defaultDohUpstream;
  const effectiveFragmentPackets = fragmentPackets && fragmentPackets.trim().length > 0 ? fragmentPackets.trim() : "tlshello";
  const effectiveFragmentLength = fragmentLength && fragmentLength.trim().length > 0 ? fragmentLength.trim() : "100-200";
  const effectiveFragmentInterval = fragmentInterval && fragmentInterval.trim().length > 0 ? fragmentInterval.trim() : "10-20";
  const validRoutingPresets = ["off", ...Object.keys(BYPASS_PRESETS), "block-ads"];
  const routingPreset = routingPresetStr && validRoutingPresets.includes(routingPresetStr) ? routingPresetStr : "off";
  const effectiveWarpPeerKey = warpPeerPublicKey && warpPeerPublicKey.trim().length > 0 ? warpPeerPublicKey.trim() : APP_CONFIG.defaultWarpPeerPublicKey;
  const validChainTypes = ["vless", "trojan", "ss", "socks", "http"];
  const chainType = chainTypeStr && validChainTypes.includes(chainTypeStr) ? chainTypeStr : "socks";
  const chainPort = chainPortStr ? parseInt(chainPortStr, 10) || 1080 : 1080;
  const settings = {
    vlessUuid: vlessUuid.trim(),
    trojanPassword: trojanPassword.trim(),
    proxyPath: effectiveProxyPath,
    proxyIp: proxyIp ? proxyIp.trim() : "",
    // Panel value wins; RELAY_IP is what deploy.mjs sets on Workers/Pages.
    relayIp: relayIp && relayIp.trim() ? relayIp.trim() : String(env2.RELAY_IP || "").trim(),
    // Used when no relay is set: public NAT64 gateways reach Cloudflare IPs over IPv6 (BPB's method).
    nat64Prefixes: String(nat64Str ?? env2.NAT64_PREFIXES ?? DEFAULT_NAT64_PREFIXES).split(/[\s,]+/).map((p) => p.replace(/^\[|\]$/g, "").replace(/\/96$/, "")).filter((p) => p.endsWith("::")),
    subToken: subToken.trim(),
    dnsDoH: effectiveDnsDoH,
    allowLANConnection: allowLANConnectionStr === "true",
    fragmentEnabled: fragmentEnabledStr === "true",
    fragmentPackets: effectiveFragmentPackets,
    fragmentLength: effectiveFragmentLength,
    fragmentInterval: effectiveFragmentInterval,
    routingPreset,
    warpPrivateKey: warpPrivateKey ? warpPrivateKey.trim() : "",
    warpPeerPublicKey: effectiveWarpPeerKey,
    // WARP registration returns a bare IPv6; sing-box and WireGuard reject it without a prefix.
    warpIPv6: warpIPv6 && warpIPv6.trim() ? warpIPv6.includes("/") ? warpIPv6.trim() : `${warpIPv6.trim()}/128` : "",
    warpReserved: warpReserved ? warpReserved.trim() : "",
    // Warp Pro
    warpProEnabled: warpProEnabledStr === "true",
    warpAmneziaVersion: warpAmneziaVersion ? warpAmneziaVersion.trim() : "2",
    warpNoiseCount: warpNoiseCount ? warpNoiseCount.trim() : "5",
    warpNoiseMin: warpNoiseMin ? warpNoiseMin.trim() : "10",
    warpNoiseMax: warpNoiseMax ? warpNoiseMax.trim() : "50",
    warpNoiseDelay: warpNoiseDelay ? warpNoiseDelay.trim() : "20",
    warpAmneziaS1: warpAmneziaS1 ? warpAmneziaS1.trim() : "15",
    warpAmneziaS2: warpAmneziaS2 ? warpAmneziaS2.trim() : "25",
    warpAmneziaH1: warpAmneziaH1 ? warpAmneziaH1.trim() : "1",
    warpAmneziaH2: warpAmneziaH2 ? warpAmneziaH2.trim() : "2",
    warpAmneziaH3: warpAmneziaH3 ? warpAmneziaH3.trim() : "3",
    warpAmneziaH4: warpAmneziaH4 ? warpAmneziaH4.trim() : "4",
    // Chain Proxy
    chainEnabled: chainEnabledStr === "true",
    chainType,
    chainAddress: chainAddress ? chainAddress.trim() : "",
    chainPort,
    chainAuth: chainAuth ? chainAuth.trim() : "",
    chainPath: chainPath ? chainPath.trim() : "",
    chainSecurity: chainSecurityStr === "tls" ? "tls" : "none",
    chainTransport: chainTransportStr === "ws" ? "ws" : "tcp",
    chainSni: chainSni ? chainSni.trim() : "",
    chainHost: chainHost ? chainHost.trim() : "",
    // Node Share
    nodeShareToken: nodeShareToken.trim(),
    // New Feature Defaults
    domainFrontingEnabled: domainFrontingEnabledStr === "true",
    frontingSni: frontingSni ? frontingSni.trim() : "cdnjs.cloudflare.com",
    frontingHost: frontingHost ? frontingHost.trim() : "",
    frontingCleanIps: frontingCleanIps ? frontingCleanIps.trim() : "104.16.1.1,104.19.241.93,172.67.180.1,162.159.138.6",
    staticIpList: staticIpList ? staticIpList.trim() : "",
    openvpnEnabled: openvpnEnabledStr !== "false",
    openvpnPort: openvpnPort ? openvpnPort.trim() : "443",
    openvpnProto: openvpnProto ? openvpnProto.trim() : "tcp",
    openvpnCipher: openvpnCipher ? openvpnCipher.trim() : "AES-256-GCM",
    anytlsFingerprint: anytlsFingerprint ? anytlsFingerprint.trim() : "chrome",
    anytlsAlpn: anytlsAlpn ? anytlsAlpn.trim() : "h2,http/1.1",
    xhttpEnabled: xhttpEnabledStr !== "false",
    xhttpPath: xhttpPath ? xhttpPath.trim() : "/bk-xhttp",
    xhttpMode: xhttpMode ? xhttpMode.trim() : "stream-one",
    httpUpgradeEnabled: httpUpgradeEnabledStr !== "false",
    ssEnabled: ssEnabledStr !== "false",
    ssPassword: ssPassword ? ssPassword.trim() : "HEX-" + (vlessUuid ? vlessUuid.slice(0, 8) : "Pass2026"),
    ssMethod: ssMethod ? ssMethod.trim() : "chacha20-ietf-poly1305",
    dnsCustom: dnsCustom ? dnsCustom.trim() : "",
    clientDns: readDns(clientDnsSettings)
  };
  cachedSettings = settings;
  cachedSettingsTimestamp = now;
  return settings;
}
function handleHealth(request, env2) {
  const healthData = {
    ok: true,
    name: "HEX",
    version: APP_CONFIG.version,
    tagline: APP_CONFIG.tagline,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    status: "healthy"
  };
  return new Response(JSON.stringify(healthData, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store"
    }
  });
}
async function handleProxyDebug(request, env2) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  const settings = await getOrInitSettings(env2);
  if (!token || !constantTimeEquals(token, settings.subToken)) {
    return new Response(
      JSON.stringify(
        {
          error: "Unauthorized",
          message: "A valid ?token=<subToken> query parameter is required."
        },
        null,
        2
      ),
      {
        status: 401,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      }
    );
  }
  const debugData = {
    ok: true,
    version: APP_CONFIG.version,
    proxyPath: settings.proxyPath,
    uuidPrefix8: settings.vlessUuid.slice(0, 8),
    earlyDataSupported: true,
    ports: [443, 2053, 2083, 2087, 2096, 8443]
  };
  return new Response(JSON.stringify(debugData, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers) {
    buf.set(buffer, i);
    i += buffer.length;
  }
  return buf;
}
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function getNamedCurve(alg) {
  switch (alg) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkSigCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      if (!isAlgorithm(key.algorithm, "HMAC"))
        throw unusable("HMAC");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5"))
        throw unusable("RSASSA-PKCS1-v1_5");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm(key.algorithm, "RSA-PSS"))
        throw unusable("RSA-PSS");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "EdDSA": {
      if (key.algorithm.name !== "Ed25519" && key.algorithm.name !== "Ed448") {
        throw unusable("Ed25519 or Ed448");
      }
      break;
    }
    case "Ed25519": {
      if (!isAlgorithm(key.algorithm, "Ed25519"))
        throw unusable("Ed25519");
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA"))
        throw unusable("ECDSA");
      const expected = getNamedCurve(alg);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected)
        throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}
function message(msg, actual, ...types2) {
  types2 = types2.filter(Boolean);
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
function withAlg(alg, actual, ...types2) {
  return message(`Key for the ${alg} algorithm must be `, actual, ...types2);
}
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
function isJWK(key) {
  return isObject(key) && typeof key.kty === "string";
}
function isPrivateJWK(key) {
  return key.kty !== "oct" && typeof key.d === "string";
}
function isPublicJWK(key) {
  return key.kty !== "oct" && typeof key.d === "undefined";
}
function isSecretJWK(key) {
  return isJWK(key) && key.kty === "oct" && typeof key.k === "string";
}
function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;
  switch (jwk.kty) {
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES384":
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES512":
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: "ECDH", namedCurve: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519":
          algorithm = { name: "Ed25519" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "EdDSA":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return { algorithm, keyUsages };
}
async function importJWK(jwk, alg) {
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  alg || (alg = jwk.alg);
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      return decode(jwk.k);
    case "RSA":
      if ("oth" in jwk && jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
    case "EC":
    case "OKP":
      return jwk_to_key_default({ ...jwk, alg });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}
function checkKeyType(allowJwk, alg, key, usage) {
  const symmetric = alg.startsWith("HS") || alg === "dir" || alg.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg);
  if (symmetric) {
    symmetricTypeCheck(alg, key, usage, allowJwk);
  } else {
    asymmetricTypeCheck(alg, key, usage, allowJwk);
  }
}
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
function subtleDsa(alg, algorithm) {
  const hash = `SHA-${alg.slice(-3)}`;
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512":
      return { hash, name: "HMAC" };
    case "PS256":
    case "PS384":
    case "PS512":
      return { hash, name: "RSA-PSS", saltLength: alg.slice(-3) >> 3 };
    case "RS256":
    case "RS384":
    case "RS512":
      return { hash, name: "RSASSA-PKCS1-v1_5" };
    case "ES256":
    case "ES384":
    case "ES512":
      return { hash, name: "ECDSA", namedCurve: algorithm.namedCurve };
    case "Ed25519":
      return { name: "Ed25519" };
    case "EdDSA":
      return { name: algorithm.name };
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}
async function getCryptoKey(alg, key, usage) {
  if (usage === "sign") {
    key = await normalize_key_default.normalizePrivateKey(key, alg);
  }
  if (usage === "verify") {
    key = await normalize_key_default.normalizePublicKey(key, alg);
  }
  if (isCryptoKey(key)) {
    checkSigCryptoKey(key, alg, usage);
    return key;
  }
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new TypeError(invalid_key_input_default(key, ...types));
    }
    return webcrypto_default.subtle.importKey("raw", key, { hash: `SHA-${alg.slice(-3)}`, name: "HMAC" }, false, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array", "JSON Web Key"));
}
async function flattenedVerify(jws, key, options) {
  if (!isObject(jws)) {
    throw new JWSInvalid("Flattened JWS must be an object");
  }
  if (jws.protected === void 0 && jws.header === void 0) {
    throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
  }
  if (jws.protected !== void 0 && typeof jws.protected !== "string") {
    throw new JWSInvalid("JWS Protected Header incorrect type");
  }
  if (jws.payload === void 0) {
    throw new JWSInvalid("JWS Payload missing");
  }
  if (typeof jws.signature !== "string") {
    throw new JWSInvalid("JWS Signature missing or incorrect type");
  }
  if (jws.header !== void 0 && !isObject(jws.header)) {
    throw new JWSInvalid("JWS Unprotected Header incorrect type");
  }
  let parsedProt = {};
  if (jws.protected) {
    try {
      const protectedHeader = decode(jws.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader));
    } catch {
      throw new JWSInvalid("JWS Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jws.header)) {
    throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jws.header
  };
  const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, parsedProt, joseHeader);
  let b64 = true;
  if (extensions.has("b64")) {
    b64 = parsedProt.b64;
    if (typeof b64 !== "boolean") {
      throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
    }
  }
  const { alg } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  }
  const algorithms = options && validate_algorithms_default("algorithms", options.algorithms);
  if (algorithms && !algorithms.has(alg)) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (b64) {
    if (typeof jws.payload !== "string") {
      throw new JWSInvalid("JWS Payload must be a string");
    }
  } else if (typeof jws.payload !== "string" && !(jws.payload instanceof Uint8Array)) {
    throw new JWSInvalid("JWS Payload must be a string or an Uint8Array instance");
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jws);
    resolvedKey = true;
    checkKeyTypeWithJwk(alg, key, "verify");
    if (isJWK(key)) {
      key = await importJWK(key, alg);
    }
  } else {
    checkKeyTypeWithJwk(alg, key, "verify");
  }
  const data = concat(encoder.encode(jws.protected ?? ""), encoder.encode("."), typeof jws.payload === "string" ? encoder.encode(jws.payload) : jws.payload);
  let signature;
  try {
    signature = decode(jws.signature);
  } catch {
    throw new JWSInvalid("Failed to base64url decode the signature");
  }
  const verified = await verify_default(alg, key, signature, data);
  if (!verified) {
    throw new JWSSignatureVerificationFailed();
  }
  let payload;
  if (b64) {
    try {
      payload = decode(jws.payload);
    } catch {
      throw new JWSInvalid("Failed to base64url decode the payload");
    }
  } else if (typeof jws.payload === "string") {
    payload = encoder.encode(jws.payload);
  } else {
    payload = jws.payload;
  }
  const result = { payload };
  if (jws.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jws.header !== void 0) {
    result.unprotectedHeader = jws.header;
  }
  if (resolvedKey) {
    return { ...result, key };
  }
  return result;
}
async function compactVerify(jws, key, options) {
  if (jws instanceof Uint8Array) {
    jws = decoder.decode(jws);
  }
  if (typeof jws !== "string") {
    throw new JWSInvalid("Compact JWS must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split(".");
  if (length !== 3) {
    throw new JWSInvalid("Invalid Compact JWS");
  }
  const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
  const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: verified.key };
  }
  return result;
}
async function jwtVerify(jwt, key, options) {
  const verified = await compactVerify(jwt, key, options);
  if (verified.protectedHeader.crit?.includes("b64") && verified.protectedHeader.b64 === false) {
    throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
  }
  const payload = jwt_claims_set_default(verified.protectedHeader, verified.payload, options);
  const result = { payload, protectedHeader: verified.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: verified.key };
  }
  return result;
}
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
async function getJwtSecret(env2) {
  if (cachedJwtSecret) {
    return cachedJwtSecret;
  }
  if (env2.JWT_SECRET && env2.JWT_SECRET.trim().length > 0) {
    cachedJwtSecret = env2.JWT_SECRET.trim();
    return cachedJwtSecret;
  }
  const kv = getKV(env2);
  if (kv) {
    try {
      const stored = await kv.get(KV_KEYS.jwtSecret);
      if (stored && stored.trim().length >= 32) {
        cachedJwtSecret = stored.trim();
        return cachedJwtSecret;
      }
      const randomBytes2 = new Uint8Array(36);
      crypto.getRandomValues(randomBytes2);
      const generated = Array.from(randomBytes2, (b) => b.toString(16).padStart(2, "0")).join("");
      try {
        await kv.put(KV_KEYS.jwtSecret, generated);
      } catch (putErr) {
        console.warn("Could not persist JWT secret to KV:", putErr?.message || putErr);
        if (putErr?.message?.toLowerCase().includes("limit exceeded") || putErr?.message?.toLowerCase().includes("quota")) {
          console.error("Cloudflare KV daily put limit exceeded when writing JWT secret.");
        }
      }
      cachedJwtSecret = generated;
      return cachedJwtSecret;
    } catch (err) {
      console.warn("Could not read or initialize JWT secret in KV:", err);
    }
  }
  if (env2.PANEL_PASSWORD && env2.PANEL_PASSWORD.trim().length > 0) {
    console.warn("\u26A0\uFE0F KV unavailable for JWT secret persistence. Deriving the signing key from PANEL_PASSWORD; set JWT_SECRET explicitly for a stable, independent key.");
    const material = new TextEncoder().encode(`hex-jwt-derivation-v1:${env2.PANEL_PASSWORD.trim()}`);
    const digest = await crypto.subtle.digest("SHA-256", material);
    cachedJwtSecret = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    return cachedJwtSecret;
  }
  throw new Error("No JWT signing key available: configure a KV namespace (BK_KV), or set JWT_SECRET, or set PANEL_PASSWORD.");
}
function getSecretKey(secret) {
  if (!secret) throw new Error("Refusing to sign or verify a session with an empty key.");
  return new TextEncoder().encode(secret);
}
async function createSessionToken(user = "admin", secretOrEnv) {
  const secret = typeof secretOrEnv === "string" ? secretOrEnv : await getJwtSecret(secretOrEnv);
  const key = getSecretKey(secret);
  return await new SignJWT({ user }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime(`${APP_CONFIG.sessionMaxAgeSeconds}s`).sign(key);
}
async function verifySessionToken(token, secretOrEnv) {
  try {
    const secret = typeof secretOrEnv === "string" ? secretOrEnv : await getJwtSecret(secretOrEnv);
    const key = getSecretKey(secret);
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["HS256"]
    });
    return {
      user: String(payload.user || "admin"),
      iat: payload.iat,
      exp: payload.exp
    };
  } catch {
    return null;
  }
}
function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader)
    return {};
  const cookies = {};
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const [name, ...rest] = pair.trim().split("=");
    if (name) {
      cookies[name] = rest.join("=");
    }
  }
  return cookies;
}
function getSessionCookie(request) {
  const cookies = parseCookies(request);
  return cookies[APP_CONFIG.cookieName] || cookies[APP_CONFIG.legacyCookieName];
}
function createSessionCookie(token, isSecure = false) {
  const secureFlag = isSecure ? " Secure;" : "";
  return `${APP_CONFIG.cookieName}=${token}; Path=/; Max-Age=${APP_CONFIG.sessionMaxAgeSeconds}; HttpOnly; SameSite=Lax;${secureFlag}`;
}
function createClearCookie() {
  return `${APP_CONFIG.cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax;`;
}
function withSecurityHeaders(response) {
  if (!response || response.status === 101 || response.webSocket) {
    return response;
  }
  const headers = new Headers(response.headers);
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  const isHtml = (headers.get("Content-Type") || "").includes("text/html");
  if (isHtml) {
    headers.set("Content-Security-Policy", [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "object-src 'none'"
    ].join("; "));
  }
  try {
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  } catch (e) {
    return response;
  }
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"'`]/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "`": "&#96;"
  })[ch]);
}
function constantTimeEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
function invalidatePasswordCache() {
  cachedPasswordConfigured = null;
  cachedAdminPassword = null;
}
async function hasConfiguredPassword(env2) {
  if (env2.PANEL_PASSWORD && env2.PANEL_PASSWORD.trim().length > 0) {
    return true;
  }
  if (cachedPasswordConfigured !== null) {
    return cachedPasswordConfigured;
  }
  const kv = getKV(env2);
  if (kv) {
    try {
      const kvPassword = await kv.get(KV_KEYS.adminPassword);
      if (kvPassword && kvPassword.trim().length > 0) {
        cachedAdminPassword = kvPassword.trim();
        cachedPasswordConfigured = true;
        return true;
      }
    } catch (err) {
      console.warn("Could not check password from KV:", err);
    }
  }
  cachedPasswordConfigured = false;
  return false;
}
async function getExpectedPassword(env2) {
  if (cachedAdminPassword) {
    return { password: cachedAdminPassword, isConfigured: true };
  }
  const kv = getKV(env2);
  if (kv) {
    try {
      const kvPassword = await kv.get(KV_KEYS.adminPassword);
      if (kvPassword && kvPassword.trim().length > 0) {
        cachedAdminPassword = kvPassword.trim();
        cachedPasswordConfigured = true;
        return { password: cachedAdminPassword, isConfigured: true };
      }
    } catch (err) {
      console.warn("Could not read password from KV:", err);
    }
  }
  if (env2.PANEL_PASSWORD && env2.PANEL_PASSWORD.trim().length > 0) {
    cachedAdminPassword = env2.PANEL_PASSWORD.trim();
    cachedPasswordConfigured = true;
    return { password: cachedAdminPassword, isConfigured: true };
  }
  return { isConfigured: false };
}
var PBKDF2_ITERATIONS = 1e5;
var PBKDF2_PREFIX = "pbkdf2$";
function bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function derivePasswordHash(password, salt, iterations = PBKDF2_ITERATIONS) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256
  );
  return new Uint8Array(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePasswordHash(password, salt);
  return `${PBKDF2_PREFIX}${PBKDF2_ITERATIONS}$${bytesToB64(salt)}$${bytesToB64(hash)}`;
}
function isHashedPassword(stored) {
  return typeof stored === "string" && stored.startsWith(PBKDF2_PREFIX);
}
async function verifyPasswordHash(submitted, stored) {
  try {
    const [, iterStr, saltB64, hashB64] = stored.split("$");
    const iterations = Number(iterStr);
    if (!Number.isFinite(iterations) || iterations < 1e4) return false;
    const derived = await derivePasswordHash(submitted, b64ToBytes(saltB64), iterations);
    return constantTimeEquals(bytesToB64(derived), hashB64);
  } catch {
    return false;
  }
}
async function verifyPassword(submitted, env2) {
  if (!submitted)
    return false;
  const { password, isConfigured } = await getExpectedPassword(env2);
  if (!isConfigured || !password) {
    return false;
  }
  const candidate = submitted.trim();
  if (isHashedPassword(password)) {
    return await verifyPasswordHash(candidate, password);
  }
  const ok = constantTimeEquals(candidate, password);
  if (ok) {
    const kv = getKV(env2);
    if (kv) {
      try {
        const stored = await kv.get(KV_KEYS.adminPassword);
        if (stored && !isHashedPassword(stored)) {
          const upgraded = await hashPassword(candidate);
          await kv.put(KV_KEYS.adminPassword, upgraded);
          cachedAdminPassword = upgraded;
        }
      } catch (err) {
        console.warn("Could not upgrade stored password to a hash:", err?.message || err);
      }
    }
  }
  return ok;
}
async function setPassword(newPassword, env2) {
  if (!newPassword || newPassword.trim().length < 8) {
    throw new Error("Password must be at least 8 characters long");
  }
  const kv = getKV(env2);
  if (!kv) {
    throw new Error("KV binding (BK_KV or WD_KV) is not available");
  }
  try {
    const record = await hashPassword(newPassword.trim());
    await kv.put(KV_KEYS.adminPassword, record);
    cachedAdminPassword = record;
    cachedPasswordConfigured = true;
    return true;
  } catch (err) {
    const msg = err?.message || String(err);
    if (msg.toLowerCase().includes("limit exceeded") || msg.toLowerCase().includes("quota")) {
      throw new Error("KV write quota exceeded \u2014 try again after daily reset");
    }
    throw new Error(`Failed to save password to KV: ${msg}`);
  }
}
function renderPageLayout(options) {
  return `<!DOCTYPE html>
<html lang="en" id="htmlRoot">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
  <title>${options.title} - HEX Panel</title>
  <script>
    (function() {
      try {
        var THEMES = ['theme-1', 'theme-2', 'theme-3', 'theme-4', 'theme-5'];
        var params = new URLSearchParams(window.location.search);
        var isNewLogin = params.get('login') === 'success' || params.get('setup') === 'success';
        var currentTheme = sessionStorage.getItem('hex-current-session-theme');
        if (currentTheme && THEMES.indexOf(currentTheme) === -1) currentTheme = null;
        if (!currentTheme || isNewLogin) {
          var lastLoginTheme = localStorage.getItem('hex-last-login-theme');
          var candidates = THEMES.filter(function(t) { return t !== lastLoginTheme; });
          var picked = candidates[Math.floor(Math.random() * candidates.length)] || THEMES[0];
          currentTheme = picked;
          sessionStorage.setItem('hex-current-session-theme', currentTheme);
          localStorage.setItem('hex-last-login-theme', currentTheme);
          localStorage.setItem('hex-current-session-theme', currentTheme);
        }
        document.documentElement.setAttribute('data-theme', currentTheme);
      } catch (e) {
        document.documentElement.setAttribute('data-theme', 'theme-1');
      }
    })();
  </script>
  <style>
    ${BASE_STYLES}
  </style>
</head>
<body>
  ${options.content}

  <div id="toast" class="toast-msg">
    <span>\u2728 Copied to clipboard!</span>
  </div>

  <!-- Responsive QR Code Modal -->
  <div id="qrModal" class="modal-backdrop" onclick="closeQrModal(event)">
    <div class="modal-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h3 id="qrModalTitle" style="font-size: 15px; font-family: 'Quicksand', sans-serif;">Subscription QR Code</h3>
        <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('qrModal').classList.remove('show')">\u2715</button>
      </div>
      <div style="text-align: center; padding: 6px;">
        <img id="qrModalImg" src="" alt="QR Code" style="max-width: 200px; width: 100%; height: auto; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin: 0 auto; display: block;" />
        <p style="font-size: 11px; color: var(--theme-text-muted); margin-top: 10px; word-break: break-all; font-family: 'JetBrains Mono', monospace; max-height: 60px; overflow-y: auto;" id="qrModalUrl"></p>
      </div>
    </div>
  </div>

  <script>
    // Initialize RTL from localStorage
    (function initRtl() {
      const savedDir = localStorage.getItem('wd_direction') || 'ltr';
      document.getElementById('htmlRoot').setAttribute('dir', savedDir);
      updateRtlButtons(savedDir);
    })();

    function toggleRtl() {
      const html = document.getElementById('htmlRoot');
      const current = html.getAttribute('dir') || 'ltr';
      const next = current === 'rtl' ? 'ltr' : 'rtl';
      html.setAttribute('dir', next);
      localStorage.setItem('wd_direction', next);
      updateRtlButtons(next);
      showToast(next === 'rtl' ? 'RTL Layout Activated' : 'LTR Layout Activated');
    }

    function updateRtlButtons(dir) {
      const btns = document.querySelectorAll('.rtl-toggle-btn');
      btns.forEach(b => {
        b.textContent = dir === 'rtl' ? 'LTR \u21C4' : 'RTL \u21C4';
      });
    }

    function toggleSidebar() {
      const sidebar = document.getElementById('appSidebar');
      const backdrop = document.getElementById('drawerBackdrop');
      if (sidebar && backdrop) {
        const isOpen = sidebar.classList.toggle('open');
        backdrop.classList.toggle('show', isOpen);
      }
    }

    function closeSidebar() {
      const sidebar = document.getElementById('appSidebar');
      const backdrop = document.getElementById('drawerBackdrop');
      if (sidebar && backdrop) {
        sidebar.classList.remove('open');
        backdrop.classList.remove('show');
      }
    }

    function showQrModal(title, url) {
      const modal = document.getElementById('qrModal');
      const titleEl = document.getElementById('qrModalTitle');
      const imgEl = document.getElementById('qrModalImg');
      const urlEl = document.getElementById('qrModalUrl');
      if (titleEl) titleEl.textContent = title;
      if (urlEl) urlEl.textContent = url;
      if (imgEl) imgEl.src = 'https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=' + encodeURIComponent(url);
      if (modal) modal.classList.add('show');
    }

    function closeQrModal(e) {
      if (e.target.id === 'qrModal') {
        document.getElementById('qrModal').classList.remove('show');
      }
    }

    function showToast(text) {
      const toast = document.getElementById('toast');
      if (text) {
        toast.innerHTML = '<span>\u2728 ' + text + '</span>';
      }
      toast.classList.add('show');
      setTimeout(() => {
        toast.classList.remove('show');
      }, 2400);
    }

    function copyToClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
          showToast('Copied to clipboard!');
        }).catch(() => fallbackCopy(text));
      } else {
        fallbackCopy(text);
      }
    }

    function fallbackCopy(text) {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        showToast('Copied to clipboard!');
      } catch (err) {
        alert('Failed to copy');
      }
      document.body.removeChild(textArea);
    }

    function setHEXTheme(themeId) {
      if (!themeId) return;
      document.documentElement.setAttribute('data-theme', themeId);
      try {
        sessionStorage.setItem('hex-current-session-theme', themeId);
        localStorage.setItem('hex-last-login-theme', themeId);
        localStorage.setItem('hex-current-session-theme', themeId);
      } catch (e) {}
      const sels = document.querySelectorAll('.theme-selector-dropdown');
      sels.forEach(s => {
        if (s.value !== themeId) s.value = themeId;
      });
      showToast('Theme updated: ' + themeId);
    }

    function randomizeHEXTheme() {
      const themes = ['theme-1', 'theme-2', 'theme-3', 'theme-4', 'theme-5'];
      const current = document.documentElement.getAttribute('data-theme') || 'theme-1';
      const candidates = themes.filter(function(t) { return t !== current; });
      const next = candidates[Math.floor(Math.random() * candidates.length)] || 'theme-1';
      setHEXTheme(next);
    }

    window.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        closeSidebar();
        const qrModal = document.getElementById('qrModal');
        if (qrModal) qrModal.classList.remove('show');
      }
    });

    (function syncThemeUI() {
      const current = document.documentElement.getAttribute('data-theme') || 'theme-1';
      const sels = document.querySelectorAll('.theme-selector-dropdown');
      sels.forEach(s => {
        s.value = current;
      });
    })();
  </script>
</body>
</html>`;
}
function renderLoginPage(options) {
  const errorAlert = options.error ? `
    <div style="background: rgba(254, 226, 226, 0.9); border: 1.5px solid #FDA4AF; color: #991B1B; padding: 10px 14px; border-radius: 10px; margin-bottom: 16px; font-size: 13px; display: flex; align-items: center; gap: 8px;">
      <span>\u{1F338}</span>
      <span>${escapeHtml(options.error)}</span>
    </div>` : "";
  const defaultHint = options.isDefaultPassword ? `
    <div style="background: var(--theme-primary-soft); border: 1px dashed var(--theme-border-hover); color: var(--theme-primary); padding: 10px 14px; border-radius: 10px; margin-top: 18px; font-size: 12px; text-align: center;">
      <span>\u{1F4A1} Default dev password is: <strong>${APP_CONFIG.defaultDevPassword}</strong></span>
    </div>` : "";
  const content = `
  <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;">
    <div class="card" style="width: 100%; max-width: 400px; padding: 30px 24px; border-radius: 18px; position: relative; overflow: hidden; box-shadow: 0 20px 48px -10px var(--theme-shadow), 0 0 24px var(--theme-glow);">
      
      <!-- Top Pastel Arc -->
      <div style="position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, var(--theme-primary), var(--theme-secondary), var(--theme-accent));"></div>

      <!-- Mascot & Brand Title -->
      <div style="display: flex; flex-direction: column; align-items: center; text-align: center; margin-bottom: 22px;">
        <div style="margin-bottom: 10px; filter: drop-shadow(0 6px 14px var(--theme-glow));">
          ${MASCOT_SVG}
        </div>
        <h1 style="font-size: 22px; color: var(--theme-text-primary); margin-bottom: 4px;">HEX Panel</h1>
        <p style="color: var(--theme-text-muted); font-size: 13px;">Welcome to HEX — Enter your access key \u{1F338}</p>
        
        <div style="display: flex; align-items: center; gap: 8px; margin-top: 10px; flex-wrap: wrap; justify-content: center;">
          <span class="badge badge-sky">\u2728 v${APP_CONFIG.version} HEX Nebula</span>
          <div class="theme-pill-control" style="padding: 2px 8px;">
            <select class="theme-selector-dropdown" onchange="setHEXTheme(this.value)">
              <option value="theme-1">Lunar Eclipse 🌑</option>
              <option value="theme-2">Emerald Forest 🌿</option>
              <option value="theme-3">Blood Moon Ronin 🩸</option>
              <option value="theme-4">Neon Night 🌃</option>
              <option value="theme-5">Dark Knight 🦇</option>
            </select>
            <button type="button" class="theme-dice-btn" onclick="randomizeHEXTheme()" title="Randomize Theme" style="width: 20px; height: 20px; font-size: 10px;">\u{1F3B2}</button>
          </div>
        </div>
      </div>

      ${errorAlert}

      <form action="/panel/login" method="POST">
        <div class="form-group">
          <label class="form-label" for="password">Panel Password</label>
          <input 
            type="password" 
            id="password" 
            name="password" 
            class="form-control" 
            placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" 
            required 
            autofocus
            style="letter-spacing: 2px; height: 42px;"
          />
        </div>

        <button type="submit" class="btn btn-primary" style="width: 100%; height: 42px; font-size: 14.5px; margin-top: 6px;">
          <span>Unlock HEX</span>
          <span>\u{1F6E1}\uFE0F\u2728</span>
        </button>
      </form>

      ${defaultHint}

      <div style="margin-top: 22px; text-align: center; font-size: 11.5px; color: var(--theme-text-muted);">
        HEX Panel &bull; Encrypted DNS &amp; Proxy Dashboard
        <div style="margin-top: 8px;">
          <a href="${APP_CONFIG.telegramChannel}" target="_blank" rel="noopener noreferrer" style="display: inline-flex; align-items: center; gap: 6px; font-weight: 700; color: var(--theme-primary);">
            <span>\u{1F4E2}</span><span>@HEX_Net on Telegram</span>
          </a>
        </div>
      </div>

    </div>
  </div>
  `;
  return renderPageLayout({
    title: "Login",
    content
  });
}
function renderSetupPage(options) {
  const errorAlert = options.error ? `
    <div style="background: rgba(254, 226, 226, 0.9); border: 1.5px solid #FDA4AF; color: #991B1B; padding: 10px 14px; border-radius: 10px; margin-bottom: 16px; font-size: 13px; display: flex; align-items: center; gap: 8px;">
      <span>\u{1F338}</span>
      <span>${escapeHtml(options.error)}</span>
    </div>` : "";
  const content = `
  <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;">
    <div class="card" style="width: 100%; max-width: 420px; padding: 30px 24px; border-radius: 18px; position: relative; overflow: hidden; box-shadow: 0 20px 48px -10px var(--theme-shadow), 0 0 24px var(--theme-glow);">
      
      <!-- Top Pastel Arc -->
      <div style="position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, var(--theme-primary), var(--theme-secondary), var(--theme-accent));"></div>

      <!-- Mascot & Brand Title -->
      <div style="display: flex; flex-direction: column; align-items: center; text-align: center; margin-bottom: 20px;">
        <div style="margin-bottom: 10px; filter: drop-shadow(0 6px 14px var(--theme-glow));">
          ${MASCOT_SVG}
        </div>
        <h1 style="font-size: 22px; color: var(--theme-text-primary); margin-bottom: 4px;">HEX Panel Setup</h1>
        <p style="color: var(--theme-text-muted); font-size: 13px;">Create HEX administrator password \u{1F338}</p>
        <div style="margin-top: 8px;">
          <span class="badge badge-sky">\u2728 First-Run Setup &bull; v${APP_CONFIG.version}</span>
        </div>
      </div>

      ${errorAlert}

      <div style="background: var(--theme-primary-soft); border: 1px dashed var(--theme-border-hover); color: var(--theme-text-primary); padding: 10px 14px; border-radius: 10px; margin-bottom: 18px; font-size: 12px; line-height: 1.45;">
        <span>\u{1F4A1} <strong>Private KV Storage:</strong> Password is stored in your private KV (<code>WD_KV</code> or <code>BK_KV</code>).</span>
      </div>

      <form action="/panel/setup" method="POST">
        <div class="form-group">
          <label class="form-label" for="password">Create Password</label>
          <input 
            type="password" 
            id="password" 
            name="password" 
            class="form-control" 
            placeholder="At least 8 characters" 
            required 
            minlength="8"
            autofocus
            style="letter-spacing: 1px; height: 40px;"
          />
        </div>

        <div class="form-group">
          <label class="form-label" for="confirmPassword">Confirm Password</label>
          <input 
            type="password" 
            id="confirmPassword" 
            name="confirmPassword" 
            class="form-control" 
            placeholder="Repeat password exactly" 
            required 
            minlength="8"
            style="letter-spacing: 1px; height: 40px;"
          />
        </div>

        <button type="submit" class="btn btn-primary" style="width: 100%; height: 42px; font-size: 14.5px; margin-top: 8px;">
          <span>Complete Setup &amp; Unlock</span>
          <span>\u{1F6E1}\uFE0F\u2728</span>
        </button>
      </form>

      <div style="margin-top: 22px; text-align: center; font-size: 11.5px; color: var(--theme-text-muted);">
        HEX Panel &bull; Encrypted DNS &amp; Proxy Dashboard
        <div style="margin-top: 8px;">
          <a href="${APP_CONFIG.telegramChannel}" target="_blank" rel="noopener noreferrer" style="display: inline-flex; align-items: center; gap: 6px; font-weight: 700; color: var(--theme-primary);">
            <span>\u{1F4E2}</span><span>@HEX_Net on Telegram</span>
          </a>
        </div>
      </div>

    </div>
  </div>
  `;
  return renderPageLayout({
    title: "First-Run Setup",
    content
  });
}
async function handleSetup(request, env2) {
  const url = new URL(request.url);
  const isConfigured = await hasConfiguredPassword(env2);
  if (isConfigured) {
    const cookies = parseCookies(request);
    const existingToken = cookies[APP_CONFIG.cookieName];
    if (existingToken && await verifySessionToken(existingToken, env2)) {
      return Response.redirect(`${url.origin}/panel`, 302);
    }
    return Response.redirect(`${url.origin}/panel/login`, 302);
  }
  if (request.method === "POST") {
    let password = "";
    let confirmPassword = "";
    const contentType = request.headers.get("content-type") || "";
    if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      password = String(formData.get("password") || "").trim();
      confirmPassword = String(formData.get("confirmPassword") || "").trim();
    } else if (contentType.includes("application/json")) {
      const body = await request.json().catch(() => ({}));
      password = String(body.password || "").trim();
      confirmPassword = String(body.confirmPassword || "").trim();
    }
    if (!password || password.length < 8) {
      const html22 = renderSetupPage({ error: "Password must be at least 8 characters long." });
      return new Response(html22, { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    if (password !== confirmPassword) {
      const html22 = renderSetupPage({ error: "Passwords do not match. Please verify and re-enter." });
      return new Response(html22, { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    try {
      await setPassword(password, env2);
      const token = await createSessionToken("admin", env2);
      const isSecure = url.protocol === "https:";
      const cookieHeader = createSessionCookie(token, isSecure);
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/panel?setup=success",
          "Set-Cookie": cookieHeader
        }
      });
    } catch (err) {
      const html22 = renderSetupPage({ error: err.message || "Failed to save password to KV." });
      return new Response(html22, { status: 500, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
  }
  const html2 = renderSetupPage({});
  return new Response(html2, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
async function handleLogin(request, env2) {
  const url = new URL(request.url);
  const isConfigured = await hasConfiguredPassword(env2);
  if (!isConfigured) {
    if (request.method === "POST") {
      return await handleSetup(request, env2);
    }
    const html22 = renderSetupPage({});
    return new Response(html22, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
  const cookies = parseCookies(request);
  const existingToken = cookies[APP_CONFIG.cookieName];
  if (existingToken) {
    const session = await verifySessionToken(existingToken, env2);
    if (session) {
      return Response.redirect(`${url.origin}/panel`, 302);
    }
  }
  if (request.method === "POST") {
    let submittedPassword = "";
    const contentType = request.headers.get("content-type") || "";
    if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      submittedPassword = String(formData.get("password") || "");
    } else if (contentType.includes("application/json")) {
      const body = await request.json().catch(() => ({}));
      submittedPassword = String(body.password || "");
    }
    const isValid = await verifyPassword(submittedPassword, env2);
    if (isValid) {
      const token = await createSessionToken("admin", env2);
      const isSecure = url.protocol === "https:";
      const cookieHeader = createSessionCookie(token, isSecure);
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/panel?login=success",
          "Set-Cookie": cookieHeader
        }
      });
    } else {
      const html22 = renderLoginPage({
        error: "Incorrect password! Please try again with love \u{1F338}",
        isDefaultPassword: false
      });
      return new Response(html22, {
        status: 401,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
  }
  const errorParam = url.searchParams.get("error");
  const html2 = renderLoginPage({
    error: errorParam ? decodeURIComponent(errorParam) : void 0,
    isDefaultPassword: false
  });
  return new Response(html2, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
function handleLogout(request) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/panel/login",
      "Set-Cookie": createClearCookie()
    }
  });
}
function renderDashboardPage(options) {
  const { settings } = options;
  const initialTab = options.initialTab || "overview";
  const defaultPasswordBanner = options.isDefaultPassword ? `
    <div style="background: rgba(254, 226, 226, 0.9); border: 1.5px solid #FDA4AF; border-radius: 14px; padding: 12px 18px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; gap: 14px;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 20px;">\u26A0\uFE0F</span>
        <div>
          <strong style="color: #9F1239; font-family: 'Quicksand', sans-serif; font-size: 13.5px;">Default Dev Password Active</strong>
          <p style="color: #BE123C; font-size: 12px; margin-top: 1px;">Your panel is using the fallback password (<code>${APP_CONFIG.defaultDevPassword}</code>). Please set a secure password in Settings.</p>
        </div>
      </div>
      <button type="button" onclick="switchTab('settings')" class="btn btn-sm btn-secondary" style="background: #FFFFFF; border-color: #FECDD3; color: #E11D48; white-space: nowrap;">
        Go to Settings
      </button>
    </div>` : "";
  const flashAlert = options.flashMessage ? `
    <div style="background: ${options.flashMessage.type === "success" ? "rgba(236, 253, 245, 0.9)" : "rgba(254, 242, 242, 0.9)"}; border: 1.5px solid ${options.flashMessage.type === "success" ? "#A7F3D0" : "#FCA5A5"}; color: ${options.flashMessage.type === "success" ? "#065F46" : "#991B1B"}; padding: 10px 16px; border-radius: 12px; margin-bottom: 16px; font-size: 13px; display: flex; align-items: center; gap: 8px;">
      <span>${options.flashMessage.type === "success" ? "\u{1F338}\u2728" : "\u26A0\uFE0F"}</span>
      <span>${options.flashMessage.text}</span>
    </div>` : "";
  const tokenParam = `?token=${encodeURIComponent(settings.subToken)}`;
  const shareTokenParam = `?token=${encodeURIComponent(settings.nodeShareToken)}`;
  const subUrls = {
    vless: `https://${options.host}/sub/vless${tokenParam}`,
    trojan: `https://${options.host}/sub/trojan${tokenParam}`,
    singbox: `https://${options.host}/sub/singbox${tokenParam}`,
    clash: `https://${options.host}/sub/clash${tokenParam}`,
    xray: `https://${options.host}/sub/xray${tokenParam}`,
    xrayJson: `https://${options.host}/sub/xray-json${tokenParam}`,
    warp: `https://${options.host}/sub/warp${tokenParam}`,
    amnezia: `https://${options.host}/sub/amnezia${tokenParam}`,
    openvpn: `https://${options.host}/sub/openvpn${tokenParam}`,
    ss: `https://${options.host}/sub/ss${tokenParam}`,
    doh: `https://${options.host}/dns-query`,
    nodeExport: `https://${options.host}/api/node/export${shareTokenParam}`
  };
  const wsProxyEndpoint = `wss://${options.host}${settings.proxyPath}`;
  const hasWarp = false;
  const warpBadge = hasWarp ? settings.warpProEnabled ? '<span class="badge badge-sakura">Warp Pro Active</span>' : '<span class="badge badge-mint">Warp Basic Active</span>' : '<span class="badge badge-lavender">Warp Idle</span>';
  const chainBadge = settings.chainEnabled ? `<span class="badge badge-mint">Chain: ${settings.chainType.toUpperCase()}</span>` : '<span class="badge badge-lavender">Chain Off</span>';
  const content = `
  <div class="drawer-backdrop" id="drawerBackdrop" onclick="closeSidebar()"></div>

  <div class="app-layout">
    <!-- Slim Reference-Style Floating Glass Sidebar (258px desktop) -->
    <aside class="app-sidebar" id="appSidebar">
      <div>
        <div class="sidebar-brand">
          <div class="brand-mark">${MASCOT_SVG}</div>
          <div style="min-width: 0;">
            <div class="brand-title" style="font-size: 16px; line-height: 1.15;">HEX</div>
            <div class="brand-tagline">Secure &bull; Fast &bull; Private</div>
          </div>
        </div>

        <!-- First-Level Navigation: Dashboard ALWAYS visible at the top! -->
        <nav class="sidebar-nav">
          <div class="nav-section">Panel</div>
          <button type="button" id="nav-overview" onclick="switchTab('overview')" class="nav-btn ${initialTab === "overview" ? "active" : ""}">
            <span class="nav-icon">\u{1F4CA}</span>
            <span>Dashboard</span>
          </button>
          <button type="button" id="nav-subscriptions" onclick="switchTab('subscriptions')" class="nav-btn ${initialTab === "subscriptions" ? "active" : ""}">
            <span class="nav-icon">\u{1F517}</span>
            <span>Subscriptions</span>
          </button>
          <button type="button" id="nav-protocols" onclick="switchTab('protocols')" class="nav-btn ${initialTab === "protocols" ? "active" : ""}">
            <span class="nav-icon">\u{1F6E1}\uFE0F</span>
            <span>Protocols</span>
          </button>
          <button type="button" id="nav-dns" onclick="switchTab('dns')" class="nav-btn ${initialTab === "dns" ? "active" : ""}">
            <span class="nav-icon">\u{1F310}</span>
            <span>DNS Settings</span>
          </button>
          <button type="button" id="nav-routing" onclick="switchTab('routing')" class="nav-btn ${initialTab === "routing" ? "active" : ""}">
            <span class="nav-icon">\u{1F500}</span>
            <span>Routing &amp; Chain</span>
          </button>
          <button type="button" id="nav-users" onclick="switchTab('users')" class="nav-btn ${initialTab === "users" ? "active" : ""}">
            <span class="nav-icon">\u{1F465}</span>
            <span>Users</span>
          </button>
          <button type="button" id="nav-settings" onclick="switchTab('settings')" class="nav-btn ${initialTab === "settings" ? "active" : ""}">
            <span class="nav-icon">\u2699\uFE0F</span>
            <span>Settings</span>
          </button>
          <div class="nav-section">Diagnostics</div>
          <a href="/dns-json?name=cloudflare.com&type=A" target="_blank" class="nav-btn">
            <span class="nav-icon">\u26A1</span>
            <span>Test DoH</span>
            <span class="nav-tag">DNS</span>
          </a>
          <a href="/api/health" target="_blank" class="nav-btn">
            <span class="nav-icon">\u{1FA7A}</span>
            <span>API Health</span>
            <span class="nav-tag">Live</span>
          </a>
          <div class="nav-section">Community</div>
          <a href="${APP_CONFIG.telegramChannel}" target="_blank" rel="noopener noreferrer" class="nav-btn">
            <span class="nav-icon">\u{1F4E2}</span>
            <span>Telegram</span>
            <span class="nav-tag">News</span>
          </a>
        </nav>
      </div>

      <div class="sidebar-footer">
        <div class="sidebar-status-pill">
          <div class="sidebar-status-dot"></div>
          <div style="flex: 1; min-width: 0;">
            <div style="font-size: 12px; font-weight: 700; color: var(--theme-text-primary); line-height: 1.2;">System Online</div>
            <div style="font-size: 10.5px; color: var(--theme-text-muted); margin-top: 1px;">Tunnel engine running</div>
          </div>
          <span class="badge badge-mint" style="font-size: 10px; padding: 2px 6px;">Active</span>
        </div>

        <a href="/panel/logout" class="btn btn-secondary btn-sm" style="width: 100%; justify-content: space-between;">
          <span>Log out</span>
          <span>\u{1F6AA}</span>
        </a>
      </div>
    </aside>

    <!-- Transparent Main Canvas (NO giant enclosing frosted slab) -->
    <main class="app-main">
      <!-- Persistent Compact Header Bar -->
      <header class="app-header">
        <div class="header-left">
          <button type="button" class="mobile-nav-toggle" onclick="toggleSidebar()" aria-label="Toggle Navigation">\u2630</button>
          <div class="header-icon-box">
            <span id="page-icon">\u{1F4CA}</span>
          </div>
          <div>
            <h1 id="page-heading" style="font-size: 16.5px; margin-bottom: 2px;">System Dashboard</h1>
            <p id="page-subheading" style="color: var(--theme-text-muted); font-size: 12px; font-weight: 600;">Pastel proxy command center &amp; live tunnel stats</p>
          </div>
        </div>

        <div class="header-right">
          <div class="theme-pill-control">
            <span style="font-size: 13px;">\u{1F3A8}</span>
            <select class="theme-selector-dropdown" onchange="setHEXTheme(this.value)">
              <option value="theme-1">Theme 1 \u2014 Lunar Eclipse</option>
              <option value="theme-2">Theme 2 \u2014 Emerald Forest</option>
              <option value="theme-3">Theme 3 \u2014 Blood Moon Ronin</option>
              <option value="theme-4">Theme 4 \u2014 Neon Night</option>
              <option value="theme-5">Theme 5 \u2014 Dark Knight</option>
            </select>
            <button type="button" class="theme-dice-btn" onclick="randomizeHEXTheme()" title="Randomize Theme">\u{1F3B2}</button>
          </div>

          <button type="button" class="btn btn-secondary btn-sm rtl-toggle-btn" onclick="toggleRtl()">RTL \u21C4</button>
          <span class="badge badge-mint">\u25CF Sockets Engine Online</span>
          <span class="badge badge-sky" style="max-width: 130px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(options.host)}</span>
        </div>
      </header>

      ${defaultPasswordBanner}
      ${flashAlert}

      <!-- ====================================================================
           TAB 1: DASHBOARD (PRIMARY ACTION CARD + QUICK TILES + LIVE DOH)
           ==================================================================== -->
      <section id="tab-overview" class="tab-pane ${initialTab === "overview" ? "active" : ""}">
        
        <!-- Primary Feature Card (Level 1 Status Card) -->
        <div class="card card-primary" style="margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
            <div>
              <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <span style="font-size: 22px;">\u{1F54A}\uFE0F</span>
                <h2 style="font-size: 18px;">Cloudflare Sockets Dual-Protocol Proxy</h2>
              </div>
              <p style="color: var(--theme-text-muted); font-size: 12.5px;">Multiplexed WebSocket inbound tunneling VLESS &amp; Trojan over Cloudflare Edge</p>
            </div>
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              ${chainBadge}
              <span class="badge ${settings.fragmentEnabled ? "badge-mint" : "badge-lavender"}">Fragment ${settings.fragmentEnabled ? "ON" : "OFF"}</span>
            </div>
          </div>

          <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px; margin-bottom: 14px;">
            <label class="form-label" style="font-size: 11.5px; margin-bottom: 4px;">Primary Tunnel Endpoint (WSS)</label>
            <div class="copy-wrapper">
              <input type="text" readonly class="form-control code-input" value="${wsProxyEndpoint}" />
              <div class="copy-actions">
                <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${wsProxyEndpoint}')">\u{1F4CB} Copy Endpoint</button>
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; font-size: 12px;">
            <div style="background: var(--theme-surface-soft); padding: 8px 12px; border-radius: 10px; border: 1px solid var(--theme-border);">
              <span style="color: var(--theme-text-muted);">VLESS UUID:</span>
              <div style="font-family: 'JetBrains Mono', monospace; font-weight: 700; overflow: hidden; text-overflow: ellipsis; color: var(--theme-primary);">${settings.vlessUuid}</div>
            </div>
            <div style="background: var(--theme-surface-soft); padding: 8px 12px; border-radius: 10px; border: 1px solid var(--theme-border);">
              <span style="color: var(--theme-text-muted);">Trojan Pass:</span>
              <div style="font-family: 'JetBrains Mono', monospace; font-weight: 700; overflow: hidden; text-overflow: ellipsis; color: var(--theme-secondary);">${settings.trojanPassword}</div>
            </div>
            <div style="background: var(--theme-surface-soft); padding: 8px 12px; border-radius: 10px; border: 1px solid var(--theme-border);">
              <span style="color: var(--theme-text-muted);">Clean IP:</span>
              <div style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: var(--theme-accent);">${settings.proxyIp || "(Default Domain)"}</div>
            </div>
            <div style="background: var(--theme-surface-soft); padding: 8px 12px; border-radius: 10px; border: 1px solid var(--theme-border);">
              <span style="color: var(--theme-text-muted);">Routing Preset:</span>
              <div style="font-weight: 700; color: var(--theme-text-primary); text-transform: uppercase;">${settings.routingPreset}</div>
            </div>
          </div>
        </div>

        <!-- Quick Action Tiles Grid (Level 2) -->
        <div class="quick-action-grid">
          <div class="action-tile" onclick="copyToClipboard('${subUrls.vless}')">
            <div class="action-tile-icon">\u{1F4CB}</div>
            <div class="action-tile-text">
              <h4>Copy VLESS</h4>
              <p>v2rayN &amp; Nekobox</p>
            </div>
          </div>

          <div class="action-tile" onclick="copyToClipboard('${subUrls.clash}')">
            <div class="action-tile-icon">\u{1F517}</div>
            <div class="action-tile-text">
              <h4>Copy Clash</h4>
              <p>Clash.Meta / Mihomo</p>
            </div>
          </div>

          <div class="action-tile" onclick="copyToClipboard('${subUrls.singbox}')">
            <div class="action-tile-icon">\u{1F4E6}</div>
            <div class="action-tile-text">
              <h4>Copy Sing-box</h4>
              <p>Sing-box 1.9+ JSON</p>
            </div>
          </div>

          <div class="action-tile" onclick="switchTab('dns')">
            <div class="action-tile-icon">\u{1F310}</div>
            <div class="action-tile-text">
              <h4>DoH Resolver</h4>
              <p>Real-time DNS &amp; RTT</p>
            </div>
          </div>

          <div class="action-tile" onclick="switchTab('protocols')">
            <div class="action-tile-icon">\u{1F6E1}\uFE0F</div>
            <div class="action-tile-text">
              <h4>Protocols</h4>
              <p>UUID &amp; Clean IP</p>
            </div>
          </div>
        </div>

        <!-- 2-Column Grid: Live DoH Query Resolver + Notice -->
        <div class="grid-2col" style="margin-bottom: 16px;">
          <!-- Live DoH Query Resolver Widget -->
          <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
              <div class="card-title">
                <span>\u26A1</span>
                <span>Live DoH Resolver</span>
              </div>
              <span class="badge badge-sky">RFC 8484 / JSON</span>
            </div>
            <p class="card-desc">Query upstream DNS latency &amp; resolve domains directly from Cloudflare edge.</p>

            <div style="display: flex; gap: 8px; margin-bottom: 10px; flex-wrap: wrap;">
              <input type="text" id="dohTestDomain" class="form-control code-input" value="cloudflare.com" placeholder="e.g. google.com" style="flex: 2; min-width: 140px;" />
              <select id="dohTestType" class="form-control code-input" style="flex: 1; min-width: 80px;">
                <option value="A" selected>A</option>
                <option value="AAAA">AAAA</option>
                <option value="CNAME">CNAME</option>
                <option value="TXT">TXT</option>
                <option value="NS">NS</option>
                <option value="MX">MX</option>
              </select>
              <button type="button" class="btn btn-primary btn-sm" onclick="runDohTest()" style="height: 38px; padding: 0 14px;">
                <span>\u26A1 Resolve</span>
              </button>
            </div>

            <div id="dohTestResult" style="display: none; background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 10px; padding: 10px 12px; margin-top: 8px; font-size: 12px;"></div>
          </div>

          <!-- Client Connectivity Guidance Notice -->
          <div class="card" style="border-inline-start: 4px solid var(--theme-primary);">
            <div class="card-title">
              <span>\u{1F4A1}</span>
              <span>Client Testing Notice</span>
            </div>
            <p class="card-desc" style="margin-bottom: 10px;">
              <strong>v2rayN latency ping delay can show -1:</strong> GUI clients attempt synthetic ICMP/TCP probes that Cloudflare Workers terminate. Always verify real traffic by opening websites or streaming video through the proxy.
            </p>
            <div style="background: var(--theme-surface-strong); padding: 10px 12px; border-radius: 10px; border: 1px solid var(--theme-border); font-size: 12px; display: flex; justify-content: space-between; align-items: center;">
              <span>Upstream DoH Gateway:</span>
              <code style="font-family: 'JetBrains Mono', monospace; color: var(--theme-primary); font-size: 11.5px;">${settings.dnsDoH}</code>
            </div>
          </div>
        </div>

        <!-- Live Client Subscriptions & Services Table -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
            <div class="card-title" style="margin-bottom: 0;">
              <span>\u{1F517}</span>
              <span>Live Client Subscription Profiles</span>
            </div>
            <span class="badge badge-mint">\u25CF All Feeds Active</span>
          </div>

          <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
              <thead>
                <tr style="border-bottom: 1.5px solid var(--theme-border); color: var(--theme-text-muted); font-family: 'Quicksand', sans-serif;">
                  <th style="padding: 8px 10px;">Service</th>
                  <th style="padding: 8px 10px;">Recommended Client</th>
                  <th style="padding: 8px 10px;">Status / Features</th>
                  <th style="padding: 8px 10px; text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody>
                <tr style="border-bottom: 1px solid var(--theme-border);">
                  <td style="padding: 10px; font-weight: 700;">VLESS Share Link</td>
                  <td style="padding: 10px;"><span class="badge badge-lavender">v2rayN, Nekobox</span></td>
                  <td style="padding: 10px;"><span class="badge badge-sky">${settings.fragmentEnabled ? "Fragment Ready" : "Standard WS"}</span></td>
                  <td style="padding: 10px; text-align: right;">
                    <button type="button" class="btn btn-sm btn-secondary" onclick="copyToClipboard('${subUrls.vless}')">\u{1F4CB} Copy</button>
                  </td>
                </tr>
                <tr style="border-bottom: 1px solid var(--theme-border);">
                  <td style="padding: 10px; font-weight: 700;">Trojan Share Link</td>
                  <td style="padding: 10px;"><span class="badge badge-sakura">Shadowrocket</span></td>
                  <td style="padding: 10px;"><span class="badge badge-mint">TLS + WS</span></td>
                  <td style="padding: 10px; text-align: right;">
                    <button type="button" class="btn btn-sm btn-secondary" onclick="copyToClipboard('${subUrls.trojan}')">\u{1F4CB} Copy</button>
                  </td>
                </tr>
                <tr style="border-bottom: 1px solid var(--theme-border);">
                  <td style="padding: 10px; font-weight: 700;">Clash.Meta / Mihomo</td>
                  <td style="padding: 10px;"><span class="badge badge-sky">Clash Verge, Flclash</span></td>
                  <td style="padding: 10px;"><span class="badge badge-lavender">${settings.routingPreset}${settings.chainEnabled ? " + Chain" : ""}</span></td>
                  <td style="padding: 10px; text-align: right;">
                    <button type="button" class="btn btn-sm btn-secondary" onclick="copyToClipboard('${subUrls.clash}')">\u{1F4CB} Copy</button>
                  </td>
                </tr>
                <tr style="border-bottom: 1px solid var(--theme-border);">
                  <td style="padding: 10px; font-weight: 700;">Sing-box 1.9+ JSON</td>
                  <td style="padding: 10px;"><span class="badge badge-mint">Sing-box (Win, iOS, Android)</span></td>
                  <td style="padding: 10px;"><span class="badge badge-lavender">Outbounds &amp; Detour</span></td>
                  <td style="padding: 10px; text-align: right;">
                    <button type="button" class="btn btn-sm btn-secondary" onclick="copyToClipboard('${subUrls.singbox}')">\u{1F4CB} Copy</button>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 10px; font-weight: 700;">Private DoH Gateway</td>
                  <td style="padding: 10px;"><span class="badge badge-sky">Any Browser / Client</span></td>
                  <td style="padding: 10px;"><span class="badge badge-mint">RFC 8484 Wireformat</span></td>
                  <td style="padding: 10px; text-align: right;">
                    <button type="button" class="btn btn-sm btn-secondary" onclick="copyToClipboard('${subUrls.doh}')">\u{1F4CB} Copy</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </section>

      <!-- ====================================================================
           TAB 3: SUBSCRIPTIONS (GRID OF COMPACT CARDS + QR MODAL)
           ==================================================================== -->
      <section id="tab-subscriptions" class="tab-pane ${initialTab === "subscriptions" ? "active" : ""}">
        
        <div class="card" style="margin-bottom: 16px;">
          <div class="card-title">
            <span>\u{1F517}</span>
            <span>Live Subscription Links &amp; Client Feeds</span>
          </div>
          <p class="card-desc">Token-gated client configurations with active proxy routes and fragment parameters.</p>

          <div style="display: flex; flex-direction: column; gap: 12px;">
            
            <div class="glass-card" style="padding:16px">
              <strong>All configured protocols \u2014 Sing-box 1.14+</strong>
              <p>VLESS and Trojan, plus provisioned ShadowTLS, Shadowsocks, Hysteria2, TUIC and AnyTLS in one profile. OpenVPN uses its separate client download below.</p>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="https://${options.host}/sub/all?token=${encodeURIComponent(settings.subToken)}" />
                <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('https://${options.host}/sub/all?token=${encodeURIComponent(settings.subToken)}')">Copy all-protocol profile</button>
              </div>
            </div>
            <div class="glass-card" style="padding:16px">
              <strong>VLESS + Trojan + Shadowsocks \u2014 combined subscription</strong>
              <p>Use this link for all three panel protocols. Shadowsocks uses WebSocket/TLS with v2ray-plugin support.</p>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.xray}" />
                <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.xray}')">Copy combined subscription</button>
              </div>
            </div>
            <!-- VLESS Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">VLESS Direct Feed</strong>
                <span class="badge badge-lavender">v2rayN / Nekobox</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.vless}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.vless}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('VLESS Subscription', '${subUrls.vless}')">\u{1F4F1} QR</button>
                  <a href="${subUrls.vless}" target="_blank" class="btn btn-secondary btn-sm">\u{1F441}\uFE0F Preview</a>
                </div>
              </div>
            </div>

            <!-- Trojan Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">Trojan Direct Feed</strong>
                <span class="badge badge-sakura">Shadowrocket</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.trojan}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.trojan}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('Trojan Subscription', '${subUrls.trojan}')">\u{1F4F1} QR</button>
                  <a href="${subUrls.trojan}" target="_blank" class="btn btn-secondary btn-sm">\u{1F441}\uFE0F Preview</a>
                </div>
              </div>
            </div>

            <!-- Clash Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">Clash.Meta / Mihomo (YAML)</strong>
                <span class="badge badge-sky">Clash Verge / Mihomo</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.clash}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.clash}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('Clash.Meta YAML Profile', '${subUrls.clash}')">\u{1F4F1} QR</button>
                  <a href="${subUrls.clash}" target="_blank" class="btn btn-secondary btn-sm">\u{1F441}\uFE0F Preview</a>
                </div>
              </div>
            </div>

            <!-- Sing-box Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">Sing-box 1.14+ Config (JSON)</strong>
                <span class="badge badge-mint">Sing-box Client</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.singbox}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.singbox}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('Sing-box Remote Config', '${subUrls.singbox}')">\u{1F4F1} QR</button>
                  <a href="${subUrls.singbox}" target="_blank" class="btn btn-secondary btn-sm">\u{1F441}\uFE0F Preview</a>
                </div>
              </div>
            </div>

            <!-- Xray Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">Xray Client Configuration (JSON)</strong>
                <span class="badge badge-sky">Xray / v2rayN Core</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.xrayJson}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.xrayJson}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('Xray Client JSON', '${subUrls.xrayJson}')">\u{1F4F1} QR</button>
                  <a href="${subUrls.xrayJson}" target="_blank" class="btn btn-secondary btn-sm">\u{1F441}\uFE0F Preview</a>
                </div>
              </div>
            </div>

            <!-- Native protocol subscriptions -->
            <div class="glass-card" style="padding:16px">
              <strong>Native connections</strong>
              <p>ShadowTLS, Shadowsocks, Hysteria2, TUIC and AnyTLS require the native server deployment. Downloads return a configuration error until provisioned.</p>
              <a class="btn btn-secondary btn-sm" href="/sub/native?token=${encodeURIComponent(settings.subToken)}">Download native Sing-box connections</a>
            </div>
            <!-- OpenVPN Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">\u{1F6E1}\uFE0F OpenVPN Client Profile (.ovpn)</strong>
                <span class="badge badge-mint">Native OpenVPN server required</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.openvpn}" />
                <div class="copy-actions">
                  <a href="${subUrls.openvpn}" download="hex.ovpn" class="btn btn-primary btn-sm">\u{1F4E5} Download .ovpn</a>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="copyToClipboard('${subUrls.openvpn}')">\u{1F4CB} Copy Link</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('OpenVPN Configuration', '${subUrls.openvpn}')">\u{1F4F1} QR</button>
                </div>
              </div>
            </div>

            <!-- Shadowsocks (SS) Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">\u{1F510} Shadowsocks (SS) Feed</strong>
                <span class="badge badge-sakura">WebSocket/TLS \xB7 TCP</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.ss}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.ss}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('Shadowsocks Subscription', '${subUrls.ss}')">\u{1F4F1} QR</button>
                  <a href="${subUrls.ss}" target="_blank" class="btn btn-secondary btn-sm">\u{1F441}\uFE0F Preview</a>
                </div>
              </div>
            </div>

            <!-- DoH Sub -->
            <div style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 12px 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 13.5px;">Private DNS-over-HTTPS Endpoint</strong>
                <span class="badge badge-sky">RFC 8484 + JSON</span>
              </div>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${subUrls.doh}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-primary btn-sm" onclick="copyToClipboard('${subUrls.doh}')">\u{1F4CB} Copy</button>
                  <button type="button" class="btn btn-secondary btn-sm" onclick="showQrModal('Private DoH Gateway', '${subUrls.doh}')">\u{1F4F1} QR</button>
                  <a href="/dns-json?name=cloudflare.com&type=A" target="_blank" class="btn btn-secondary btn-sm">\u26A1 Test</a>
                </div>
              </div>
            </div>

          </div>
        </div>

      </section>

      <!-- ====================================================================
           TAB 4: PROTOCOLS (COMPACT 2-COLUMN DASHBOARD GRID)
           ==================================================================== -->
      <section id="tab-protocols" class="tab-pane ${initialTab === "protocols" ? "active" : ""}">
        
        <form action="/panel/settings/protocols" method="POST">
          <div class="grid-2col" style="margin-bottom: 16px;">
            
            <!-- Card 1: Inbound Transport & Client Credentials -->
            <div class="card">
              <div class="card-title">
                <span>\u{1F512}</span>
                <span>Inbound Transport &amp; Credentials</span>
              </div>
              <p class="card-desc">WebSocket proxy credentials for VLESS and Trojan client authentications.</p>

              <div class="form-group">
                <label class="form-label" for="vlessUuid">VLESS User UUID</label>
                <div class="copy-wrapper">
                  <input type="text" id="vlessUuid" name="vlessUuid" class="form-control code-input" value="${settings.vlessUuid}" required />
                  <div class="copy-actions">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="generateRandomUuid()">\u{1F3B2} Gen</button>
                  </div>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="trojanPassword">Trojan Client Password</label>
                <div class="copy-wrapper">
                  <input type="text" id="trojanPassword" name="trojanPassword" class="form-control code-input" value="${settings.trojanPassword}" required />
                  <div class="copy-actions">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="generateRandomPassword()">\u{1F3B2} Gen</button>
                  </div>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="proxyPath">WebSocket Proxy Path</label>
                <input type="text" id="proxyPath" name="proxyPath" class="form-control code-input" value="${settings.proxyPath}" required placeholder="/wd-ws" />
                <div style="font-size: 11px; color: var(--theme-text-muted); margin-top: 3px;">Accepts both /wd-ws and legacy /hex-ws paths.</div>
              </div>

              <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label" for="subToken">Subscription Token</label>
                <div class="copy-wrapper">
                  <input type="text" id="subToken" name="subToken" class="form-control code-input" value="${settings.subToken}" required />
                  <div class="copy-actions">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="generateRandomToken()">\u{1F3B2} Gen</button>
                  </div>
                </div>
              </div>
            </div>

            <!-- Card 2: Network, Clean IP & Listening Mode -->
            <div class="card">
              <div class="card-title">
                <span>\u{1F310}</span>
                <span>Network &amp; Preferred Addresses</span>
              </div>
              <p class="card-desc">Clean CDN IPs for fronting and local area network sharing configurations.</p>

              <div class="form-group">
                <label class="form-label" for="proxyIp">Clean IP / Preferred Address (Optional)</label>
                <input type="text" id="proxyIp" name="proxyIp" class="form-control code-input" value="${settings.proxyIp}" placeholder="e.g. 104.16.1.1 (leave empty for worker default)" />
                <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px;">
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 11px; padding: 2px 8px; height: 26px;" onclick="setCleanIp('')">Default</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 11px; padding: 2px 8px; height: 26px;" onclick="setCleanIp('104.16.1.1')">104.16.1.1</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 11px; padding: 2px 8px; height: 26px;" onclick="setCleanIp('104.19.241.93')">104.19.241.93</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 11px; padding: 2px 8px; height: 26px;" onclick="setCleanIp('172.67.180.1')">172.67.180.1</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 11px; padding: 2px 8px; height: 26px;" onclick="setCleanIp('162.159.138.6')">162.159.138.6</button>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="relayIp">Relay for Cloudflare-hosted Sites (ProxyIP)</label>
                <input type="text" id="relayIp" name="relayIp" class="form-control code-input" value="${escapeHtml(settings.relayIp)}" placeholder="e.g. proxyip.example.com or 1.2.3.4:443" />
                <p class="card-desc" style="margin: 6px 0 0;">Workers cannot open sockets to Cloudflare IPs, so sites behind Cloudflare CDN fail on a direct dial. When that happens the Worker retries through this non-Cloudflare relay. Port defaults to the target port. Ignored while an upstream chain is enabled.</p>
              </div>

              <div class="form-group">
                <label class="form-label" for="nat64Prefixes">NAT64 Prefixes (used when no relay is set)</label>
                <input type="text" id="nat64Prefixes" name="nat64Prefixes" class="form-control code-input" value="${escapeHtml(settings.nat64Prefixes.join(", "))}" placeholder="${DEFAULT_NAT64_PREFIXES}" />
                <p class="card-desc" style="margin: 6px 0 0;">With no relay, Cloudflare-hosted sites are reached through a public NAT64 gateway: the site's IPv4 is embedded in one of these IPv6 prefixes. Works out of the box; replace the list if these gateways stop answering. Clear it to disable.</p>
              </div>

              <div class="form-group">
                <label class="form-label" for="dnsDoH">Underlying DoH Upstream URL</label>
                <input type="text" id="dnsDoH" name="dnsDoH" class="form-control code-input" value="${settings.dnsDoH}" placeholder="https://cloudflare-dns.com/dns-query" />
              </div>

              <div class="setting-group" style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 12px; padding: 10px 14px;">
                <div class="setting-row" style="padding: 0;">
                  <div class="setting-label-col">
                    <div class="setting-title">Allow LAN Sharing</div>
                    <div class="setting-subtitle">Listen on 0.0.0.0 to allow devices on your local network to route through this client.</div>
                  </div>
                  <div class="setting-control-col">
                    <input type="checkbox" id="allowLANConnection" name="allowLANConnection" ${settings.allowLANConnection ? "checked" : ""} style="accent-color: var(--theme-primary); width: 18px; height: 18px; cursor: pointer;" />
                  </div>
                </div>
              </div>

            </div>

            <!-- Card 3: Domain Fronting & SNI Decoupling -->
            <div class="card">
              <div class="card-title">
                <span>\u{1F3AD}</span>
                <span>Domain Fronting &amp; SNI Camouflage</span>
              </div>
              <p class="card-desc">Decouple TLS SNI from HTTP Host header to bypass deep packet inspection filters.</p>

              <div class="setting-group" style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 10px; padding: 8px 12px; margin-bottom: 12px;">
                <div class="setting-row" style="padding: 0;">
                  <div class="setting-label-col">
                    <div class="setting-title" style="font-size: 13px;">Enable Domain Fronting</div>
                    <div class="setting-subtitle" style="font-size: 11px;">Generate fronted nodes in subscriptions with camouflage SNI.</div>
                  </div>
                  <div class="setting-control-col">
                    <input type="checkbox" id="domainFrontingEnabled" name="domainFrontingEnabled" ${settings.domainFrontingEnabled ? "checked" : ""} style="accent-color: var(--theme-primary); width: 18px; height: 18px; cursor: pointer;" />
                  </div>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="frontingSni">Camouflage Fronting SNI</label>
                <input type="text" id="frontingSni" name="frontingSni" class="form-control code-input" value="${settings.frontingSni || "cdnjs.cloudflare.com"}" placeholder="e.g. cdnjs.cloudflare.com, speedtest.net" />
                <div style="display: flex; gap: 6px; margin-top: 4px; flex-wrap: wrap;">
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 10.5px; padding: 2px 6px;" onclick="document.getElementById('frontingSni').value='cdnjs.cloudflare.com'">cdnjs</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 10.5px; padding: 2px 6px;" onclick="document.getElementById('frontingSni').value='speedtest.net'">speedtest</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 10.5px; padding: 2px 6px;" onclick="document.getElementById('frontingSni').value='zoom.us'">zoom</button>
                  <button type="button" class="btn btn-sm btn-secondary" style="font-size: 10.5px; padding: 2px 6px;" onclick="document.getElementById('frontingSni').value='investors.cloudflare.com'">cloudflare</button>
                </div>
              </div>

              <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label" for="frontingHost">Target Worker Host Header (Optional)</label>
                <input type="text" id="frontingHost" name="frontingHost" class="form-control code-input" value="${settings.frontingHost || ""}" placeholder="Leave empty for current host: ${escapeHtml(options.host)}" />
              </div>
            </div>

            <!-- Card 4: Static IP Pool Management -->
            <div class="card">
              <div class="card-title">
                <span>\u{1F4CD}</span>
                <span>Static Clean IP Pool</span>
              </div>
              <p class="card-desc">Configured static IPs will generate separate dedicated node entries in subscriptions.</p>

              <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label" for="staticIpList">Static / Anycast IP List (Comma or space separated)</label>
                <textarea id="staticIpList" name="staticIpList" class="form-control code-input" rows="4" placeholder="104.16.1.1, 104.19.241.93, 172.67.180.1, 162.159.138.6" style="resize: vertical; font-size: 12px;">${settings.staticIpList || ""}</textarea>
                <div style="font-size: 11px; color: var(--theme-text-muted); margin-top: 4px;">
                  \u{1F4A1} Each IP will be added as a distinct selectable node in Clash, Sing-box, and VLESS subscriptions.
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-title">Shadowsocks over WebSocket/TLS</div>
              <p class="card-desc">Included alongside VLESS and Trojan in combined feeds. Requires v2ray-plugin in URI clients; Xray JSON and Sing-box exports configure the transport.</p>
              <label><input type="checkbox" name="ssEnabled" ${settings.ssEnabled ? "checked" : ""} /> Enable Shadowsocks</label>
              <label class="form-label">Cipher</label>
              <select class="form-control" name="ssMethod">${SS_METHODS.map((method) => `<option value="${method}" ${settings.ssMethod === method ? "selected" : ""}>${method}</option>`).join("")}</select>
              <label class="form-label">Password</label>
              <input type="password" class="form-control" name="ssPassword" value="${settings.ssPassword.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")}" />
            </div>
            <div class="card">
              <div class="card-title">Native protocol servers</div>
              <p class="card-desc">Shadowsocks, ShadowTLS, AnyTLS, Hysteria2, TUIC and OpenVPN use the native deployment. Manage their credentials in that deployment and download client profiles from Subscriptions.</p>
              <a class="btn btn-secondary" href="/panel/settings/subscriptions">Open native subscriptions</a>
            </div>
            <!-- Card 6: XHTTP, HTTP Upgrade & AnyTLS Engine -->
            <div class="card">
              <div class="card-title">
                <span>\u26A1</span>
                <span>Experimental HTTP streaming &amp; client TLS</span>
              </div>
              <p class="card-desc">Raw VLESS/Trojan HTTP streaming is experimental and is not Xray split-HTTP. Use WebSocket subscriptions for client compatibility.</p>

              <div class="setting-group" style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 10px; padding: 8px 12px; margin-bottom: 10px;">
                <div class="setting-row" style="padding: 0;">
                  <div class="setting-label-col">
                    <div class="setting-title" style="font-size: 13px;">Enable experimental HTTP streaming</div>
                    <div class="setting-subtitle" style="font-size: 11px;">HTTP/2 &amp; HTTP/3 streaming chunked body proxying.</div>
                  </div>
                  <div class="setting-control-col">
                    <input type="checkbox" id="xhttpEnabled" name="xhttpEnabled" ${settings.xhttpEnabled ? "checked" : ""} style="accent-color: var(--theme-primary); width: 18px; height: 18px; cursor: pointer;" />
                  </div>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="xhttpPath">HTTP Streaming Endpoint Path</label>
                <input type="text" id="xhttpPath" name="xhttpPath" class="form-control code-input" value="${settings.xhttpPath || "/bk-xhttp"}" placeholder="/bk-xhttp" />
              </div>

              <div class="form-group">
                <label class="form-label" for="anytlsFingerprint">TLS Client Fingerprint</label>
                <select id="anytlsFingerprint" name="anytlsFingerprint" class="form-control code-input">
                  <option value="chrome" ${settings.anytlsFingerprint === "chrome" ? "selected" : ""}>Chrome (Default - Highest Compatibility)</option>
                  <option value="firefox" ${settings.anytlsFingerprint === "firefox" ? "selected" : ""}>Firefox</option>
                  <option value="safari" ${settings.anytlsFingerprint === "safari" ? "selected" : ""}>Safari / iOS</option>
                  <option value="edge" ${settings.anytlsFingerprint === "edge" ? "selected" : ""}>Edge</option>
                  <option value="randomized" ${settings.anytlsFingerprint === "randomized" ? "selected" : ""}>Randomized Chameleon</option>
                </select>
              </div>

              <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label" for="anytlsAlpn">TLS ALPN Negotiation</label>
                <input type="text" id="anytlsAlpn" name="anytlsAlpn" class="form-control code-input" value="${settings.anytlsAlpn || "h2,http/1.1"}" placeholder="h2,http/1.1" />
              </div>
            </div>

          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%; height: 42px;">
            <span>Save Protocol &amp; Inbound Settings to KV</span>
            <span>\u2728</span>
          </button>
        </form>

      </section>

      <!-- ====================================================================
           TAB 5: DNS SETTINGS (UPSTREAM DOH SELECTOR & TESTER)
           ==================================================================== -->
      <section id="tab-dns" class="tab-pane ${initialTab === "dns" ? "active" : ""}">
        ${dnsControls(settings.clientDns)}
        
        <div class="grid-2col" style="margin-bottom: 16px;">
          <!-- Upstream Provider Selector -->
          <div class="card">
            <div class="card-title">
              <span>\u{1F310}</span>
              <span>Upstream DoH Provider &amp; Custom DNS Server</span>
            </div>
            <p class="card-desc">Select primary upstream DNS-over-HTTPS resolver or configure an arbitrary private DoH / DNS endpoint.</p>

            <form action="/panel/settings/protocols" method="POST">
            <div class="form-group" style="margin-bottom: 14px;">
              <label class="form-label" for="dnsCustom">Custom DoH / DNS Upstream URL (Optional)</label>
              <input type="text" id="dnsCustom" name="dnsCustom" class="form-control code-input" value="${settings.dnsCustom || ""}" placeholder="e.g. https://dns.adguard-dns.com/dns-query or https://dns.alidns.com/dns-query" />
              <div style="font-size: 11px; color: var(--theme-text-muted); margin-top: 4px;">
                \u{1F4A1} Overrides the primary upstream for /dns-query and /dns-json. Client subscriptions use it when their resolver is set to panel.
              </div>
            </div>

              <div class="form-group">
                <label class="form-label" for="dnsDoHMain">Primary Upstream DoH URL</label>
                <input type="text" id="dnsDoHMain" name="dnsDoH" class="form-control code-input" value="${settings.dnsDoH}" />
              </div>

              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 14px;">
                <button type="button" class="btn btn-secondary btn-sm" onclick="setDohUpstream('https://cloudflare-dns.com/dns-query')">Cloudflare (Default)</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="setDohUpstream('https://dns.google/dns-query')">Google (8.8.8.8)</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="setDohUpstream('https://dns.adguard-dns.com/dns-query')">AdGuard (AdBlock)</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="setDohUpstream('https://dns.quad9.net/dns-query')">Quad9 (Security)</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="setDohUpstream('https://dns.mullvad.net/dns-query')">Mullvad (Privacy)</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="setDohUpstream('https://freedns.controld.com/p0')">ControlD</button>
              </div>

              <button type="submit" class="btn btn-primary btn-sm" style="width: 100%; height: 38px;">
                <span>Save DNS Provider to KV</span>
                <span>\u2728</span>
              </button>
            </form>
          </div>

          <!-- Live DNS Benchmark & Resolver -->
          <div class="card">
            <div class="card-title">
              <span>\u26A1</span>
              <span>Live DoH Query Tester</span>
            </div>
            <p class="card-desc">Direct RFC 8484 round-trip latency &amp; record verification tool.</p>

            <div style="display: flex; gap: 8px; margin-bottom: 10px; flex-wrap: wrap;">
              <input type="text" id="dnsPageTestDomain" class="form-control code-input" value="cloudflare.com" placeholder="e.g. google.com" style="flex: 2; min-width: 140px;" />
              <select id="dnsPageTestType" class="form-control code-input" style="flex: 1; min-width: 80px;">
                <option value="A" selected>A</option>
                <option value="AAAA">AAAA</option>
                <option value="CNAME">CNAME</option>
                <option value="TXT">TXT</option>
                <option value="NS">NS</option>
                <option value="MX">MX</option>
              </select>
              <button type="button" class="btn btn-primary btn-sm" onclick="runCustomDohTest('dnsPageTestDomain', 'dnsPageTestType', 'dnsPageTestResult')" style="height: 38px; padding: 0 14px;">
                <span>\u26A1 Resolve</span>
              </button>
            </div>

            <div id="dnsPageTestResult" style="background: var(--theme-surface-strong); border: 1px solid var(--theme-border); border-radius: 10px; padding: 10px 12px; font-size: 12px; min-height: 80px;">
              <span style="color: var(--theme-text-muted);">Enter a domain and click Resolve to benchmark upstream DNS latency.</span>
            </div>
          </div>
        </div>

      </section>

      <!-- ====================================================================
           TAB 6: ROUTING & CHAIN (PRESETS, FRAGMENT, SOCKS/HTTP CHAIN)
           ==================================================================== -->
      <section id="tab-routing" class="tab-pane ${initialTab === "routing" ? "active" : ""}">
        
        <form action="/panel/settings/protocols" method="POST">
          <div class="grid-2col" style="margin-bottom: 16px;">
            
            <!-- Card 1: Subscription Routing Presets -->
            <div class="card">
              <div class="card-title">
                <span>\u{1F500}</span>
                <span>Subscription Routing Presets</span>
              </div>
              <p class="card-desc">Injected into Clash.Meta, Sing-box, and Xray subscription configs.</p>

              <div class="form-group">
                <label class="form-label" for="routingPreset">Active Preset</label>
                <select id="routingPreset" name="routingPreset" class="form-control">
                  <option value="off" ${settings.routingPreset === "off" ? "selected" : ""}>Off (Default &bull; Route all traffic via Proxy)</option>
                  <option value="bypass-iran" ${settings.routingPreset === "bypass-iran" ? "selected" : ""}>Bypass Iran (GEOIP/Geosite IR &amp; .ir direct)</option>
                  <option value="bypass-russia" ${settings.routingPreset === "bypass-russia" ? "selected" : ""}>Bypass Russia (GEOIP/Geosite RU &amp; .ru/.su/.\u0440\u0444 direct)</option>
                  <option value="bypass-iran-russia" ${settings.routingPreset === "bypass-iran-russia" ? "selected" : ""}>Bypass Iran + Russia</option>
                  <option value="bypass-cn" ${settings.routingPreset === "bypass-cn" ? "selected" : ""}>Bypass China (GEOIP/Geosite CN &amp; .cn direct)</option>
                  <option value="block-ads" ${settings.routingPreset === "block-ads" ? "selected" : ""}>Block Ads &amp; Malicious Trackers</option>
                </select>
              </div>

              <!-- TLS Fragment Settings -->
              <div style="margin-top: 18px; padding-top: 14px; border-top: 1px dashed var(--theme-border);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                  <strong style="font-size: 13.5px;">Client-Side TLS Fragmentation</strong>
                  <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px; font-weight: 700; color: var(--theme-primary);">
                    <input type="checkbox" name="fragmentEnabled" ${settings.fragmentEnabled ? "checked" : ""} style="accent-color: var(--theme-primary); width: 16px; height: 16px;" />
                    <span>Enable</span>
                  </label>
                </div>
                <p style="color: var(--theme-text-muted); font-size: 11.5px; margin-bottom: 10px;">Splits ClientHello TLS packets for DPI evasion in v2rayN and Nekobox.</p>

                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;">
                  <div>
                    <label class="form-label" style="font-size: 11px;">Packets</label>
                    <input type="text" name="fragmentPackets" class="form-control code-input" value="${settings.fragmentPackets}" placeholder="tlshello" />
                  </div>
                  <div>
                    <label class="form-label" style="font-size: 11px;">Length</label>
                    <input type="text" name="fragmentLength" class="form-control code-input" value="${settings.fragmentLength}" placeholder="100-200" />
                  </div>
                  <div>
                    <label class="form-label" style="font-size: 11px;">Interval ms</label>
                    <input type="text" name="fragmentInterval" class="form-control code-input" value="${settings.fragmentInterval}" placeholder="10-20" />
                  </div>
                </div>
              </div>
            </div>

            <!-- Card 2: Dual-Layer Chain Proxy -->
            <div class="card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <div class="card-title" style="margin-bottom: 0;">
                  <span>\u{1F517}</span>
                  <span>Dual-Layer Chain Proxy</span>
                </div>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px; font-weight: 700; color: var(--theme-secondary);">
                  <input type="checkbox" name="chainEnabled" ${settings.chainEnabled ? "checked" : ""} style="accent-color: var(--theme-secondary); width: 16px; height: 16px;" />
                  <span>Enable Chain</span>
                </label>
              </div>
              <p class="card-desc">Worker forwards site traffic through your external HTTP/SOCKS5 exit. Test that the exit can access your target sites. Client subscriptions connect to the Worker normally; upstream credentials stay on the server.</p>

              <div style="display: grid; grid-template-columns: 1fr 2fr 1fr; gap: 8px; margin-bottom: 10px;">
                <div>
                  <label class="form-label" style="font-size: 11px;">Type</label>
                  <select name="chainType" class="form-control code-input">
                    <option value="socks" ${settings.chainType === "socks" ? "selected" : ""}>SOCKS5</option>
                    <option value="http" ${settings.chainType === "http" ? "selected" : ""}>HTTP</option>
                  </select>
                </div>
                <div>
                  <label class="form-label" style="font-size: 11px;">Upstream Address</label>
                  <input type="text" name="chainAddress" class="form-control code-input" value="${escapeHtml(settings.chainAddress)}" placeholder="proxy.example.com" />
                </div>
                <div>
                  <label class="form-label" style="font-size: 11px;">Port</label>
                  <input type="number" name="chainPort" class="form-control code-input" value="${settings.chainPort}" placeholder="1080" />
                </div>
              </div>

              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px;">
                <div>
                  <label class="form-label" style="font-size: 11px;">Auth (Optional)</label>
                  <input type="text" name="chainAuth" class="form-control code-input" value="${escapeHtml(settings.chainAuth)}" placeholder="user:pass" />
                </div>
                <div>
                  <label class="form-label" style="font-size: 11px;">Security</label>
                  <select name="chainSecurity" class="form-control code-input">
                    <option value="none" ${settings.chainSecurity === "none" ? "selected" : ""}>None</option>
                    <option value="tls" ${settings.chainSecurity === "tls" ? "selected" : ""}>TLS (HTTPS proxy / SOCKS over TLS)</option>
                  </select>
                </div>
              </div>
              <p class="card-desc" style="margin: 0;">Saving with the chain enabled runs a live test through the upstream and reports the result. While enabled, proxy traffic never falls back to a direct connection.</p>
            </div>

          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%; height: 42px;">
            <span>Save Routing &amp; Chain Rules to KV</span>
            <span>\u2728</span>
          </button>
        </form>

      </section>

      <!-- ====================================================================
           TAB 7: SETTINGS (PASSWORD, P2P SYNC, APPEARANCE)
           ==================================================================== -->
      <section id="tab-settings" class="tab-pane ${initialTab === "settings" ? "active" : ""}">
        
        <div class="grid-2col" style="margin-bottom: 16px;">
          <!-- Password Card -->
          <div class="card">
            <div class="card-title">
              <span>\u{1F511}</span>
              <span>Change Administrator Password</span>
            </div>
            <p class="card-desc">Updates your master dashboard password stored securely in Cloudflare KV.</p>

            <form action="/panel/settings/password" method="POST">
              <div class="form-group">
                <label class="form-label" for="currentPassword">Current Password</label>
                <input type="password" id="currentPassword" name="currentPassword" class="form-control" required placeholder="Current password" />
              </div>

              <div class="form-group">
                <label class="form-label" for="newPassword">New Password</label>
                <input type="password" id="newPassword" name="newPassword" class="form-control" required minlength="8" placeholder="Min 8 characters" />
              </div>

              <div class="form-group">
                <label class="form-label" for="confirmPassword">Confirm New Password</label>
                <input type="password" id="confirmPassword" name="confirmPassword" class="form-control" required minlength="8" placeholder="Repeat new password" />
              </div>

              <button type="submit" class="btn btn-primary" style="width: 100%; height: 40px; margin-top: 4px;">
                <span>Update Password in KV</span>
                <span>\u{1F512}</span>
              </button>
            </form>
          </div>

          <!-- Node Share P2P Peer Sync -->
          <div class="card">
            <div class="card-title">
              <span>\u{1F504}</span>
              <span>Node Share (Peer Sync)</span>
            </div>
            <p class="card-desc">Safely exchange routing, DoH, and chain settings with other HEX instances.</p>

            <div class="form-group">
              <label class="form-label">Node Share Secret Token</label>
              <div class="copy-wrapper">
                <input type="text" readonly class="form-control code-input" value="${settings.nodeShareToken}" />
                <div class="copy-actions">
                  <button type="button" class="btn btn-secondary btn-sm" onclick="copyToClipboard('${settings.nodeShareToken}')">\u{1F4CB} Copy</button>
                  <form action="/panel/settings/nodeshare/regen" method="POST" style="margin: 0;">
                    <button type="submit" class="btn btn-secondary btn-sm">\u{1F3B2} Regen</button>
                  </form>
                </div>
              </div>
            </div>

            <div style="margin-top: 14px; padding-top: 12px; border-top: 1px dashed var(--theme-border);">
              <label class="form-label">Import HEX JSON Configuration</label>
              <textarea id="importJsonText" class="form-control code-input" rows="3" placeholder='Paste {"settings": {...}} exported from another HEX node'></textarea>
              <button type="button" class="btn btn-secondary btn-sm" style="width: 100%; height: 36px; margin-top: 8px;" onclick="importNodeConfig()">
                <span>Merge Configuration into KV</span>
                <span>\u{1F4E5}</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Appearance & Theme Selector Card -->
        <div class="card">
          <div class="card-title">
            <span>\u{1F3A8}</span>
            <span>Aesthetic Themes &amp; Wallpaper Engine</span>
          </div>
          <p class="card-desc">5 wallpaper themes: Lunar Eclipse, Emerald Forest, Blood Moon Ronin, Neon Night and Dark Knight.</p>

          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <select class="form-control theme-selector-dropdown" onchange="setHEXTheme(this.value)" style="flex: 2; min-width: 200px;">
              <option value="theme-1">Theme 1 \u2014 Lunar Eclipse</option>
              <option value="theme-2">Theme 2 \u2014 Emerald Forest</option>
              <option value="theme-3">Theme 3 \u2014 Blood Moon Ronin</option>
              <option value="theme-4">Theme 4 \u2014 Neon Night</option>
              <option value="theme-5">Theme 5 \u2014 Dark Knight</option>
            </select>
            <button type="button" class="btn btn-primary" onclick="randomizeHEXTheme()" style="flex: 1; min-width: 160px;">
              <span>\u{1F3B2} Randomize Theme</span>
            </button>
          </div>
        </div>

      </section>

      <!-- ====================================================================
           TAB 8: USERS (add user + list, separate from Settings)
           ==================================================================== -->
      <section id="tab-users" class="tab-pane ${initialTab === "users" ? "active" : ""}">

        <div class="card" style="margin-bottom:16px;">
          <div class="card-title">
            <span>&#x2795;</span>
            <span>&#x627;&#x641;&#x632;&#x648;&#x62F;&#x646; &#x6A9;&#x627;&#x631;&#x628;&#x631; &#x62C;&#x62F;&#x6CC;&#x62F;</span>
          </div>
          <p class="card-desc">&#x628;&#x631;&#x627;&#x6CC; &#x647;&#x631; &#x6A9;&#x627;&#x631;&#x628;&#x631; &#x6CC;&#x6A9; UUID &#x627;&#x62E;&#x62A;&#x635;&#x627;&#x635;&#x6CC; &#x648; &#x6CC;&#x6A9; &#x644;&#x6CC;&#x646;&#x6A9; &#x627;&#x634;&#x62A;&#x631;&#x627;&#x6A9; &#x62C;&#x62F;&#x627; &#x633;&#x627;&#x62E;&#x62A;&#x647; &#x645;&#x6CC;&#x200C;&#x634;&#x648;&#x62F;. &#x628;&#x627; &#x62D;&#x630;&#x641; &#x6A9;&#x627;&#x631;&#x628;&#x631;&#x60C; UUID &#x648; &#x644;&#x6CC;&#x646;&#x6A9; &#x627;&#x648; &#x627;&#x632; &#x6A9;&#x627;&#x631; &#x645;&#x6CC;&#x200C;&#x627;&#x641;&#x62A;&#x62F;.</p>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <input id="hexUserName" class="form-control" placeholder="&#x646;&#x627;&#x645; &#x6A9;&#x627;&#x631;&#x628;&#x631; (&#x645;&#x62B;&#x644;&#x627;&#x64B; Alireza)" style="flex:2; min-width:180px;" />
            <select id="hexUserFlag" class="form-control" style="flex:1; min-width:150px;">
              <option value="de">&#x1F1E9;&#x1F1EA; Germany (DE)</option>
              <option value="us">&#x1F1FA;&#x1F1F8; United States (US)</option>
              <option value="ir" selected>&#x1F1EE;&#x1F1F7; Iran (IR)</option>
              <option value="tr">&#x1F1F9;&#x1F1F7; Turkey (TR)</option>
              <option value="nl">&#x1F1F3;&#x1F1F1; Netherlands (NL)</option>
              <option value="gb">&#x1F1EC;&#x1F1E7; United Kingdom (GB)</option>
              <option value="fr">&#x1F1EB;&#x1F1F7; France (FR)</option>
              <option value="ca">&#x1F1E8;&#x1F1E6; Canada (CA)</option>
              <option value="ae">&#x1F1E6;&#x1F1EA; UAE (AE)</option>
              <option value="sg">&#x1F1F8;&#x1F1EC; Singapore (SG)</option>
              <option value="jp">&#x1F1EF;&#x1F1F5; Japan (JP)</option>
              <option value="se">&#x1F1F8;&#x1F1EA; Sweden (SE)</option>
              <option value="ru">&#x1F1F7;&#x1F1FA; Russia (RU)</option>
            </select>
            <button type="button" class="btn btn-primary" onclick="hexAddUserRow()">&#x627;&#x641;&#x632;&#x648;&#x62F;&#x646; &#x6A9;&#x627;&#x631;&#x628;&#x631; +</button>
          </div>
        </div>

        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:10px;">
            <div class="card-title" style="margin-bottom:0;">
              <span>&#x1F465;</span>
              <span>&#x644;&#x6CC;&#x633;&#x62A; &#x6A9;&#x627;&#x631;&#x628;&#x631;&#x627;&#x646;</span>
              <span id="hexUserCount" class="badge badge-sky" style="margin-left:6px;">0 &#x6A9;&#x627;&#x631;&#x628;&#x631;</span>
            </div>
            <span class="badge badge-mint">&#x630;&#x62E;&#x6CC;&#x631;&#x647;&#x200C;&#x6CC; &#x62F;&#x627;&#x626;&#x645;&#x6CC; (KV) &#xB7; &#x628;&#x62F;&#x648;&#x646; &#x627;&#x646;&#x642;&#x636;&#x627;</span>
          </div>
          <p class="card-desc">&#x647;&#x631; &#x6A9;&#x627;&#x631;&#x628;&#x631; UUID &#x648; &#x644;&#x6CC;&#x646;&#x6A9; &#x627;&#x634;&#x62A;&#x631;&#x627;&#x6A9; &#x627;&#x62E;&#x62A;&#x635;&#x627;&#x635;&#x6CC; &#x62F;&#x627;&#x631;&#x62F; &#x648; &#x6A9;&#x627;&#x646;&#x641;&#x6CC;&#x6AF;&#x200C;&#x647;&#x627; &#x62F;&#x631; &#x6A9;&#x644;&#x627;&#x6CC;&#x646;&#x62A; &#x628;&#x627; &#x646;&#x627;&#x645; &#x648; &#x67E;&#x631;&#x686;&#x645; &#x647;&#x645;&#x627;&#x646; &#x6A9;&#x627;&#x631;&#x628;&#x631; &#x646;&#x645;&#x627;&#x6CC;&#x634; &#x62F;&#x627;&#x62F;&#x647; &#x645;&#x6CC;&#x200C;&#x634;&#x648;&#x646;&#x62F;. &#xAB;&#x62A;&#x648;&#x6A9;&#x646; &#x62C;&#x62F;&#x6CC;&#x62F;&#xBB; &#x641;&#x642;&#x637; &#x644;&#x6CC;&#x646;&#x6A9; &#x627;&#x634;&#x62A;&#x631;&#x627;&#x6A9; &#x631;&#x627; &#x639;&#x648;&#x636; &#x645;&#x6CC;&#x200C;&#x6A9;&#x646;&#x62F; &#x648; &#xAB;UUID &#x62C;&#x62F;&#x6CC;&#x62F;&#xBB; UUID &#x627;&#x62A;&#x635;&#x627;&#x644; &#x631;&#x627; &#x639;&#x648;&#x636; &#x645;&#x6CC;&#x200C;&#x6A9;&#x646;&#x62F; (&#x6A9;&#x627;&#x646;&#x641;&#x6CC;&#x6AF; &#x642;&#x628;&#x644;&#x6CC; &#x6A9;&#x627;&#x631; &#x646;&#x645;&#x6CC;&#x200C;&#x6A9;&#x646;&#x62F;).</p>
          <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; text-align:left; font-size:13px;">
              <thead>
                <tr style="border-bottom:1.5px solid var(--theme-border); color:var(--theme-text-muted); font-family:'Quicksand',sans-serif;">
                  <th style="padding:8px 10px;">&#x646;&#x627;&#x645; + &#x67E;&#x631;&#x686;&#x645;</th>
                  <th style="padding:8px 10px;">&#x6A9;&#x62F; &#x6A9;&#x634;&#x648;&#x631;</th>
                  <th style="padding:8px 10px;">UUID</th>
                  <th style="padding:8px 10px;">&#x644;&#x6CC;&#x646;&#x6A9; &#x627;&#x634;&#x62A;&#x631;&#x627;&#x6A9; &#x627;&#x62E;&#x62A;&#x635;&#x627;&#x635;&#x6CC;</th>
                  <th style="padding:8px 10px; text-align:right;">&#x639;&#x645;&#x644;&#x6CC;&#x627;&#x62A;</th>
                </tr>
              </thead>
              <tbody id="hexUserTableBody">
              </tbody>
            </table>
          </div>
        </div>

      </section>


    </main>
  </div>

  <script>

    // HEX \u{2014} Users (persistent via KV, per-user subscription link).
    // NOTE: this code is inside a server-side template string: no backticks, dollar-brace or backslashes here.
    var HEX_FLAGS = { de:"\u{1F1E9}\u{1F1EA}", us:"\u{1F1FA}\u{1F1F8}", ir:"\u{1F1EE}\u{1F1F7}", tr:"\u{1F1F9}\u{1F1F7}", nl:"\u{1F1F3}\u{1F1F1}", gb:"\u{1F1EC}\u{1F1E7}", fr:"\u{1F1EB}\u{1F1F7}", ca:"\u{1F1E8}\u{1F1E6}", ae:"\u{1F1E6}\u{1F1EA}", sg:"\u{1F1F8}\u{1F1EC}", jp:"\u{1F1EF}\u{1F1F5}", se:"\u{1F1F8}\u{1F1EA}", ru:"\u{1F1F7}\u{1F1FA}" };
    var HEX_FORMATS = [["xray","Xray / v2rayN / Hiddify"],["clash","Clash.Meta"],["singbox","Sing-box"],["vless","VLESS (plain)"],["trojan","Trojan (plain)"]];
    var hexUsers = [];
    var hexFmt = "xray";
    function hexFlag(code){ return HEX_FLAGS[(code||"").toLowerCase()] || "\u{1F3F3}\u{FE0F}"; }
    function hexSubUrl(u, fmt){ return location.origin + "/sub/" + fmt + "?token=" + encodeURIComponent(u.token || ""); }
    function hexRenderUsers(){
      var tbody = document.getElementById("hexUserTableBody");
      var cnt = document.getElementById("hexUserCount");
      if (cnt) cnt.textContent = hexUsers.length + " \u{6A9}\u{627}\u{631}\u{628}\u{631}";
      if (!tbody) return;
      tbody.innerHTML = "";
      if (!hexUsers.length) {
        var er = document.createElement("tr");
        var ec = document.createElement("td");
        ec.colSpan = 5;
        ec.style.cssText = "padding:14px; text-align:center; color:var(--theme-text-muted);";
        ec.textContent = "\u{647}\u{646}\u{648}\u{632} \u{6A9}\u{627}\u{631}\u{628}\u{631}\u{6CC} \u{627}\u{636}\u{627}\u{641}\u{647} \u{646}\u{634}\u{62F}\u{647} \u{627}\u{633}\u{62A}";
        er.appendChild(ec);
        tbody.appendChild(er);
        return;
      }
      hexUsers.forEach(function(u){
        var tr = document.createElement("tr");
        tr.style.borderBottom = "1px solid var(--theme-border)";
        var td1 = document.createElement("td");
        td1.style.cssText = "padding:10px; display:flex; align-items:center; gap:8px;";
        var fl = document.createElement("span");
        fl.style.fontSize = "18px";
        fl.textContent = hexFlag(u.cc);
        var nm = document.createElement("strong");
        nm.textContent = u.name;
        td1.appendChild(fl); td1.appendChild(nm);
        var td2 = document.createElement("td");
        td2.style.cssText = "padding:10px; text-transform:uppercase; font-size:12px; color:var(--theme-text-muted);";
        td2.textContent = u.cc;
        var tdU = document.createElement("td");
        tdU.style.cssText = "padding:10px; min-width:270px;";
        var uin = document.createElement("input");
        uin.type = "text"; uin.readOnly = true;
        uin.className = "form-control code-input";
        uin.style.cssText = "width:100%; font-size:11px;";
        uin.value = u.uuid || "";
        var ucp = document.createElement("button");
        ucp.type = "button";
        ucp.className = "btn btn-primary btn-sm";
        ucp.style.marginTop = "6px";
        ucp.textContent = "\u{6A9}\u{67E}\u{6CC} UUID";
        ucp.onclick = function(){ copyToClipboard(uin.value); };
        tdU.appendChild(uin); tdU.appendChild(ucp);
        var tdL = document.createElement("td");
        tdL.style.cssText = "padding:10px; min-width:290px;";
        var sel = document.createElement("select");
        sel.className = "form-control";
        sel.style.cssText = "width:auto; padding:4px 8px; font-size:12px; margin-bottom:6px;";
        HEX_FORMATS.forEach(function(f){
          var o = document.createElement("option");
          o.value = f[0]; o.textContent = f[1];
          if (f[0] === hexFmt) o.selected = true;
          sel.appendChild(o);
        });
        var inp = document.createElement("input");
        inp.type = "text"; inp.readOnly = true;
        inp.className = "form-control code-input";
        inp.style.cssText = "width:100%; font-size:11px;";
        var upd = function(){ inp.value = hexSubUrl(u, sel.value); };
        sel.onchange = function(){ hexFmt = sel.value; upd(); };
        upd();
        var cp = document.createElement("button");
        cp.type = "button";
        cp.className = "btn btn-primary btn-sm";
        cp.style.marginTop = "6px";
        cp.textContent = "\u{6A9}\u{67E}\u{6CC} \u{644}\u{6CC}\u{646}\u{6A9}";
        cp.onclick = function(){ copyToClipboard(inp.value); };
        tdL.appendChild(sel); tdL.appendChild(inp); tdL.appendChild(cp);
        var td3 = document.createElement("td");
        td3.style.cssText = "padding:10px; text-align:right; white-space:nowrap;";
        var rg = document.createElement("button");
        rg.type = "button";
        rg.className = "btn btn-secondary btn-sm";
        rg.style.marginRight = "6px";
        rg.textContent = "\u{62A}\u{648}\u{6A9}\u{646} \u{62C}\u{62F}\u{6CC}\u{62F}";
        rg.onclick = function(){ hexRegenUser(u.id); };
        var del = document.createElement("button");
        del.type = "button";
        del.className = "btn btn-secondary btn-sm";
        del.textContent = "\u{62D}\u{630}\u{641}";
        del.onclick = function(){ hexDelUser(u.id); };
        var rgu = document.createElement("button");
        rgu.type = "button";
        rgu.className = "btn btn-secondary btn-sm";
        rgu.style.marginRight = "6px";
        rgu.textContent = "UUID \u{62C}\u{62F}\u{6CC}\u{62F}";
        rgu.onclick = function(){ hexRegenUuid(u.id); };
        td3.appendChild(rg); td3.appendChild(rgu); td3.appendChild(del);
        tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(tdU); tr.appendChild(tdL); tr.appendChild(td3);
        tbody.appendChild(tr);
      });
    }
    function hexLoadUsers(){
      fetch("/panel/settings/users", { credentials: "same-origin", cache: "no-store" })
        .then(function(r){ return r.json(); })
        .then(function(d){
          if (d && d.ok) { hexUsers = d.users || []; hexRenderUsers(); }
          else { showToast("\u{62E}\u{637}\u{627} \u{62F}\u{631} \u{62E}\u{648}\u{627}\u{646}\u{62F}\u{646} \u{6A9}\u{627}\u{631}\u{628}\u{631}\u{627}\u{646}: " + ((d && d.error) || "\u{646}\u{627}\u{645}\u{634}\u{62E}\u{635}")); }
        })
        .catch(function(){ showToast("\u{62E}\u{637}\u{627} \u{62F}\u{631} \u{627}\u{631}\u{62A}\u{628}\u{627}\u{637} \u{628}\u{627} \u{633}\u{631}\u{648}\u{631}"); });
    }
    function hexSaveUsers(){
      return fetch("/panel/settings/users", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ users: hexUsers })
      })
        .then(function(r){ return r.json(); })
        .then(function(d){
          if (!d || !d.ok) throw new Error((d && d.error) || "\u{630}\u{62E}\u{6CC}\u{631}\u{647} \u{646}\u{634}\u{62F}");
          hexUsers = d.users || hexUsers;
          hexRenderUsers();
        })
        .catch(function(e){
          showToast("\u{630}\u{62E}\u{6CC}\u{631}\u{647} \u{646}\u{634}\u{62F}: " + e.message);
          hexLoadUsers();
        });
    }
    function hexAddUserRow(){
      var nameEl = document.getElementById("hexUserName");
      var ccEl = document.getElementById("hexUserFlag");
      var name = ((nameEl && nameEl.value) || "").trim();
      var cc = ((ccEl && ccEl.value) || "de").trim().toLowerCase();
      if (!name) { showToast("\u{646}\u{627}\u{645} \u{6A9}\u{627}\u{631}\u{628}\u{631} \u{631}\u{627} \u{648}\u{627}\u{631}\u{62F} \u{6A9}\u{646}\u{6CC}\u{62F}"); return; }
      hexUsers.push({ id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name: name.slice(0, 60), cc: cc });
      nameEl.value = "";
      hexRenderUsers();
      hexSaveUsers().then(function(){ showToast("\u{6A9}\u{627}\u{631}\u{628}\u{631} \u{630}\u{62E}\u{6CC}\u{631}\u{647} \u{634}\u{62F}: " + name + " " + hexFlag(cc)); });
    }
    function hexDelUser(id){
      if (!confirm("\u{627}\u{6CC}\u{646} \u{6A9}\u{627}\u{631}\u{628}\u{631} \u{62D}\u{630}\u{641} \u{634}\u{648}\u{62F}\u{61F} \u{644}\u{6CC}\u{646}\u{6A9} \u{627}\u{634}\u{62A}\u{631}\u{627}\u{6A9} \u{627}\u{648} \u{627}\u{632} \u{6A9}\u{627}\u{631} \u{645}\u{6CC}\u{200C}\u{627}\u{641}\u{62A}\u{62F}.")) return;
      hexUsers = hexUsers.filter(function(u){ return u.id !== id; });
      hexRenderUsers();
      hexSaveUsers();
    }
    function hexRegenUser(id){
      if (!confirm("\u{62A}\u{648}\u{6A9}\u{646} \u{62C}\u{62F}\u{6CC}\u{62F} \u{633}\u{627}\u{62E}\u{62A}\u{647} \u{634}\u{648}\u{62F}\u{61F} \u{644}\u{6CC}\u{646}\u{6A9} \u{642}\u{628}\u{644}\u{6CC} \u{627}\u{6CC}\u{646} \u{6A9}\u{627}\u{631}\u{628}\u{631} \u{627}\u{632} \u{6A9}\u{627}\u{631} \u{645}\u{6CC}\u{200C}\u{627}\u{641}\u{62A}\u{62F}.")) return;
      hexUsers = hexUsers.map(function(u){ return u.id === id ? { id: u.id, name: u.name, cc: u.cc, regen: true } : u; });
      hexSaveUsers().then(function(){ showToast("\u{62A}\u{648}\u{6A9}\u{646} \u{62C}\u{62F}\u{6CC}\u{62F} \u{633}\u{627}\u{62E}\u{62A}\u{647} \u{634}\u{62F}"); });
    }
    function hexRegenUuid(id){
      if (!confirm("UUID \u{62C}\u{62F}\u{6CC}\u{62F} \u{633}\u{627}\u{62E}\u{62A}\u{647} \u{634}\u{648}\u{62F}\u{61F} \u{6A9}\u{627}\u{646}\u{641}\u{6CC}\u{6AF} \u{642}\u{628}\u{644}\u{6CC} \u{627}\u{6CC}\u{646} \u{6A9}\u{627}\u{631}\u{628}\u{631} \u{627}\u{632} \u{6A9}\u{627}\u{631} \u{645}\u{6CC}\u{200C}\u{627}\u{641}\u{62A}\u{62F} \u{648} \u{628}\u{627}\u{6CC}\u{62F} \u{644}\u{6CC}\u{646}\u{6A9} \u{627}\u{634}\u{62A}\u{631}\u{627}\u{6A9} \u{631}\u{627} \u{62F}\u{648}\u{628}\u{627}\u{631}\u{647} \u{622}\u{67E}\u{62F}\u{6CC}\u{62A} \u{6A9}\u{646}\u{62F}.")) return;
      hexUsers = hexUsers.map(function(u){ return u.id === id ? { id: u.id, name: u.name, cc: u.cc, regenUuid: true } : u; });
      hexSaveUsers().then(function(){ showToast("UUID \u{62C}\u{62F}\u{6CC}\u{62F} \u{633}\u{627}\u{62E}\u{62A}\u{647} \u{634}\u{62F}"); });
    }
    hexLoadUsers();

    function switchTab(tabName) {
      document.querySelectorAll('.tab-pane').forEach(el => {
        el.style.display = 'none';
        el.classList.remove('active');
      });
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

      const targetPane = document.getElementById('tab-' + tabName);
      const targetNav = document.getElementById('nav-' + tabName);
      
      if (targetPane) {
        targetPane.style.display = 'block';
        targetPane.classList.add('active');
      }
      if (targetNav) targetNav.classList.add('active');

      const headings = {
        overview: { icon: '\u{1F4CA}', title: 'System Dashboard', sub: 'Pastel proxy command center & live tunnel stats' },
        subscriptions: { icon: '\u{1F517}', title: 'Client Subscriptions & Feeds', sub: 'Live VLESS, Trojan, Clash.Meta, Sing-box & DoH feeds' },
        protocols: { icon: '\u{1F6E1}\uFE0F', title: 'Proxy Protocols & Inbound', sub: 'UUID credentials, clean IP fronting & local listening rules' },
        dns: { icon: '\u{1F310}', title: 'DNS Gateway & Upstream Resolver', sub: 'Manage upstream DoH endpoints & test real-time query latency' },
        routing: { icon: '\u{1F500}', title: 'Routing Presets & Chain Proxy', sub: 'Geo-bypass rules, TLS ClientHello fragmentation & upstream chaining' },
        users: { icon: '\u{1F465}', title: 'Users', sub: 'Add users, per-user UUID & personal subscription links' },
        settings: { icon: '\u2699\uFE0F', title: 'System & Security Settings', sub: 'Administrator KV password, Node Share P2P sync & themes' }
      };

      if (headings[tabName]) {
        const iconEl = document.getElementById('page-icon');
        if (iconEl) iconEl.innerText = headings[tabName].icon;
        document.getElementById('page-heading').innerText = headings[tabName].title;
        document.getElementById('page-subheading').innerText = headings[tabName].sub;
      }

      window.location.hash = tabName;
      closeSidebar();
    }

    function generateRandomUuid() {
      if (crypto && crypto.randomUUID) {
        const el = document.getElementById('vlessUuid');
        if (el) el.value = crypto.randomUUID();
        showToast('Generated new UUID!');
      }
    }

    function generateRandomPassword() {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let res = "wd_";
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      for (let i = 0; i < 16; i++) {
        res += chars[arr[i] % chars.length];
      }
      const el = document.getElementById('trojanPassword');
      if (el) el.value = res;
      showToast('Generated new Trojan password!');
    }

    function generateRandomToken() {
      const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
      let res = "";
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      for (let i = 0; i < 16; i++) {
        res += chars[arr[i] % chars.length];
      }
      const el = document.getElementById('subToken');
      if (el) el.value = res;
      showToast('Generated new Sub token!');
    }

    async function runCustomDohTest(domainInputId, typeInputId, resultBoxId) {
      const domain = document.getElementById(domainInputId).value.trim();
      const type = document.getElementById(typeInputId).value;
      const resBox = document.getElementById(resultBoxId);
      if (!domain) {
        showToast('Please enter a domain to resolve!');
        return;
      }
      resBox.style.display = 'block';
      resBox.innerHTML = '<div style="color: var(--theme-text-muted); font-size: 12px;">Resolving ' + domain + ' (' + type + ')...</div>';

      const startTime = performance.now();
      try {
        const response = await fetch('/dns-json?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
        const duration = Math.round(performance.now() - startTime);
        if (!response.ok) {
          throw new Error('HTTP ' + response.status + ' ' + response.statusText);
        }
        const data = await response.json();

        let answersHtml = '';
        if (data.Answer && Array.isArray(data.Answer) && data.Answer.length > 0) {
          answersHtml = '<table style="width: 100%; border-collapse: collapse; font-size: 11.5px; margin-top: 6px;">' +
            '<thead><tr style="border-bottom: 1px solid var(--theme-border); color: var(--theme-text-muted);">' +
            '<th style="padding: 3px 6px; text-align: left;">Name</th>' +
            '<th style="padding: 3px 6px; text-align: left;">Type</th>' +
            '<th style="padding: 3px 6px; text-align: left;">TTL</th>' +
            '<th style="padding: 3px 6px; text-align: left;">Data</th>' +
            '</tr></thead><tbody>';
          data.Answer.forEach(ans => {
            answersHtml += '<tr style="border-bottom: 1px dashed var(--theme-border); font-family: var(--font-mono);">' +
              '<td style="padding: 4px 6px;">' + (ans.name || '') + '</td>' +
              '<td style="padding: 4px 6px;"><span class="badge badge-sky" style="font-size: 10px;">' + (ans.type || type) + '</span></td>' +
              '<td style="padding: 4px 6px;">' + (ans.TTL || '') + 's</td>' +
              '<td style="padding: 4px 6px; font-weight: 700; color: var(--theme-primary);">' + (ans.data || '') + '</td>' +
              '</tr>';
          });
          answersHtml += '</tbody></table>';
        } else {
          answersHtml = '<div style="margin-top: 6px; font-size: 11.5px; color: var(--theme-text-muted);">No Answer records returned (Status: ' + (data.Status === 0 ? 'NOERROR' : data.Status) + ')</div>';
        }

        resBox.innerHTML = 
          '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">' +
            '<div style="display: flex; align-items: center; gap: 6px;">' +
              '<span class="badge badge-mint" style="font-size: 10px;">Status: ' + (data.Status === 0 ? 'NOERROR' : data.Status) + '</span>' +
              '<span style="font-size: 11.5px; color: var(--theme-text-muted);">Query: <strong>' + domain + '</strong></span>' +
            '</div>' +
            '<span class="badge badge-lavender" style="font-size: 10px;">RTT: ' + duration + ' ms</span>' +
          '</div>' + answersHtml;
      } catch (err) {
        resBox.innerHTML = '<div style="color: var(--theme-primary); font-size: 12px;">\u26A0\uFE0F Resolution error: ' + err.message + '</div>';
      }
    }

    function runDohTest() {
      runCustomDohTest('dohTestDomain', 'dohTestType', 'dohTestResult');
    }

    function setDohUpstream(url) {
      const el1 = document.getElementById('dnsDoH');
      const el2 = document.getElementById('dnsDoHMain');
      if (el1) el1.value = url;
      if (el2) el2.value = url;
      showToast('Selected DoH: ' + url);
    }

    function setCleanIp(ip) {
      const el = document.getElementById('proxyIp');
      if (el) {
        el.value = ip;
        showToast(ip ? 'Selected Clean IP: ' + ip : 'Reset to default Worker host');
      }
    }

    async function importNodeConfig() {
      const jsonStr = document.getElementById('importJsonText').value.trim();
      if (!jsonStr) {
        showToast('Please paste JSON configuration first!');
        return;
      }
      try {
        const parsed = JSON.parse(jsonStr);
        const res = await fetch('/api/node/import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed)
        });
        const result = await res.json();
        if (res.ok) {
          showToast('Imported ' + result.importedCount + ' settings! Reloading...');
          setTimeout(() => window.location.reload(), 1200);
        } else {
          alert('Import failed: ' + (result.message || result.error));
        }
      } catch (err) {
        alert('Invalid JSON syntax: ' + err.message);
      }
    }

    // Restore tab from URL hash on load
    window.addEventListener('DOMContentLoaded', () => {
      const validTabs = ['overview', 'subscriptions', 'protocols', 'dns', 'routing', 'users', 'settings'];
      const hash = window.location.hash.replace('#', '');
      if (hash && validTabs.includes(hash)) {
        switchTab(hash);
      } else if ('${initialTab}' && validTabs.includes('${initialTab}')) {
        switchTab('${initialTab}');
      }
    });
  </script>
  `;
  return renderPageLayout({
    title: "Dashboard",
    content
  });
}
function x25519(scalarBytes, uBytes) {
  const k = new Uint8Array(scalarBytes);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  let u = 0n;
  for (let i = 0; i < 32; i++) {
    u |= BigInt(uBytes[i]) << BigInt(8 * i);
  }
  const x1 = u % P;
  let x2 = 1n, z2 = 0n;
  let x3 = u % P, z3 = 1n;
  let swap = 0n;
  for (let t = 254; t >= 0; t--) {
    const byteIdx = t >> 3;
    const bitIdx = t & 7;
    const k_t = BigInt(k[byteIdx] >> bitIdx & 1);
    swap ^= k_t;
    if (swap === 1n) {
      let tmp = x2;
      x2 = x3;
      x3 = tmp;
      tmp = z2;
      z2 = z3;
      z3 = tmp;
    }
    swap = k_t;
    const A = (x2 + z2) % P;
    const AA = A * A % P;
    const B = (x2 - z2 + P) % P;
    const BB = B * B % P;
    const E = (AA - BB + P) % P;
    const C = (x3 + z3) % P;
    const D = (x3 - z3 + P) % P;
    const DA = D * A % P;
    const CB = C * B % P;
    const x3_new = (DA + CB) % P * ((DA + CB) % P) % P;
    const diff = (DA - CB + P) % P;
    const z3_new = x1 * (diff * diff % P) % P;
    const x2_new = AA * BB % P;
    const z2_new = E * ((AA + A24 * E % P) % P) % P;
    x2 = x2_new;
    z2 = z2_new;
    x3 = x3_new;
    z3 = z3_new;
  }
  if (swap === 1n) {
    let tmp = x2;
    x2 = x3;
    x3 = tmp;
    tmp = z2;
    z2 = z3;
    z3 = tmp;
  }
  function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp & 1n)
        res = res * base % mod;
      base = base * base % mod;
      exp >>= 1n;
    }
    return res;
  }
  __name(modPow, "modPow");
  __name2(modPow, "modPow");
  const result = x2 * modPow(z2, P - 2n, P) % P;
  const out = new Uint8Array(32);
  let temp = result;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}
function bytesToBase64(bytes) {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
function generateWireGuardKeyPair() {
  const priv = crypto.getRandomValues(new Uint8Array(32));
  priv[0] &= 248;
  priv[31] &= 127;
  priv[31] |= 64;
  const baseU = new Uint8Array(32);
  baseU[0] = 9;
  const pub = x25519(priv, baseU);
  return {
    privateKey: bytesToBase64(priv),
    publicKey: bytesToBase64(pub)
  };
}
function parseReservedBytes(clientIdB64) {
  if (!clientIdB64)
    return "";
  try {
    const binary = atob(clientIdB64);
    const bytes = [];
    for (let i = 0; i < binary.length; i++) {
      bytes.push(binary.charCodeAt(i));
    }
    return bytes.join(", ");
  } catch {
    return clientIdB64;
  }
}
async function registerWarpAccount(env2) {
  const kv = getKV(env2);
  if (!kv) {
    throw new Error("KV binding (BK_KV or WD_KV) is required to persist Warp credentials.");
  }
  const { privateKey, publicKey } = generateWireGuardKeyPair();
  const payload = {
    key: publicKey,
    install_id: "",
    fcm_token: "",
    tos: (/* @__PURE__ */ new Date()).toISOString(),
    model: "PC",
    serial_number: "",
    locale: "en_US"
  };
  const response = await fetch("https://api.cloudflareclient.com/v0a2158/reg", {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "User-Agent": "okhttp/3.12.1",
      "CF-Client-Version": "a-6.3-2158"
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const errText = await response.text().catch(() => "");
    throw new Error(`Cloudflare Warp API registration failed (status ${response.status}): ${errText.slice(0, 150)}`);
  }
  const data = await response.json();
  if (!data || !data.config) {
    throw new Error("Invalid response received from Cloudflare Warp API: missing config.");
  }
  const ipv4 = data.config.interface?.addresses?.v4 || "172.16.0.2";
  const ipv6 = data.config.interface?.addresses?.v6 || "";
  const peerPublicKey = data.config.peers?.[0]?.public_key || "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
  const endpoint = "162.159.192.1:2408";
  const reserved = parseReservedBytes(data.config.client_id);
  try {
    await kv.put(KV_KEYS.warpPrivateKey, privateKey);
    await kv.put(KV_KEYS.warpPeerPublicKey, peerPublicKey);
    if (ipv6)
      await kv.put(KV_KEYS.warpIPv6, ipv6);
    if (reserved)
      await kv.put(KV_KEYS.warpReserved, reserved);
    invalidateSettingsCache();
  } catch (putErr) {
    const isQuota = putErr?.message?.toLowerCase().includes("quota") || putErr?.message?.toLowerCase().includes("limit exceeded");
    if (isQuota) {
      throw new Error("KV write quota exceeded \u2014 try again after daily reset");
    }
    throw putErr;
  }
  return {
    ok: true,
    privateKey,
    publicKey,
    peerPublicKey,
    ipv4,
    ipv6,
    reserved,
    endpoint,
    accountId: data.id
  };
}
function generateRandomToken2(length = 24) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}
const HEX_USERS_KEY = "hex:users";
function hexFlagEmoji(cc) {
  const c = String(cc || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(c)) return "\u{1F3F3}\uFE0F";
  return String.fromCodePoint(...[...c].map((ch) => 127397 + ch.charCodeAt(0)));
}
function hexSafeLabel(name) {
  return String(name || "").replace(/[\u0000-\u001f"\\]/g, "").trim().slice(0, 60) || "User";
}
function hexB64Utf8(s) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(String(s))));
}
function hexNewUserUuid() {
  return crypto.randomUUID();
}
let hexUuidCache = { at: 0, list: null };
let hexTrojanCache = { at: 0, list: null };
function hexUserTrojanPass(uuid) {
  return "wd_" + String(uuid || "").replace(/-/g, "").slice(0, 24);
}
async function getAllowedTrojanPasswords(env2, settings) {
  const now = Date.now();
  if (hexTrojanCache.list && now - hexTrojanCache.at < 300000) return hexTrojanCache.list;
  const list = [String(settings.trojanPassword || "")];
  const kv = getKV(env2);
  if (kv) {
    const users = await hexReadUsers(kv);
    for (const u of users) if (u && u.uuid) list.push(hexUserTrojanPass(u.uuid));
  }
  hexTrojanCache = { at: now, list };
  return list;
}
function parseTrojanHeaderMulti(buffer, passwords) {
  for (const p of passwords) {
    if (!p) continue;
    const r = parseTrojanHeader(buffer, p);
    if (r) return r;
  }
  return null;
}
async function getAllowedVlessUuids(env2, settings) {
  const now = Date.now();
  if (hexUuidCache.list && now - hexUuidCache.at < 300000) return hexUuidCache.list;
  const list = [String(settings.vlessUuid || "").toLowerCase()];
  const kv = getKV(env2);
  if (kv) {
    const users = await hexReadUsers(kv);
    for (const u of users) if (u && u.uuid) list.push(String(u.uuid).toLowerCase());
  }
  hexUuidCache = { at: now, list };
  return list;
}
function hexNewUserToken() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hexReadUsers(kv) {
  try {
    const raw = await kv.get(HEX_USERS_KEY);
    const users = raw ? JSON.parse(raw) : [];
    return Array.isArray(users) ? users : [];
  } catch (e) {
    return [];
  }
}
async function findHexUserByToken(env2, token) {
  const kv = getKV(env2);
  if (!kv || !token || String(token).length < 16) return null;
  const users = await hexReadUsers(kv);
  for (const u of users) {
    if (u && u.token && constantTimeEquals(String(token), String(u.token))) {
      return { id: u.id, name: u.name, cc: u.cc, uuid: u.uuid || "" };
    }
  }
  return null;
}
async function handleHexUsersApi(request, env2) {
  const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
  const kv = getKV(env2);
  if (!kv) return json({ ok: false, error: "KV binding (BK_KV or WD_KV) is not available" }, 500);
  if (request.method === "GET") {
    const users = await hexReadUsers(kv);
    const seenUuid = new Set();
    let dirty = false;
    for (const u of users) {
      if (!u.token) { u.token = hexNewUserToken(); dirty = true; }
      if (!u.uuid || seenUuid.has(String(u.uuid).toLowerCase())) { u.uuid = hexNewUserUuid(); dirty = true; }
      seenUuid.add(String(u.uuid).toLowerCase());
    }
    if (dirty) {
      try { await kv.put(HEX_USERS_KEY, JSON.stringify(users)); hexUuidCache = { at: 0, list: null }; hexTrojanCache = { at: 0, list: null }; } catch (e) {}
    }
    return json({ ok: true, users });
  }
  if (request.method === "POST") {
    if (!(request.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) {
      return json({ ok: false, error: "Content-Type must be application/json" }, 415);
    }
    try {
      const body = await request.json();
      if (!body || !Array.isArray(body.users)) return json({ ok: false, error: "users array required" }, 400);
      const existing = await hexReadUsers(kv);
      const tokenById = new Map(existing.map((u) => [u.id, u.token]));
      const uuidById = new Map(existing.map((u) => [u.id, u.uuid]));
      const usedUuids = new Set();
      const seen = new Set();
      const users = [];
      for (const u of body.users.slice(0, 500)) {
        let id = String(u && u.id || "").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || crypto.randomUUID();
        if (seen.has(id)) id = crypto.randomUUID();
        seen.add(id);
        const name = String(u && u.name || "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, 60);
        if (!name) continue;
        const cc = String(u && u.cc || "").toLowerCase().replace(/[^a-z]/g, "").slice(0, 2);
        let token = tokenById.get(id);
        if (!token || (u && u.regen === true)) token = hexNewUserToken();
        let uuid = uuidById.get(id);
        if (!uuid || (u && u.regenUuid === true) || usedUuids.has(String(uuid).toLowerCase())) uuid = hexNewUserUuid();
        usedUuids.add(String(uuid).toLowerCase());
        users.push({ id, name, cc, token, uuid });
      }
      await kv.put(HEX_USERS_KEY, JSON.stringify(users));
      hexUuidCache = { at: 0, list: null }; hexTrojanCache = { at: 0, list: null };
      return json({ ok: true, users });
    } catch (err) {
      const msg = String(err && err.message || "").toLowerCase();
      const isQuota = msg.includes("quota") || msg.includes("limit exceeded");
      return json({ ok: false, error: isQuota ? "KV write quota exceeded \u2014 try again after daily reset" : (err.message || "Failed to save users") }, isQuota ? 429 : 500);
    }
  }
  return json({ ok: false, error: "Method not allowed" }, 405);
}
async function handlePanel(request, env2) {
  const url = new URL(request.url);
  const isConfigured = await hasConfiguredPassword(env2);
  if (!isConfigured) {
    return Response.redirect(`${url.origin}/panel/setup`, 302);
  }
  const cookies = parseCookies(request);
  const token = cookies[APP_CONFIG.cookieName];
  if (!token) {
    return Response.redirect(`${url.origin}/panel/login`, 302);
  }
  const session = await verifySessionToken(token, env2);
  if (!session) {
    return Response.redirect(
      `${url.origin}/panel/login?error=${encodeURIComponent("Session expired. Please log in again.")}`,
      302
    );
  }
  if (url.pathname.replace(/\/+$/, "") === "/panel/settings/users") {
    return await handleHexUsersApi(request, env2);
  }
  let settings = await getOrInitSettings(env2);
  let flashMessage;
  if (url.searchParams.get("setup") === "success") {
    flashMessage = { type: "success", text: "Welcome to HEX Panel! Administrator password configured successfully. \u2728" };
  }
  let initialTab = "overview";
  const pathname = url.pathname;
  const TAB_ROUTES = {
    protocols: "protocols",
    subscriptions: "subscriptions",
    dns: "dns",
    routing: "routing",
    settings: "settings",
    users: "users",
    overview: "overview",
    password: "settings",
    nodeshare: "settings"
  };
  const lastSegment = pathname.split("/").filter(Boolean).pop() || "";
  if (TAB_ROUTES[lastSegment]) {
    initialTab = TAB_ROUTES[lastSegment];
  }
  if (request.method === "POST") {
    if (pathname === "/panel/settings/password") {
      initialTab = "settings";
      try {
        const formData = await request.formData();
        const currentPass = String(formData.get("currentPassword") || "");
        const newPass = String(formData.get("newPassword") || "");
        const confirmPass = String(formData.get("confirmPassword") || "");
        const isCurrentValid = await verifyPassword(currentPass, env2);
        if (!isCurrentValid) {
          flashMessage = { type: "error", text: "Current password was incorrect." };
        } else if (newPass !== confirmPass) {
          flashMessage = { type: "error", text: "New passwords do not match." };
        } else if (newPass.length < 8) {
          flashMessage = { type: "error", text: "New password must be at least 8 characters." };
        } else {
          await setPassword(newPass, env2);
          invalidatePasswordCache();
          flashMessage = { type: "success", text: "Password updated successfully in KV storage! \u{1F338}" };
        }
      } catch (err) {
        const isQuota = err?.message?.toLowerCase().includes("quota") || err?.message?.toLowerCase().includes("limit exceeded");
        flashMessage = {
          type: "error",
          text: isQuota ? "KV write quota exceeded \u2014 try again after daily reset" : err.message || "Failed to update password."
        };
      }
    } else if (pathname === "/panel/settings/nodeshare/regen") {
      initialTab = "settings";
      try {
        const kv = getKV(env2);
        if (!kv) {
          throw new Error("KV binding (BK_KV or WD_KV) is not available");
        }
        const newToken = generateRandomToken2(24);
        await kv.put(KV_KEYS.nodeShareToken, newToken);
        invalidateSettingsCache();
        settings = await getOrInitSettings(env2);
        flashMessage = { type: "success", text: "New Node Share token generated! \u2728" };
      } catch (err) {
        const isQuota = err?.message?.toLowerCase().includes("quota") || err?.message?.toLowerCase().includes("limit exceeded");
        flashMessage = {
          type: "error",
          text: isQuota ? "KV write quota exceeded \u2014 try again after daily reset" : err.message || "Failed to regenerate share token."
        };
      }
    } else if (pathname === "/panel/settings/protocols") {
      try {
        const kv = getKV(env2);
        if (!kv) {
          throw new Error("KV binding (BK_KV or WD_KV) is not available");
        }
        const formData = await request.formData();
        const currentSettings = await getOrInitSettings(env2);
        const updates = [];
        let chainSubmitted = false;
        if (formData.has("clientDnsSettings")) {
          initialTab = "dns";
          const value = JSON.stringify(dnsFromForm(formData));
          if (value !== JSON.stringify(currentSettings.clientDns)) updates.push({ key: KV_KEYS.clientDnsSettings, value });
        }
        const check = /* @__PURE__ */ __name((key, fieldName, newVal, oldVal) => {
          if (formData.has(fieldName) && newVal !== oldVal) {
            updates.push({ key, value: newVal });
          }
        }, "check");
        const checkBool = /* @__PURE__ */ __name((key, newVal, oldVal) => {
          if (newVal !== oldVal) {
            updates.push({ key, value: newVal });
          }
        }, "checkBool");
        if (formData.has("vlessUuid")) {
          initialTab = "protocols";
          const newUuid = String(formData.get("vlessUuid") || "").trim();
          if (newUuid && newUuid !== currentSettings.vlessUuid) {
            updates.push({ key: KV_KEYS.vlessUuid, value: newUuid });
          }
        }
        if (formData.has("trojanPassword")) {
          initialTab = "protocols";
          const newTrojan = String(formData.get("trojanPassword") || "").trim();
          if (newTrojan && newTrojan !== currentSettings.trojanPassword) {
            updates.push({ key: KV_KEYS.trojanPassword, value: newTrojan });
          }
        }
        if (formData.has("proxyPath")) {
          initialTab = "protocols";
          const newPath = String(formData.get("proxyPath") || "").trim();
          if (newPath) {
            const formattedPath = newPath.startsWith("/") ? newPath : `/${newPath}`;
            if (formattedPath !== currentSettings.proxyPath) {
              updates.push({ key: KV_KEYS.proxyPath, value: formattedPath });
            }
          }
        }
        if (formData.has("subToken")) {
          initialTab = "protocols";
          const newSubToken = String(formData.get("subToken") || "").trim();
          if (newSubToken && newSubToken !== currentSettings.subToken) {
            updates.push({ key: KV_KEYS.subToken, value: newSubToken });
          }
        }
        if (formData.has("proxyIp")) {
          initialTab = "protocols";
          check(KV_KEYS.proxyIp, "proxyIp", String(formData.get("proxyIp") || "").trim(), currentSettings.proxyIp);
        }
        if (formData.has("relayIp")) {
          initialTab = "protocols";
          check(KV_KEYS.relayIp, "relayIp", String(formData.get("relayIp") || "").trim(), currentSettings.relayIp);
        }
        if (formData.has("nat64Prefixes")) {
          const nat64 = String(formData.get("nat64Prefixes") || "").trim();
          if (nat64.split(/[\s,]+/).filter(Boolean).some((p) => !/^\[?[0-9a-fA-F:]+::\]?(\/96)?$/.test(p))) throw new Error("NAT64 prefixes must look like 2602:fc59:b0:64:: (a /96 ending in ::).");
          check(KV_KEYS.nat64Prefixes, "nat64Prefixes", nat64, currentSettings.nat64Prefixes.join(", "));
        }
        if (formData.has("dnsDoH")) {
          if (!formData.has("vlessUuid")) initialTab = "dns";
          check(KV_KEYS.dnsDoH, "dnsDoH", validateDoh(String(formData.get("dnsDoH") || "").trim()), currentSettings.dnsDoH);
        }
        if (formData.has("allowLANConnection") || formData.has("staticIpList")) {
          initialTab = "protocols";
          const allowLANVal = formData.get("allowLANConnection");
          const allowLANConnection = allowLANVal === "on" || allowLANVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.allowLANConnection, allowLANConnection, String(currentSettings.allowLANConnection));
        }
        if (formData.has("domainFrontingEnabled") || formData.has("frontingSni")) {
          initialTab = "protocols";
          const frontingVal = formData.get("domainFrontingEnabled");
          const domainFrontingEnabled = frontingVal === "on" || frontingVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.domainFrontingEnabled, domainFrontingEnabled, String(currentSettings.domainFrontingEnabled));
          check(KV_KEYS.frontingSni, "frontingSni", String(formData.get("frontingSni") || "cdnjs.cloudflare.com").trim(), currentSettings.frontingSni);
          check(KV_KEYS.frontingHost, "frontingHost", String(formData.get("frontingHost") || "").trim(), currentSettings.frontingHost);
          check(KV_KEYS.frontingCleanIps, "frontingCleanIps", String(formData.get("frontingCleanIps") || "").trim(), currentSettings.frontingCleanIps);
        }
        if (formData.has("staticIpList")) {
          initialTab = "protocols";
          check(KV_KEYS.staticIpList, "staticIpList", String(formData.get("staticIpList") || "").trim(), currentSettings.staticIpList);
        }
        if (formData.has("ssEnabled") || formData.has("ssPassword") || formData.has("ssMethod")) {
          initialTab = "protocols";
          const ssVal = formData.get("ssEnabled");
          const ssEnabled = ssVal === "on" || ssVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.ssEnabled, ssEnabled, String(currentSettings.ssEnabled));
          check(KV_KEYS.ssPassword, "ssPassword", String(formData.get("ssPassword") || "").trim(), currentSettings.ssPassword);
          check(KV_KEYS.ssMethod, "ssMethod", String(formData.get("ssMethod") || "chacha20-ietf-poly1305").trim(), currentSettings.ssMethod);
        }
        if (formData.has("xhttpEnabled") || formData.has("xhttpPath") || formData.has("httpUpgradeEnabled")) {
          initialTab = "protocols";
          const xhttpVal = formData.get("xhttpEnabled");
          const xhttpEnabled = xhttpVal === "on" || xhttpVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.xhttpEnabled, xhttpEnabled, String(currentSettings.xhttpEnabled));
          check(KV_KEYS.xhttpPath, "xhttpPath", String(formData.get("xhttpPath") || "/bk-xhttp").trim(), currentSettings.xhttpPath);
          check(KV_KEYS.xhttpMode, "xhttpMode", String(formData.get("xhttpMode") || "stream-one").trim(), currentSettings.xhttpMode);
          const httpUpVal = formData.get("httpUpgradeEnabled");
          const httpUpgradeEnabled = httpUpVal === "on" || httpUpVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.httpUpgradeEnabled, httpUpgradeEnabled, String(currentSettings.httpUpgradeEnabled));
        }
        if (formData.has("anytlsFingerprint") || formData.has("anytlsAlpn")) {
          initialTab = "protocols";
          check(KV_KEYS.anytlsFingerprint, "anytlsFingerprint", String(formData.get("anytlsFingerprint") || "chrome").trim(), currentSettings.anytlsFingerprint);
          check(KV_KEYS.anytlsAlpn, "anytlsAlpn", String(formData.get("anytlsAlpn") || "h2,http/1.1").trim(), currentSettings.anytlsAlpn);
        }
        if (formData.has("dnsCustom")) {
          if (!formData.has("vlessUuid")) initialTab = "dns";
          check(KV_KEYS.dnsCustom, "dnsCustom", validateDoh(String(formData.get("dnsCustom") || "").trim()), currentSettings.dnsCustom);
        }
        if (formData.has("openvpnEnabled") || formData.has("openvpnPort") || formData.has("openvpnCipher")) {
          initialTab = "protocols";
          const ovpnVal = formData.get("openvpnEnabled");
          const openvpnEnabled = ovpnVal === "on" || ovpnVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.openvpnEnabled, openvpnEnabled, String(currentSettings.openvpnEnabled));
          check(KV_KEYS.openvpnPort, "openvpnPort", String(formData.get("openvpnPort") || "443").trim(), currentSettings.openvpnPort);
          check(KV_KEYS.openvpnProto, "openvpnProto", String(formData.get("openvpnProto") || "tcp").trim(), currentSettings.openvpnProto);
          check(KV_KEYS.openvpnCipher, "openvpnCipher", String(formData.get("openvpnCipher") || "AES-256-GCM").trim(), currentSettings.openvpnCipher);
        }
        if (formData.has("fragmentEnabled") || formData.has("fragmentPackets")) {
          initialTab = "routing";
          const fragmentVal = formData.get("fragmentEnabled");
          const fragmentEnabled = fragmentVal === "on" || fragmentVal === "true" ? "true" : "false";
          checkBool(KV_KEYS.fragmentEnabled, fragmentEnabled, String(currentSettings.fragmentEnabled));
          check(KV_KEYS.fragmentPackets, "fragmentPackets", String(formData.get("fragmentPackets") || "tlshello").trim(), currentSettings.fragmentPackets);
          check(KV_KEYS.fragmentLength, "fragmentLength", String(formData.get("fragmentLength") || "100-200").trim(), currentSettings.fragmentLength);
          check(KV_KEYS.fragmentInterval, "fragmentInterval", String(formData.get("fragmentInterval") || "10-20").trim(), currentSettings.fragmentInterval);
        }
        if (formData.has("routingPreset")) {
          initialTab = "routing";
          check(KV_KEYS.routingPreset, "routingPreset", String(formData.get("routingPreset") || "off").trim(), currentSettings.routingPreset);
        }
        if (formData.has("warpPrivateKey") || formData.has("warpProEnabled") || formData.has("warpPeerPublicKey")) {
          initialTab = "warp";
          const warpProVal = formData.get("warpProEnabled");
          const warpProEnabled = warpProVal === "on" || warpProVal === "true" ? "true" : "false";
          check(KV_KEYS.warpPrivateKey, "warpPrivateKey", String(formData.get("warpPrivateKey") || "").trim(), currentSettings.warpPrivateKey);
          check(KV_KEYS.warpPeerPublicKey, "warpPeerPublicKey", String(formData.get("warpPeerPublicKey") || "").trim(), currentSettings.warpPeerPublicKey);
          check(KV_KEYS.warpIPv6, "warpIPv6", String(formData.get("warpIPv6") || "").trim(), currentSettings.warpIPv6);
          check(KV_KEYS.warpReserved, "warpReserved", String(formData.get("warpReserved") || "").trim(), currentSettings.warpReserved);
          checkBool(KV_KEYS.warpProEnabled, warpProEnabled, String(currentSettings.warpProEnabled));
          check(KV_KEYS.warpAmneziaVersion, "warpAmneziaVersion", String(formData.get("warpAmneziaVersion") || "2").trim(), currentSettings.warpAmneziaVersion);
          check(KV_KEYS.warpNoiseCount, "warpNoiseCount", String(formData.get("warpNoiseCount") || "5").trim(), currentSettings.warpNoiseCount);
          check(KV_KEYS.warpNoiseMin, "warpNoiseMin", String(formData.get("warpNoiseMin") || "10").trim(), currentSettings.warpNoiseMin);
          check(KV_KEYS.warpNoiseMax, "warpNoiseMax", String(formData.get("warpNoiseMax") || "50").trim(), currentSettings.warpNoiseMax);
          check(KV_KEYS.warpNoiseDelay, "warpNoiseDelay", String(formData.get("warpNoiseDelay") || "20").trim(), currentSettings.warpNoiseDelay);
          check(KV_KEYS.warpAmneziaS1, "warpAmneziaS1", String(formData.get("warpAmneziaS1") || "15").trim(), currentSettings.warpAmneziaS1);
          check(KV_KEYS.warpAmneziaS2, "warpAmneziaS2", String(formData.get("warpAmneziaS2") || "25").trim(), currentSettings.warpAmneziaS2);
          check(KV_KEYS.warpAmneziaH1, "warpAmneziaH1", String(formData.get("warpAmneziaH1") || "1").trim(), currentSettings.warpAmneziaH1);
          check(KV_KEYS.warpAmneziaH2, "warpAmneziaH2", String(formData.get("warpAmneziaH2") || "2").trim(), currentSettings.warpAmneziaH2);
          check(KV_KEYS.warpAmneziaH3, "warpAmneziaH3", String(formData.get("warpAmneziaH3") || "3").trim(), currentSettings.warpAmneziaH3);
          check(KV_KEYS.warpAmneziaH4, "warpAmneziaH4", String(formData.get("warpAmneziaH4") || "4").trim(), currentSettings.warpAmneziaH4);
        }
        if (formData.has("chainEnabled") || formData.has("chainType") || formData.has("chainAddress")) {
          initialTab = "routing";
          const chainVal = formData.get("chainEnabled");
          const chainEnabled = chainVal === "on" || chainVal === "true" ? "true" : "false";
          const chainType = String(formData.get("chainType") || "socks").trim();
          const chainAddress = String(formData.get("chainAddress") || "").trim();
          const chainPort = String(formData.get("chainPort") || "1080").trim();
          const chainAuth = String(formData.get("chainAuth") || "").trim();
          if (chainEnabled === "true") {
            if (!["socks", "http"].includes(chainType)) throw new Error("Chain type must be SOCKS5 or HTTP.");
            if (!/^(\[[0-9a-fA-F:.]+\]|[^\s/:\[\]]+)$/.test(chainAddress)) throw new Error("Chain address must be a hostname or IP with no scheme, path or port.");
            if (!/^\d+$/.test(chainPort) || +chainPort < 1 || +chainPort > 65535) throw new Error("Chain port must be 1-65535.");
            if (chainType === "socks" && chainAuth && !/^[^:]+:.+$/.test(chainAuth)) throw new Error("SOCKS5 auth must be user:password.");
          }
          chainSubmitted = true;
          checkBool(KV_KEYS.chainEnabled, chainEnabled, String(currentSettings.chainEnabled));
          check(KV_KEYS.chainType, "chainType", chainType, currentSettings.chainType);
          check(KV_KEYS.chainAddress, "chainAddress", chainAddress, currentSettings.chainAddress);
          check(KV_KEYS.chainPort, "chainPort", chainPort, String(currentSettings.chainPort));
          check(KV_KEYS.chainAuth, "chainAuth", chainAuth, currentSettings.chainAuth);
          check(KV_KEYS.chainSecurity, "chainSecurity", String(formData.get("chainSecurity") || "none").trim(), currentSettings.chainSecurity);
        }
        if (updates.length === 0) {
          flashMessage = { type: "success", text: "No settings were modified \u2014 0 KV writes consumed. \u2728" };
        } else {
          for (const item of updates) {
            try {
              await kv.put(item.key, item.value);
            } catch (putErr) {
              const isQuota = putErr?.message?.toLowerCase().includes("quota") || putErr?.message?.toLowerCase().includes("limit exceeded");
              throw new Error(isQuota ? "KV write quota exceeded \u2014 try again after daily reset" : putErr?.message || "Failed to write to KV");
            }
          }
          invalidateSettingsCache();
          settings = await getOrInitSettings(env2);
          flashMessage = { type: "success", text: `Saved ${updates.length} updated setting(s) to KV! \u2728` };
        }
        const liveSettings = await getOrInitSettings(env2);
        if (chainSubmitted && liveSettings.chainEnabled) {
          const result = await testChain(liveSettings);
          flashMessage = result.ok ? { type: "success", text: `${flashMessage.text} Chain test passed: ${result.message}. Open connections keep their old route; new ones use the chain within about a minute.` } : { type: "error", text: `${flashMessage.text} Chain test FAILED: ${result.message}. Proxy traffic will fail until the upstream works or the chain is disabled.` };
        }
      } catch (err) {
        flashMessage = { type: "error", text: err.message || "Failed to save protocol settings." };
      }
    }
  }
  const html2 = renderDashboardPage({
    host: url.host,
    isDefaultPassword: false,
    flashMessage,
    settings,
    initialTab
  });
  return new Response(html2, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
async function authorizeSubscription(request, env2, expectedToken) {
  const url = new URL(request.url);
  const queryToken = url.searchParams.get("token");
  if (queryToken && constantTimeEquals(queryToken, expectedToken)) {
    return true;
  }
  const cookies = parseCookies(request);
  const sessionToken = cookies[APP_CONFIG.cookieName];
  if (sessionToken) {
    const session = await verifySessionToken(sessionToken, env2);
    if (session)
      return true;
  }
  return false;
}
var BYPASS_PRESETS = {
  "bypass-iran": ["ir"],
  "bypass-russia": ["ru"],
  "bypass-iran-russia": ["ir", "ru"],
  "bypass-cn": ["cn"]
};
var BYPASS_COUNTRIES = {
  ir: { geosite: "category-ir", suffixes: ["ir"] },
  ru: { geosite: "category-ru", suffixes: ["ru", "su", "xn--p1ai"] },
  cn: { geosite: "cn", suffixes: ["cn"] }
};
var GEO_MIRROR = "https://testingcf.jsdelivr.net/gh";
function bypassCountries(preset) {
  return (BYPASS_PRESETS[preset] || []).map((code) => ({ code, ...BYPASS_COUNTRIES[code] }));
}
function buildClashChainProxy(settings) {
  if (!settings.chainEnabled || !settings.chainAddress)
    return "";
  const type = settings.chainType;
  const isTls = settings.chainSecurity === "tls";
  if (type === "socks" || type === "http") {
    let authYaml = "";
    if (settings.chainAuth && settings.chainAuth.includes(":")) {
      const [user, pass] = settings.chainAuth.split(":");
      authYaml = `
    username: "${user}"
    password: "${pass}"`;
    }
    return `
  - name: "Chain-Upstream"
    type: ${type}
    server: "${settings.chainAddress}"
    port: ${settings.chainPort}${isTls ? "\n    tls: true" : ""}${authYaml}`;
  }
  if (type === "trojan") {
    return `
  - name: "Chain-Upstream"
    type: trojan
    server: "${settings.chainAddress}"
    port: ${settings.chainPort}
    password: "${settings.chainAuth || "password"}"
    tls: ${isTls}
    sni: "${settings.chainSni || settings.chainAddress}"
    network: ${settings.chainTransport}
    ${settings.chainTransport === "ws" ? `ws-opts:
      path: "${settings.chainPath || "/"}"
      headers:
        Host: "${settings.chainHost || settings.chainAddress}"` : ""}`;
  }
  if (type === "vless") {
    return `
  - name: "Chain-Upstream"
    type: vless
    server: "${settings.chainAddress}"
    port: ${settings.chainPort}
    uuid: "${settings.chainAuth || "00000000-0000-0000-0000-000000000000"}"
    cipher: auto
    tls: ${isTls}
    servername: "${settings.chainSni || settings.chainAddress}"
    network: ${settings.chainTransport}
    ${settings.chainTransport === "ws" ? `ws-opts:
      path: "${settings.chainPath || "/"}"
      headers:
        Host: "${settings.chainHost || settings.chainAddress}"` : ""}`;
  }
  return `
  - name: "Chain-Upstream"
    type: ss
    server: "${settings.chainAddress}"
    port: ${settings.chainPort}
    cipher: "chacha20-ietf-poly1305"
    password: "${settings.chainAuth || "secret"}"`;
}
function buildSingboxChainOutbound(settings) {
  if (!settings.chainEnabled || !settings.chainAddress)
    return null;
  const type = settings.chainType;
  const isTls = settings.chainSecurity === "tls";
  if (type === "socks" || type === "http") {
    const outbound = {
      type,
      tag: "chain-upstream",
      server: settings.chainAddress,
      server_port: settings.chainPort
    };
    if (settings.chainAuth && settings.chainAuth.includes(":")) {
      const [username, password] = settings.chainAuth.split(":");
      outbound.username = username;
      outbound.password = password;
    }
    return outbound;
  }
  if (type === "trojan") {
    return {
      type: "trojan",
      tag: "chain-upstream",
      server: settings.chainAddress,
      server_port: settings.chainPort,
      password: settings.chainAuth || "password",
      tls: {
        enabled: isTls,
        server_name: settings.chainSni || settings.chainAddress
      },
      transport: {
        type: settings.chainTransport,
        path: settings.chainPath || "/",
        headers: { Host: settings.chainHost || settings.chainAddress }
      }
    };
  }
  if (type === "vless") {
    return {
      type: "vless",
      tag: "chain-upstream",
      server: settings.chainAddress,
      server_port: settings.chainPort,
      uuid: settings.chainAuth || "00000000-0000-0000-0000-000000000000",
      tls: {
        enabled: isTls,
        server_name: settings.chainSni || settings.chainAddress
      },
      transport: {
        type: settings.chainTransport,
        path: settings.chainPath || "/",
        headers: { Host: settings.chainHost || settings.chainAddress }
      }
    };
  }
  return {
    type: "shadowsocks",
    tag: "chain-upstream",
    server: settings.chainAddress,
    server_port: settings.chainPort,
    method: "chacha20-ietf-poly1305",
    password: settings.chainAuth || "secret"
  };
}
function generateOpenVpnProfile(profile3) {
  if (typeof profile3 !== "string" || !/^remote\s+\S+\s+\d+/m.test(profile3) || !profile3.includes("-----BEGIN CERTIFICATE-----") || !profile3.includes("<key>")) return null;
  return profile3;
}
async function handleXhttpProxy(request, env2, ctx) {
  const settings = await getOrInitSettings(env2);
  const reader = request.body ? request.body.getReader() : null;
  if (!reader) {
    return new Response("Missing XHTTP Request Body", { status: 400 });
  }
  const { value: firstChunk, done } = await reader.read();
  if (done || !firstChunk || firstChunk.length === 0) {
    return new Response("Empty XHTTP Stream", { status: 400 });
  }
  let targetHost = "";
  let targetPort = 0;
  let initialPayload = new Uint8Array(0);
  let responseHeader = null;
  if (isTrojanPacket(firstChunk)) {
    const trojan = parseTrojanHeaderMulti(firstChunk, await getAllowedTrojanPasswords(env2, settings));
    if (!trojan || !trojan.isValidUser || trojan.command !== 1) {
      return new Response("Trojan Auth Failed", { status: 403 });
    }
    targetHost = trojan.targetAddress;
    targetPort = trojan.targetPort;
    initialPayload = trojan.payload;
  } else {
    const vless = parseVlessHeader(firstChunk, await getAllowedVlessUuids(env2, settings));
    if (!vless || !vless.isValidUser || vless.command !== 1) {
      return new Response("VLESS Auth Failed", { status: 403 });
    }
    targetHost = vless.targetAddress;
    targetPort = vless.targetPort;
    initialPayload = vless.payload;
    responseHeader = createVlessResponseHeader(vless.version);
  }
  try {
    const socket = await establishOutboundSocket(targetHost, targetPort, settings);
    const writer = socket.writable.getWriter();
    if (initialPayload.length > 0) {
      await writer.write(initialPayload);
    }
    const forwardBodyPromise = (async () => {
      try {
        while (true) {
          const { value, done: isDone } = await reader.read();
          if (isDone) break;
          if (value && value.length > 0) {
            await writer.write(value);
          }
        }
        await writer.close();
      } catch (_) {
        socket.close();
      } finally {
        writer.releaseLock();
        reader.releaseLock();
      }
    })();
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(forwardBodyPromise);
    }
    const responseStream = new TransformStream({
      start(controller) {
        if (responseHeader) controller.enqueue(responseHeader);
      },
      transform(chunk, controller) {
        controller.enqueue(chunk);
      }
    });
    const relay = socket.readable.pipeTo(responseStream.writable).catch(() => socket.close());
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(relay);
    return new Response(responseStream.readable, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Connection": "keep-alive"
      }
    });
  } catch (err) {
    return new Response("XHTTP Upstream Connection Failed: " + err.message, { status: 502 });
  }
}
async function handleSubscription(pathname, request, env2) {
  const url = new URL(request.url);
  const incomingHost = request.headers.get("x-forwarded-host") || request.headers.get("host") || url.host;
  const workerHost = new URL(`https://${incomingHost}`).hostname;
  const settings = await getOrInitSettings(env2);
  let isAuthorized = await authorizeSubscription(request, env2, settings.subToken);
  let subUser = null;
  const userTokenParam = url.searchParams.get("token");
  if (userTokenParam && !constantTimeEquals(userTokenParam, settings.subToken)) {
    subUser = await findHexUserByToken(env2, userTokenParam);
    if (subUser) isAuthorized = true;
  }
  const vlessAuthUuid = subUser && subUser.uuid ? subUser.uuid : settings.vlessUuid;
  const trojanAuthPass = subUser && subUser.uuid ? hexUserTrojanPass(subUser.uuid) : settings.trojanPassword;
  const profileTitleHeader = subUser ? { "Profile-Title": "base64:" + hexB64Utf8(hexFlagEmoji(subUser.cc) + " " + hexSafeLabel(subUser.name)) } : {};
  if (!isAuthorized) {
    return new Response(
      JSON.stringify(
        {
          error: "Unauthorized",
          message: "A valid subscription token (?token=...) or active panel session is required."
        },
        null,
        2
      ),
      {
        status: 401,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      }
    );
  }
  const cleanIp = settings.proxyIp && settings.proxyIp.trim() ? parseHostPort(settings.proxyIp, 0) : null;
  const serverAddress = cleanIp ? cleanIp.hostname : workerHost;
  const requestedProtocol = pathname.replace(/^\/sub\//, "").toLowerCase();
  const protocol = requestedProtocol === "all" ? "singbox" : requestedProtocol;
  const defaultPorts = request.cf || /\.(pages|workers)\.dev$/.test(workerHost) ? "443,2053,2083,2087,2096,8443" : "443";
  const cfPorts = [...new Set(String(env2.PROXY_PORTS ?? defaultPorts).split(",").map(Number).filter((port) => Number.isInteger(port) && port > 0 && port < 65536))];
  if (!cfPorts.length) return Response.json({ error: "Invalid PROXY_PORTS configuration" }, { status: 503 });
  const proxyPath = settings.proxyPath.startsWith("/") ? settings.proxyPath : `/${settings.proxyPath}`;
  const encodedPath = encodeURIComponent(proxyPath);
  const xhttpPath = (settings.xhttpPath || "/bk-xhttp").startsWith("/") ? settings.xhttpPath : `/${settings.xhttpPath}`;
  const encodedXhttpPath = encodeURIComponent(xhttpPath);
  const fragmentQuery = settings.fragmentEnabled ? `&fragment=${encodeURIComponent(`${settings.fragmentPackets},${settings.fragmentLength},${settings.fragmentInterval}`)}` : "";
  const fp = "chrome";
  const alpn = "http%2F1.1";
  const staticIps = (settings.staticIpList || "").split(/[,\n\s]+/).map((s) => s.trim()).filter((s) => s.length > 0);
  const isFronting = settings.domainFrontingEnabled && Boolean(settings.frontingSni);
  const frontSni = settings.frontingSni || "cdnjs.cloudflare.com";
  const frontHost = settings.frontingHost || workerHost;
  const nodePorts = cleanIp?.port ? [cleanIp.port] : cfPorts;
  const nodes = nodePorts.map((port) => ({ port, address: serverAddress, host: workerHost, sni: workerHost, suffix: String(port) }));
  if (isFronting) nodes.push(...nodePorts.slice(0, 2).map((port) => ({ port, address: serverAddress, host: frontHost, sni: frontSni, suffix: `Fronting-${port}` })));
  nodes.push(...[...new Set(staticIps)].map((entry, index) => {
    const { hostname: address, port } = parseHostPort(entry, 443);
    return { port, address, host: workerHost, sni: workerHost, suffix: `StaticIP-${index + 1}` };
  }));
  const userPrefix = subUser ? hexFlagEmoji(subUser.cc) + " " + hexSafeLabel(subUser.name) : "";
  const cfgName = (_kind, _suffix) => subUser ? userPrefix : "HEX";
  const warpTag = subUser ? `${userPrefix} | Warp` : "HEX-Warp";
  const uriAddress = (address) => address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
  const links = (type) => nodes.map((node) => {
    const auth = type === "vless" ? vlessAuthUuid : encodeURIComponent(trojanAuthPass);
    return `${type}://${auth}@${uriAddress(node.address)}:${node.port}?${type === "vless" ? "encryption=none&" : ""}security=tls&type=ws&path=${encodedPath}&host=${encodeURIComponent(node.host)}&sni=${encodeURIComponent(node.sni)}&fp=${fp}&alpn=${alpn}${type === "vless" ? fragmentQuery : ""}#${encodeURIComponent(`${cfgName(type === "vless" ? "VLESS" : "Trojan", node.suffix)}`)}`;
  });
  const ssNodes = settings.ssEnabled && SS_METHODS.includes(settings.ssMethod) ? nodes.filter((node) => node.host === node.sni) : [];
  const ssPath = `${proxyPath}/ss`;
  const ssLinks = ssNodes.map((node) => `ss://${btoa(`${settings.ssMethod}:${settings.ssPassword}`)}@${uriAddress(node.address)}:${node.port}/?plugin=${encodeURIComponent(`v2ray-plugin;tls;mux=0;host=${node.host};path=${ssPath}`)}#${encodeURIComponent(`${cfgName("SS", node.suffix)}`)}`);
  if (protocol === "ss" && ssLinks.length) return new Response(ssLinks.join("\n"), { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
  if (protocol === "openvpn") {
    const ovpnContent = generateOpenVpnProfile(env2.OPENVPN_CLIENT_PROFILE);
    if (!ovpnContent) return Response.json({ error: "OpenVPN is not provisioned", message: "Deploy native/openvpn on a Linux Docker host with TUN and NET_ADMIN, then configure OPENVPN_CLIENT_PROFILE_FILE. This panel does not emulate OpenVPN over WebSocket." }, { status: 503 });
    return new Response(ovpnContent, {
      status: 200,
      headers: {
        "Content-Type": "application/x-openvpn-profile; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Disposition": `attachment; filename="hex-${workerHost}.ovpn"`
      }
    });
  }
  if (["native", "shadowtls", "shadowsocks", "hysteria2", "tuic", "anytls", "ss"].includes(protocol)) {
    let native;
    try {
      native = JSON.parse(env2.NATIVE_CLIENT_CONFIG || "null");
    } catch {
    }
    if (!native || !Array.isArray(native.outbounds)) return Response.json({ error: "Native protocols are not provisioned", message: "Generate and deploy the native Docker stack, then configure NATIVE_CLIENT_CONFIG_FILE." }, { status: 503 });
    const selected = protocol === "ss" ? "shadowsocks" : protocol;
    if (selected !== "native" && !native.outbounds.some((o) => o.tag === selected)) return Response.json({ error: "Protocol is not configured" }, { status: 503 });
    if (protocol === "ss") {
      const outbound = native.outbounds.find((o) => o.tag === "shadowsocks");
      return new Response(`ss://${btoa(outbound.method + ":" + outbound.password)}@${outbound.server}:${outbound.server_port}#HEX-Shadowsocks`, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (selected !== "native") native.route = { ...native.route, final: selected };
    return Response.json(native, { headers: { "Cache-Control": "no-store" } });
  }
  if (["vless", "trojan", "xray"].includes(protocol) && !(protocol === "xray" && url.searchParams.get("format") === "json")) {
    const content = protocol === "xray" ? btoa([...links("vless"), ...links("trojan"), ...ssLinks].join("\n")) : links(protocol).join("\n");
    return new Response(content, { headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Profile-Update-Interval": "24", ...profileTitleHeader,
      "Subscription-Userinfo": "upload=0; download=0; total=107374182400; expire=0"
    } });
  }
  function parseReserved(reserved) {
    if (!reserved)
      return void 0;
    const nums = reserved.replace(/[\[\]]/g, "").split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
    return nums.length > 0 ? nums : void 0;
  }
  __name(parseReserved, "parseReserved");
  __name2(parseReserved, "parseReserved");
  function validateAwgParams(settings2) {
    if (!settings2.warpProEnabled)
      return null;
    const version2 = parseInt(settings2.warpAmneziaVersion || "2", 10);
    const jc = parseInt(settings2.warpNoiseCount || "5", 10);
    const jmin = parseInt(settings2.warpNoiseMin || "10", 10);
    const jmax = parseInt(settings2.warpNoiseMax || "50", 10);
    const s1 = parseInt(settings2.warpAmneziaS1 || "15", 10);
    const s2 = parseInt(settings2.warpAmneziaS2 || "25", 10);
    const h1 = parseInt(settings2.warpAmneziaH1 || "1", 10);
    const h2 = parseInt(settings2.warpAmneziaH2 || "2", 10);
    const h3 = parseInt(settings2.warpAmneziaH3 || "3", 10);
    const h4 = parseInt(settings2.warpAmneziaH4 || "4", 10);
    if ([version2, jc, jmin, jmax, s1, s2, h1, h2, h3, h4].some((v) => isNaN(v) || v < 0)) {
      return null;
    }
    if (jmin > jmax)
      return null;
    return { version: version2, jc, jmin, jmax, s1, s2, h1, h2, h3, h4 };
  }
  __name(validateAwgParams, "validateAwgParams");
  __name2(validateAwgParams, "validateAwgParams");
  if (protocol === "warp" || protocol === "amnezia") {
    return new Response("Not found", { status: 404 });
  }
  if (false) {
    if (!settings.warpPrivateKey) {
      return new Response(
        JSON.stringify(
          {
            error: "Warp Not Configured",
            message: "Warp (WireGuard) credentials are not yet configured in Panel Settings.",
            instructions: "Click '\u26A1 Generate Warp Account' in HEX Panel or provide your WireGuard Private Key in Settings."
          },
          null,
          2
        ),
        {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }
      );
    }
    const ipv6Address = settings.warpIPv6 ? `, ${settings.warpIPv6}` : "";
    const warpConf = `
[Interface]
PrivateKey = ${settings.warpPrivateKey}
Address = 172.16.0.2/32${ipv6Address}
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = ${settings.warpPeerPublicKey || "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.1:2408
PersistentKeepalive = 25
`.trim();
    return new Response(warpConf, {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": `attachment; filename="hex-warp.conf"`
      }
    });
  }
  if (false) {
    if (!settings.warpPrivateKey) {
      return new Response(
        JSON.stringify(
          {
            error: "Warp Not Configured",
            message: "AmneziaWG credentials are not yet configured in Panel Settings.",
            instructions: "Click '\u26A1 Generate Warp Account' in HEX Panel to automatically create WireGuard & Amnezia credentials."
          },
          null,
          2
        ),
        {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }
      );
    }
    const reservedLine = settings.warpReserved ? `Reserved = ${settings.warpReserved}
` : "";
    const ipv6Address = settings.warpIPv6 ? `, ${settings.warpIPv6}` : "";
    const amneziaConf = `
[Interface]
PrivateKey = ${settings.warpPrivateKey}
Address = 172.16.0.2/32${ipv6Address}
DNS = 1.1.1.1, 2606:4700:4700::1111
Jc = ${settings.warpNoiseCount || "5"}
Jmin = ${settings.warpNoiseMin || "10"}
Jmax = ${settings.warpNoiseMax || "50"}
S1 = ${settings.warpAmneziaS1 || "15"}
S2 = ${settings.warpAmneziaS2 || "25"}
H1 = ${settings.warpAmneziaH1 || "1"}
H2 = ${settings.warpAmneziaH2 || "2"}
H3 = ${settings.warpAmneziaH3 || "3"}
H4 = ${settings.warpAmneziaH4 || "4"}

[Peer]
PublicKey = ${settings.warpPeerPublicKey || "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.1:2408
PersistentKeepalive = 25
${reservedLine}`.trim();
    return new Response(amneziaConf, {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": `attachment; filename="hex-amnezia.conf"`
      }
    });
  }
  if (protocol === "clash") {
    const hasWarp = false;
    const hasChain = Boolean(settings.chainEnabled && settings.chainAddress);
    const awg = validateAwgParams(settings);
    const chainProxyEntry = "";
    const dialerProxyProp = "";
    const reservedArr = parseReserved(settings.warpReserved);
    const reservedYaml = reservedArr ? `
    reserved: [${reservedArr.join(", ")}]` : "";
    let awgYaml = "";
    if (awg) {
      awgYaml = `
    amnezia-wg-option:
      version: ${awg.version}
      jc: ${awg.jc}
      jmin: ${awg.jmin}
      jmax: ${awg.jmax}
      s1: ${awg.s1}
      s2: ${awg.s2}
      h1: ${awg.h1}
      h2: ${awg.h2}
      h3: ${awg.h3}
      h4: ${awg.h4}`;
    }
    const warpProxyEntry = hasWarp ? `
  - name: "${warpTag}"
    type: wireguard
    server: 162.159.192.1
    port: 2408
    ip: 172.16.0.2
    public-key: "${settings.warpPeerPublicKey}"
    private-key: "${settings.warpPrivateKey}"
    udp: true
    remote-dns-resolve: true${reservedYaml}${awgYaml}` : "";
    const warpProxyName = hasWarp ? `\n      - "${warpTag}"` : "";
    const chainProxyName = "";
    let clashRules = "";
    const clashCountries = bypassCountries(settings.routingPreset);
    if (clashCountries.length) {
      clashRules = clashCountries.map(({ code, geosite, suffixes }) => suffixes.map((x) => `
  - DOMAIN-SUFFIX,${x},DIRECT`).join("") + `
  - GEOSITE,${geosite},DIRECT
  - GEOIP,${code.toUpperCase()},DIRECT`).join("") + `
  - GEOIP,lan,DIRECT,no-resolve
  - MATCH,PROXY`;
    } else if (settings.routingPreset === "block-ads") {
      clashRules = `
  - GEOSITE,category-ads-all,REJECT
  - MATCH,PROXY`;
    } else {
      clashRules = `
  - MATCH,PROXY`;
    }
    const vlessClashProxies = nodes.map(({ port, address, host, sni, suffix }) => `
  - name: "${cfgName("VLESS", suffix)}"
    type: vless
    server: "${address}"
    port: ${port}
    uuid: "${vlessAuthUuid}"
    cipher: auto
    tls: true
    servername: "${sni}"
    network: ws
    ws-opts:
      path: "${proxyPath}"
      headers:
        Host: "${host}"${dialerProxyProp}`).join("");
    const trojanClashProxies = nodes.map(({ port, address, host, sni, suffix }) => `
  - name: "${cfgName("Trojan", suffix)}"
    type: trojan
    server: "${address}"
    port: ${port}
    password: "${trojanAuthPass}"
    tls: true
    sni: "${sni}"
    network: ws
    ws-opts:
      path: "${proxyPath}"
      headers:
        Host: "${host}"${dialerProxyProp}`).join("");
    const ssClashProxies = ssNodes.map((node) => `
  - name: "${cfgName("SS", node.suffix)}"
    type: ss
    server: "${node.address}"
    port: ${node.port}
    cipher: "${settings.ssMethod}"
    password: "${settings.ssPassword}"
    udp: false
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      mux: false
      tls: true
      host: "${node.host}"
      path: "${ssPath}"${dialerProxyProp}`).join("");
    const clashNodeNames = [
      ...nodes.map(({ suffix }) => `"${cfgName("VLESS", suffix)}"`),
      ...nodes.map(({ suffix }) => `"${cfgName("Trojan", suffix)}"`),
      ...ssNodes.map((node) => `"${cfgName("SS", node.suffix)}"`)
    ];
    const clashNodeListStr = clashNodeNames.map((n) => `
      - ${n}`).join("");
    const allowLanStr = settings.allowLANConnection ? "true" : "false";
    const bindAddressStr = settings.allowLANConnection ? "*" : "127.0.0.1";
    const proxiesYaml = `
port: 7890
socks-port: 7891
allow-lan: ${allowLanStr}
bind-address: "${bindAddressStr}"
mode: rule
log-level: info
ipv6: ${settings.clientDns.ipv6}
geo-auto-update: true
geo-update-interval: 72
geox-url:
  geoip: "${GEO_MIRROR}/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "${GEO_MIRROR}/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "${GEO_MIRROR}/MetaCubeX/meta-rules-dat@release/country.mmdb"
  asn: "${GEO_MIRROR}/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"
${clashDns(settings.clientDns, workerHost)}

proxies:${vlessClashProxies}${trojanClashProxies}${ssClashProxies}${warpProxyEntry}${chainProxyEntry}

proxy-groups:
  - name: PROXY
    type: select
    proxies:${clashNodeListStr}${warpProxyName}${chainProxyName}
      - "AUTO-FALLBACK"
      - DIRECT

  - name: AUTO-FALLBACK
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:${clashNodeListStr}${warpProxyName}

rules:${clashDnsRules(settings.clientDns)}${clashRules}
`.trim();
    return new Response(proxiesYaml, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml; charset=utf-8",
        "Profile-Update-Interval": "24", ...profileTitleHeader
      }
    });
  }
  if (protocol === "singbox") {
    const hasWarp = false;
    const hasChain = Boolean(settings.chainEnabled && settings.chainAddress);
    const detourVal = void 0;
    const vlessSingboxOutbounds = nodes.map(({ port, address, host, sni, suffix }) => ({
      type: "vless",
      tag: `${cfgName("VLESS", suffix)}`,
      server: address,
      server_port: port,
      uuid: vlessAuthUuid,
      tls: {
        enabled: true,
        server_name: sni,
        alpn: ["http/1.1"],
        utls: { enabled: true, fingerprint: "chrome" }
      },
      transport: {
        type: "ws",
        path: proxyPath,
        headers: {
          Host: host
        }
      },
      ...detourVal ? { detour: detourVal } : {}
    }));
    const trojanSingboxOutbounds = nodes.map(({ port, address, host, sni, suffix }) => ({
      type: "trojan",
      tag: `${cfgName("Trojan", suffix)}`,
      server: address,
      server_port: port,
      password: trojanAuthPass,
      tls: {
        enabled: true,
        server_name: sni,
        alpn: ["http/1.1"],
        utls: { enabled: true, fingerprint: "chrome" }
      },
      transport: {
        type: "ws",
        path: proxyPath,
        headers: {
          Host: host
        }
      },
      ...detourVal ? { detour: detourVal } : {}
    }));
    const ssSingboxOutbounds = ssNodes.map((node) => ({
      type: "shadowsocks",
      tag: `${cfgName("SS", node.suffix)}`,
      server: node.address,
      server_port: node.port,
      method: settings.ssMethod,
      password: settings.ssPassword,
      network: "tcp",
      plugin: "v2ray-plugin",
      plugin_opts: `tls;mux=0;host=${node.host};path=${ssPath}`,
      ...detourVal ? { detour: detourVal } : {}
    }));
    const endpoints = [];
    const outboundsList = [
      {
        type: "selector",
        tag: "select",
        outbounds: [
          ...nodes.map(({ suffix }) => `${cfgName("VLESS", suffix)}`),
          ...nodes.map(({ suffix }) => `${cfgName("Trojan", suffix)}`),
          ...ssSingboxOutbounds.map((outbound) => outbound.tag),
          ...hasWarp ? [warpTag] : [],
          "direct"
        ]
      },
      ...vlessSingboxOutbounds,
      ...trojanSingboxOutbounds,
      ...ssSingboxOutbounds
    ];
    if (hasWarp) {
      const reservedArr = parseReserved(settings.warpReserved);
      endpoints.push({
        type: "wireguard",
        tag: warpTag,
        system: false,
        address: ["172.16.0.2/32", ...settings.warpIPv6 ? [settings.warpIPv6] : []],
        private_key: settings.warpPrivateKey,
        peers: [{
          address: "162.159.192.1",
          port: 2408,
          public_key: settings.warpPeerPublicKey,
          allowed_ips: ["0.0.0.0/0", "::/0"],
          ...reservedArr ? { reserved: reservedArr } : {}
        }]
      });
    }
    outboundsList.push({ type: "direct", tag: "direct" });
    const routeRules = [{ action: "sniff" }, { protocol: "dns", action: "hijack-dns" }];
    const ruleSets = [];
    const ruleSet = (tag2, repo) => ({ type: "remote", tag: tag2, format: "binary", url: `${GEO_MIRROR}/SagerNet/${repo}@rule-set/${tag2}.srs`, download_detour: "select" });
    const countries = bypassCountries(settings.routingPreset);
    if (countries.length) {
      routeRules.push({ ip_is_private: true, outbound: "direct" });
      for (const { code, geosite, suffixes } of countries) {
        ruleSets.push(ruleSet(`geoip-${code}`, "sing-geoip"), ruleSet(`geosite-${geosite}`, "sing-geosite"));
        routeRules.push({ domain_suffix: suffixes, outbound: "direct" }, { rule_set: [`geosite-${geosite}`, `geoip-${code}`], outbound: "direct" });
      }
    } else if (settings.routingPreset === "block-ads") {
      ruleSets.push(ruleSet("geosite-category-ads-all", "sing-geosite"));
      routeRules.push({ rule_set: ["geosite-category-ads-all"], action: "reject" });
    }
    const listenAddress = settings.allowLANConnection ? "0.0.0.0" : "127.0.0.1";
    const singboxConfig = {
      log: {
        level: "info",
        timestamp: true
      },
      dns: singboxDns(settings.clientDns, workerHost),
      inbounds: [
        {
          type: "mixed",
          tag: "mixed-in",
          listen: listenAddress,
          listen_port: 2080
        }
      ],
      outbounds: outboundsList,
      endpoints,
      route: {
        auto_detect_interface: true,
        default_domain_resolver: "bootstrap-dns",
        rule_set: ruleSets,
        final: "select",
        rules: routeRules
      }
    };
    try {
      singboxDnsExtras(singboxConfig, settings.clientDns);
      mergeNativeSubscription(singboxConfig, env2.NATIVE_CLIENT_CONFIG);
    } catch (error3) {
      return Response.json({ error: "Native subscription configuration is invalid", message: error3.message }, { status: 503 });
    }
    return new Response(JSON.stringify(singboxConfig, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Profile-Update-Interval": "24", ...profileTitleHeader
      }
    });
  }
  if (protocol === "xray-json" || protocol === "xray" && url.searchParams.get("format") === "json") {
    const listenAddress = settings.allowLANConnection ? "0.0.0.0" : "127.0.0.1";
    const vlessOutbounds = nodes.map(({ port, address, host, sni, suffix }) => ({
      tag: `${cfgName("VLESS", suffix)}`,
      protocol: "vless",
      settings: {
        vnext: [
          {
            address,
            port,
            users: [
              {
                id: vlessAuthUuid,
                encryption: "none",
                level: 0
              }
            ]
          }
        ]
      },
      streamSettings: {
        network: "ws",
        security: "tls",
        tlsSettings: {
          serverName: sni,
          allowInsecure: false,
          fingerprint: "chrome",
          alpn: ["http/1.1"]
        },
        wsSettings: {
          path: proxyPath,
          headers: {
            Host: host
          }
        }
      }
    }));
    const trojanOutbounds = nodes.map(({ port, address, host, sni, suffix }) => ({
      tag: `${cfgName("Trojan", suffix)}`,
      protocol: "trojan",
      settings: {
        servers: [
          {
            address,
            port,
            password: trojanAuthPass,
            level: 0
          }
        ]
      },
      streamSettings: {
        network: "ws",
        security: "tls",
        tlsSettings: {
          serverName: sni,
          allowInsecure: false,
          fingerprint: "chrome",
          alpn: ["http/1.1"]
        },
        wsSettings: {
          path: proxyPath,
          headers: {
            Host: host
          }
        }
      }
    }));
    const xrayRules = [];
    const xrayCountries = bypassCountries(settings.routingPreset);
    if (xrayCountries.length) {
      xrayRules.push(
        { type: "field", outboundTag: "direct", ip: ["geoip:private", ...xrayCountries.map(({ code }) => `geoip:${code}`)] },
        { type: "field", outboundTag: "direct", domain: xrayCountries.flatMap(({ geosite, suffixes }) => [`geosite:${geosite}`, ...suffixes.map((x) => `domain:${x}`)]) }
      );
    } else if (settings.routingPreset === "block-ads") {
      xrayRules.push({
        type: "field",
        outboundTag: "block",
        domain: ["geosite:category-ads-all"]
      });
    }
    const xrayClientConfig = {
      log: {
        loglevel: "warning"
      },
      inbounds: [
        {
          tag: "socks-in",
          port: 10808,
          listen: listenAddress,
          protocol: "socks",
          settings: {
            auth: "noauth",
            udp: true
          }
        },
        {
          tag: "http-in",
          port: 10809,
          listen: listenAddress,
          protocol: "http",
          settings: {}
        }
      ],
      outbounds: [
        ...vlessOutbounds,
        ...trojanOutbounds,
        ...ssNodes.map((node) => ({
          tag: `${cfgName("SS", node.suffix)}`,
          protocol: "shadowsocks",
          settings: { servers: [{ address: node.address, port: node.port, method: settings.ssMethod, password: settings.ssPassword }] },
          streamSettings: { network: "ws", security: "tls", tlsSettings: { serverName: node.sni, fingerprint: "chrome" }, wsSettings: { path: ssPath, headers: { Host: node.host } } }
        })),
        {
          protocol: "freedom",
          tag: "direct",
          settings: {}
        },
        {
          protocol: "blackhole",
          tag: "block",
          settings: {
            response: {
              type: "http"
            }
          }
        }
      ],
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: xrayRules
      }
    };
    const requestedNode = url.searchParams.get("node");
    if (requestedNode) {
      const index = xrayClientConfig.outbounds.findIndex((o) => o.tag === requestedNode && ["vless", "trojan", "shadowsocks"].includes(o.protocol));
      if (index < 0) return Response.json({ error: "Unknown Xray node", message: "Use a proxy outbound tag from this Xray JSON profile." }, { status: 400 });
      xrayClientConfig.outbounds.unshift(...xrayClientConfig.outbounds.splice(index, 1));
    }
    applyXrayDns(xrayClientConfig, settings.clientDns, workerHost);
    return new Response(JSON.stringify(xrayClientConfig, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "X-HEX-Xray-Compatibility": "TUN is managed by your client app; h3 DNS endpoints use HTTPS over TCP",
        "Profile-Update-Interval": "24", ...profileTitleHeader
      }
    });
  }
  return new Response("Unknown subscription format", { status: 404 });
}
async function getConnect() {
  if (connectImpl) return connectImpl;
  try {
    ({ connect: connectImpl } = await import("cloudflare:sockets"));
  } catch {
    try {
      ({ connect: connectImpl } = await Promise.resolve().then(() => (init_sockets(), sockets_exports)));
    } catch {
    }
  }
  if (!connectImpl) {
    throw new Error("Raw TCP sockets are not available in this runtime.");
  }
  return connectImpl;
}
function bytesToUuid(bytes, offset = 0) {
  const hex = [];
  for (let i = 0; i < 16; i++) {
    hex.push((bytes[offset + i] < 16 ? "0" : "") + bytes[offset + i].toString(16));
  }
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join("")
  ].join("-").toLowerCase();
}
function parseVlessHeader(buffer, expectedUuid) {
  const allowedUuids = (Array.isArray(expectedUuid) ? expectedUuid : [expectedUuid]).map((x) => String(x || "").toLowerCase());
  if (buffer.length < 23) {
    return null;
  }
  const version2 = buffer[0];
  const clientUuid = bytesToUuid(buffer, 1);
  const isValidUser = allowedUuids.includes(clientUuid.toLowerCase());
  if (!isValidUser) {
    return null;
  }
  const addonLength = buffer[17];
  let cursor = 18 + addonLength;
  if (cursor + 4 > buffer.length) {
    return null;
  }
  const command = buffer[cursor];
  const targetPort = buffer[cursor + 1] << 8 | buffer[cursor + 2];
  const addressType = buffer[cursor + 3];
  cursor += 4;
  let targetAddress = "";
  if (addressType === 1) {
    if (cursor + 4 > buffer.length)
      return null;
    targetAddress = `${buffer[cursor]}.${buffer[cursor + 1]}.${buffer[cursor + 2]}.${buffer[cursor + 3]}`;
    cursor += 4;
  } else if (addressType === 2) {
    if (cursor + 1 > buffer.length)
      return null;
    const domainLength = buffer[cursor];
    cursor += 1;
    if (cursor + domainLength > buffer.length)
      return null;
    const domainBytes = buffer.subarray(cursor, cursor + domainLength);
    targetAddress = new TextDecoder().decode(domainBytes);
    cursor += domainLength;
  } else if (addressType === 3) {
    if (cursor + 16 > buffer.length)
      return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push((buffer[cursor + i] << 8 | buffer[cursor + i + 1]).toString(16));
    }
    targetAddress = `[${parts.join(":")}]`;
    cursor += 16;
  } else {
    return null;
  }
  const payload = buffer.subarray(cursor);
  return {
    version: version2,
    isValidUser,
    command,
    targetAddress,
    targetPort,
    payload
  };
}
function createVlessResponseHeader(version2 = 0) {
  return new Uint8Array([version2, 0]);
}
function sha224Hex(message2) {
  const K = [
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ];
  let H0 = 3238371032;
  let H1 = 914150663;
  let H2 = 812702999;
  let H3 = 4144912697;
  let H4 = 4290775857;
  let H5 = 1750603025;
  let H6 = 1694076839;
  let H7 = 3204075428;
  const data = new TextEncoder().encode(message2);
  const bitLen = data.length * 8;
  const padLen = (data.length + 8 >> 6) + 1 << 6;
  const padded = new Uint8Array(padLen);
  padded.set(data);
  padded[data.length] = 128;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 4, bitLen, false);
  const W = new Int32Array(64);
  for (let i = 0; i < padLen; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getInt32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (W[t - 15] >>> 7 | W[t - 15] << 25) ^ (W[t - 15] >>> 18 | W[t - 15] << 14) ^ W[t - 15] >>> 3;
      const s1 = (W[t - 2] >>> 17 | W[t - 2] << 15) ^ (W[t - 2] >>> 19 | W[t - 2] << 13) ^ W[t - 2] >>> 10;
      W[t] = W[t - 16] + s0 + W[t - 7] + s1 | 0;
    }
    let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;
    for (let t = 0; t < 64; t++) {
      const S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
      const ch = e & f ^ ~e & g;
      const temp1 = h + S1 + ch + K[t] + W[t] | 0;
      const S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
      const maj = a & b ^ a & c ^ b & c;
      const temp2 = S0 + maj | 0;
      h = g;
      g = f;
      f = e;
      e = d + temp1 | 0;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2 | 0;
    }
    H0 = H0 + a | 0;
    H1 = H1 + b | 0;
    H2 = H2 + c | 0;
    H3 = H3 + d | 0;
    H4 = H4 + e | 0;
    H5 = H5 + f | 0;
    H6 = H6 + g | 0;
    H7 = H7 + h | 0;
  }
  const words = [H0, H1, H2, H3, H4, H5, H6];
  return words.map((w) => (w >>> 0).toString(16).padStart(8, "0")).join("");
}
function isTrojanPacket(buffer) {
  if (buffer.length < 58)
    return false;
  if (buffer[56] === 13 && buffer[57] === 10) {
    for (let i = 0; i < 56; i++) {
      const b = buffer[i];
      const isHex = b >= 48 && b <= 57 || b >= 97 && b <= 102 || b >= 65 && b <= 70;
      if (!isHex)
        return false;
    }
    return true;
  }
  return false;
}
function parseTrojanHeader(buffer, expectedPassword) {
  if (buffer.length < 60)
    return null;
  let cursor = 0;
  let isValidUser = false;
  const expectedSha224 = sha224Hex(expectedPassword).toLowerCase();
  if (buffer.length >= 58 && buffer[56] === 13 && buffer[57] === 10) {
    const clientHex = new TextDecoder().decode(buffer.subarray(0, 56)).toLowerCase();
    isValidUser = clientHex === expectedSha224;
    cursor = 58;
  } else {
    const passBytes = new TextEncoder().encode(expectedPassword);
    if (buffer.length > passBytes.length + 2) {
      let match2 = true;
      for (let i = 0; i < passBytes.length; i++) {
        if (buffer[i] !== passBytes[i]) {
          match2 = false;
          break;
        }
      }
      if (match2 && buffer[passBytes.length] === 13 && buffer[passBytes.length + 1] === 10) {
        isValidUser = true;
        cursor = passBytes.length + 2;
      }
    }
  }
  if (!isValidUser) {
    return null;
  }
  if (cursor + 4 > buffer.length) {
    return null;
  }
  const command = buffer[cursor];
  const addressType = buffer[cursor + 1];
  cursor += 2;
  let targetAddress = "";
  if (addressType === 1) {
    if (cursor + 4 > buffer.length)
      return null;
    targetAddress = `${buffer[cursor]}.${buffer[cursor + 1]}.${buffer[cursor + 2]}.${buffer[cursor + 3]}`;
    cursor += 4;
  } else if (addressType === 3) {
    if (cursor + 1 > buffer.length)
      return null;
    const domainLen = buffer[cursor];
    cursor += 1;
    if (cursor + domainLen > buffer.length)
      return null;
    targetAddress = new TextDecoder().decode(buffer.subarray(cursor, cursor + domainLen));
    cursor += domainLen;
  } else if (addressType === 4) {
    if (cursor + 16 > buffer.length)
      return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push((buffer[cursor + i] << 8 | buffer[cursor + i + 1]).toString(16));
    }
    targetAddress = `[${parts.join(":")}]`;
    cursor += 16;
  } else {
    return null;
  }
  if (cursor + 4 > buffer.length) {
    return null;
  }
  const targetPort = buffer[cursor] << 8 | buffer[cursor + 1];
  cursor += 2;
  if (buffer[cursor] === 13 && buffer[cursor + 1] === 10) {
    cursor += 2;
  }
  const payload = buffer.subarray(cursor);
  return {
    isValidUser,
    command,
    targetAddress,
    targetPort,
    payload
  };
}
async function toUint8Array(data) {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    const buf = await data.arrayBuffer();
    return new Uint8Array(buf);
  }
  if (typeof data === "string") {
    return new TextEncoder().encode(data);
  }
  return null;
}
function decodeBase64Url(str) {
  try {
    let b64 = str.trim();
    if (!b64)
      return null;
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    const remainder = b64.length % 4;
    if (remainder === 2) {
      b64 += "==";
    } else if (remainder === 3) {
      b64 += "=";
    } else if (remainder === 1) {
      return null;
    }
    const binary = atob(b64);
    if (binary.length === 0)
      return null;
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}
function extractEarlyData(headerValue) {
  if (!headerValue)
    return null;
  const raw = headerValue.trim();
  if (!raw)
    return null;
  const candidates = raw.includes(",") ? raw.split(",").map((s) => s.trim()) : [raw];
  for (const candidate of candidates) {
    if (!candidate)
      continue;
    const decoded = decodeBase64Url(candidate);
    if (decoded && decoded.length > 0) {
      return decoded;
    }
  }
  return null;
}
async function handleWebSocketProxy(request, env2, ctx) {
  if (new URL(request.url).pathname.endsWith("/ss")) {
    const settings = await getOrInitSettings(env2);
    if (!settings.ssEnabled || !SS_METHODS.includes(settings.ssMethod)) return new Response("Shadowsocks disabled or unsupported cipher", { status: 503 });
  }
  const upgradeHeader = request.headers.get("Upgrade");
  if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
    return new Response("Expected WebSocket Upgrade", { status: 426 });
  }
  if (typeof WebSocketPair === "undefined") {
    return new Response(
      JSON.stringify(
        {
          error: "Unsupported Runtime",
          message: "This host cannot carry proxy traffic: it provides no WebSocket upgrade. The panel and subscription links work here, but run the tunnel on Cloudflare Workers/Pages or a Node host (Render, Fly, Railway, Koyeb, Docker)."
        },
        null,
        2
      ),
      { status: 501, headers: { "Content-Type": "application/json; charset=utf-8" } }
    );
  }
  const secProtocol = request.headers.get("sec-websocket-protocol");
  const earlyData = extractEarlyData(secProtocol);
  const webSocketPair = new WebSocketPair();
  const [clientWs, serverWs] = Object.values(webSocketPair);
  serverWs.accept();
  const ssRequest = new URL(request.url).pathname.endsWith("/ss");
  const ssSettings = ssRequest ? await getOrInitSettings(env2) : null;
  const sessionPromise = (ssRequest ? serveShadowsocks(serverWs, ssSettings, Object.assign((host, port, viaRelay) => establishOutboundSocket(host, port, ssSettings, viaRelay), { canRelay: canFallback(ssSettings) }), earlyData) : handleProxySession(serverWs, env2, earlyData)).catch((err) => {
    console.warn("Proxy session error:", err?.message || err);
    try {
      serverWs.close(1011, "Internal Error");
    } catch {
    }
  });
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(sessionPromise);
  }
  const responseHeaders = new Headers();
  if (secProtocol) {
    responseHeaders.set("Sec-WebSocket-Protocol", secProtocol);
  }
  return new Response(null, {
    status: 101,
    webSocket: clientWs,
    headers: responseHeaders
  });
}
function chainReader(socket) {
  const reader = socket.readable.getReader();
  let pending = new Uint8Array(0);
  async function read(size) {
    while (pending.length < size) {
      const { value, done } = await reader.read();
      if (done) throw new Error("Proxy closed during handshake");
      const next = new Uint8Array(pending.length + value.length);
      next.set(pending);
      next.set(value, pending.length);
      pending = next;
    }
    const result = pending.slice(0, size);
    pending = pending.slice(size);
    return result;
  }
  return {
    read,
    release() {
      reader.releaseLock();
      if (pending.length) {
        const prefix = pending;
        const original = socket.readable;
        let source;
        socket.readable = new ReadableStream({
          start(controller) {
            controller.enqueue(prefix);
            source = original.getReader();
          },
          async pull(controller) {
            try {
              const { value, done } = await source.read();
              if (done) {
                source.releaseLock();
                controller.close();
              } else controller.enqueue(value);
            } catch (err) {
              controller.error(err);
            }
          },
          cancel(reason) {
            return source.cancel(reason);
          }
        });
      }
    }
  };
}
async function dialHttpChain(remoteSocket, targetHost, targetPort, chainAuth) {
  const writer = remoteSocket.writable.getWriter();
  const input = chainReader(remoteSocket);
  try {
    const authority2 = `${targetHost.includes(":") ? `[${targetHost}]` : targetHost}:${targetPort}`;
    const auth = chainAuth ? `Proxy-Authorization: Basic ${btoa(String.fromCharCode(...new TextEncoder().encode(chainAuth)))}\r
` : "";
    await writer.write(new TextEncoder().encode(
      `CONNECT ${authority2} HTTP/1.1\r
Host: ${authority2}\r
${auth}\r
`
    ));
    let header = "";
    while (!header.endsWith("\r\n\r\n")) {
      if (header.length >= 16384) throw new Error("HTTP proxy response headers too large");
      header += String.fromCharCode((await input.read(1))[0]);
    }
    if (!/^HTTP\/1\.[01] 2\d\d(?: |\r)/.test(header)) {
      throw new Error(`HTTP proxy CONNECT failed: ${header.split("\r\n")[0]}`);
    }
  } finally {
    writer.releaseLock();
    input.release();
  }
}
function socks5Address(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return [1, ...host.split(".").map(Number)];
  if (host.includes(":")) {
    const split = (s) => s ? s.split(":") : [];
    const [head, tail] = host.includes("::") ? host.split("::").map(split) : [split(host), []];
    const groups = [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail];
    return [4, ...groups.flatMap((g) => {
      const n = parseInt(g, 16);
      return [n >> 8, n & 255];
    })];
  }
  const domain2 = new TextEncoder().encode(host);
  if (!domain2.length || domain2.length > 255) throw new Error("Invalid SOCKS5 target length");
  return [3, domain2.length, ...domain2];
}
async function dialSocks5Chain(remoteSocket, targetHost, targetPort, chainAuth) {
  const writer = remoteSocket.writable.getWriter();
  const input = chainReader(remoteSocket);
  try {
    await writer.write(new Uint8Array(chainAuth ? [5, 1, 2] : [5, 1, 0]));
    const greeting = await input.read(2);
    if (greeting[0] !== 5 || greeting[1] !== (chainAuth ? 2 : 0)) {
      throw new Error("SOCKS5 authentication method rejected");
    }
    if (chainAuth) {
      const split = chainAuth.indexOf(":");
      if (split < 0) throw new Error("SOCKS5 credentials must be user:password");
      const user = new TextEncoder().encode(chainAuth.slice(0, split));
      const pass = new TextEncoder().encode(chainAuth.slice(split + 1));
      if (!user.length || !pass.length || user.length > 255 || pass.length > 255) {
        throw new Error("Invalid SOCKS5 credential length");
      }
      await writer.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
      const auth = await input.read(2);
      if (auth[0] !== 1 || auth[1] !== 0) throw new Error("SOCKS5 credentials rejected");
    }
    await writer.write(new Uint8Array([
      5,
      1,
      0,
      ...socks5Address(targetHost),
      targetPort >> 8 & 255,
      targetPort & 255
    ]));
    const reply = await input.read(4);
    if (reply[0] !== 5 || reply[1] !== 0 || reply[2] !== 0) {
      throw new Error("SOCKS5 connection establishment rejected by upstream proxy");
    }
    const length = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : reply[3] === 3 ? (await input.read(1))[0] : -1;
    if (length < 0) throw new Error("Invalid SOCKS5 reply address");
    await input.read(length + 2);
  } finally {
    writer.releaseLock();
    input.release();
  }
}
async function establishOutboundSocket(targetHost, targetPort, settings, viaRelay = false) {
  const nativeConnect = await getConnect();
  const connect2 = (address, options) => {
    const hostname = String(address.hostname).replace(/^\[|\]$/g, "");
    const socket2 = nativeConnect({ ...address, hostname: hostname.includes(":") ? `[${hostname}]` : hostname }, options);
    return {
      readable: socket2.readable,
      writable: socket2.writable,
      opened: socket2.opened,
      closed: socket2.closed,
      close: () => socket2.close()
    };
  };
  const cleanHost = targetHost.replace(/^\[|\]$/g, "");
  if (settings.chainEnabled && (!settings.chainAddress || !(settings.chainPort > 0) || !["http", "socks"].includes(settings.chainType))) {
    throw new Error("Configure a valid HTTP or SOCKS5 upstream; unsupported chains cannot fall back to a direct connection");
  }
  if (settings.chainEnabled && settings.chainAddress && settings.chainPort > 0) {
    const socket2 = connect2(
      { hostname: settings.chainAddress.replace(/^\[|\]$/g, ""), port: settings.chainPort },
      settings.chainSecurity === "tls" ? { secureTransport: "on" } : void 0
    );
    try {
      await socket2.opened;
      await (settings.chainType === "http" ? dialHttpChain : dialSocks5Chain)(socket2, cleanHost, targetPort, settings.chainAuth);
    } catch (err) {
      socket2.close();
      throw err;
    }
    return socket2;
  }
  if (viaRelay && settings.relayIp) {
    const socket2 = connect2(parseHostPort(settings.relayIp, targetPort));
    await socket2.opened;
    return socket2;
  }
  if (viaRelay) {
    const addresses = await nat64Addresses(cleanHost, settings.nat64Prefixes);
    const sockets = addresses.map((hostname) => connect2({ hostname, port: targetPort }));
    let timer;
    try {
      const winner = await Promise.race([
        Promise.any(sockets.map((s) => s.opened.then(() => s))),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("no NAT64 gateway answered within 8s")), 8e3);
        })
      ]);
      for (const s of sockets) if (s !== winner) try {
        s.close();
      } catch {
      }
      return winner;
    } catch (err) {
      for (const s of sockets) try {
        s.close();
      } catch {
      }
      throw err instanceof AggregateError ? new Error("every NAT64 gateway refused the connection") : err;
    } finally {
      clearTimeout(timer);
    }
  }
  const socket = connect2({
    hostname: cleanHost,
    port: targetPort
  });
  await socket.opened;
  return socket;
}
async function testChain(settings, host = "example.com", port = 80) {
  const started = Date.now();
  let socket, timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("timed out after 8s")), 8e3);
  });
  try {
    return await Promise.race([timeout, (async () => {
      socket = await establishOutboundSocket(host, port, settings);
      const writer = socket.writable.getWriter();
      await writer.write(new TextEncoder().encode(`HEAD / HTTP/1.1\r
Host: ${host}\r
Connection: close\r
\r
`));
      writer.releaseLock();
      const reader = socket.readable.getReader();
      const { value } = await reader.read();
      reader.releaseLock();
      const status = new TextDecoder().decode(value || new Uint8Array()).split("\r\n")[0];
      if (!/^HTTP\/1\.[01] \d{3}/.test(status)) throw new Error(`unexpected reply from ${host} via upstream`);
      return { ok: true, message: `${host} answered "${status}" via ${settings.chainType.toUpperCase()} ${settings.chainAddress}:${settings.chainPort} in ${Date.now() - started} ms` };
    })()]);
  } catch (err) {
    return { ok: false, message: err?.message || String(err) };
  } finally {
    clearTimeout(timer);
    try {
      socket?.close();
    } catch {
    }
  }
}
var DEFAULT_NAT64_PREFIXES = "2a01:4f9:c010:3f02:64::, 2a01:4f8:c2c:123f:64::, 2a00:1098:2b::, 2602:fc59:b0:64::, 2602:fc59:11:64::, 2a02:898:146:64::";
function canFallback(settings) {
  return !!settings && !settings.chainEnabled && (!!settings.relayIp || settings.nat64Prefixes.length > 0);
}
async function nat64Addresses(host, prefixes) {
  let ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? host : null;
  if (!ipv4 && !host.includes(":")) {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: "application/dns-json" } });
    ipv4 = ((await res.json()).Answer || []).find((a2) => a2.type === 1)?.data || null;
  }
  if (!ipv4) throw new Error(`NAT64 needs an IPv4 target; ${host} has none`);
  const [a, b, c, d] = ipv4.split(".").map(Number);
  const hex = (x, y) => (x << 8 | y).toString(16);
  return prefixes.map((prefix) => `${prefix}${hex(a, b)}:${hex(c, d)}`);
}
function parseHostPort(value, defaultPort) {
  const m = String(value).trim().match(/^\[([^\]]+)\](?::(\d+))?$|^([^:]+)(?::(\d+))?$/);
  if (!m) return { hostname: String(value).trim().replace(/^\[|\]$/g, ""), port: defaultPort };
  return { hostname: m[1] || m[3], port: parseInt(m[2] || m[4], 10) || defaultPort };
}
async function handleProxySession(ws, env2, earlyData) {
  const settings = await getOrInitSettings(env2);
  let remoteSocket = null;
  let socketWriter = null;
  let hasHandshaked = false;
  let isClosed = false;
  const closeAll = /* @__PURE__ */ __name2((code = 1e3, reason = "Closed") => {
    if (isClosed)
      return;
    isClosed = true;
    if (socketWriter) {
      try {
        socketWriter.close().catch(() => {
        });
      } catch {
      }
      try {
        socketWriter.releaseLock();
      } catch {
      }
      socketWriter = null;
    }
    if (remoteSocket) {
      try {
        remoteSocket.close();
      } catch {
      }
      remoteSocket = null;
    }
    try {
      ws.close(code, reason);
    } catch {
    }
  }, "closeAll");
  async function processPacket(chunk) {
    if (isClosed)
      return;
    if (!hasHandshaked) {
      let targetHost = "";
      let targetPort = 0;
      let initialPayload = new Uint8Array(0);
      let isVless = false;
      let vlessVersion = 0;
      if (isTrojanPacket(chunk)) {
        const trojan = parseTrojanHeaderMulti(chunk, await getAllowedTrojanPasswords(env2, settings));
        if (!trojan || !trojan.isValidUser) {
          console.warn("Trojan authentication failed or malformed header");
          closeAll(1008, "Auth Failed");
          return;
        }
        if (trojan.command !== 1) {
          console.warn(`Unsupported Trojan command: ${trojan.command} (TCP only)`);
          closeAll(1003, "TCP only");
          return;
        }
        targetHost = trojan.targetAddress;
        targetPort = trojan.targetPort;
        initialPayload = trojan.payload;
      } else {
        const vless = parseVlessHeader(chunk, await getAllowedVlessUuids(env2, settings));
        if (!vless || !vless.isValidUser) {
          console.warn("VLESS authentication failed or invalid UUID");
          closeAll(1008, "Auth Failed");
          return;
        }
        if (vless.command !== 1) {
          console.warn(`Unsupported VLESS command: ${vless.command} (TCP only)`);
          closeAll(1003, "TCP only");
          return;
        }
        isVless = true;
        vlessVersion = vless.version;
        targetHost = vless.targetAddress;
        targetPort = vless.targetPort;
        initialPayload = vless.payload;
        const vlessResponse = createVlessResponseHeader(vlessVersion);
        try {
          ws.send(vlessResponse);
        } catch (sendErr) {
          console.warn("Failed to send VLESS response header:", sendErr?.message || sendErr);
          closeAll(1011, "WS Send Error");
          return;
        }
      }
      hasHandshaked = true;
      const canRelay = canFallback(settings);
      const dial = async (viaRelay) => {
        if (remoteSocket) {
          try {
            socketWriter?.releaseLock();
          } catch {
          }
          try {
            remoteSocket.close();
          } catch {
          }
        }
        try {
          remoteSocket = await establishOutboundSocket(targetHost, targetPort, settings, viaRelay);
        } catch (sockErr) {
          if (!viaRelay && canRelay) return dial(true);
          console.warn(`Failed to connect to ${targetHost}:${targetPort}${viaRelay ? " via relay" : ""}:`, sockErr?.message || sockErr);
          closeAll(1001, "Connection Refused");
          return;
        }
        if (isClosed) {
          try {
            remoteSocket.close();
          } catch {
          }
          return;
        }
        const writer = remoteSocket.writable.getWriter();
        socketWriter = writer;
        if (initialPayload.length > 0) {
          try {
            await writer.write(initialPayload);
          } catch (writeErr) {
            if (!viaRelay && canRelay) return dial(true);
            console.warn("Failed to write initial payload:", writeErr?.message || writeErr);
            closeAll(1001, "Socket Write Error");
            return;
          }
        }
        pipeRemoteToWebSocket(remoteSocket.readable, ws, closeAll, !viaRelay && canRelay ? () => dial(true) : null);
      };
      await dial(false);
    } else {
      if (socketWriter) {
        try {
          await socketWriter.write(chunk);
        } catch (writeErr) {
          console.warn("Failed to write chunk to remote socket:", writeErr?.message || writeErr);
          closeAll(1001, "Socket Write Error");
        }
      }
    }
  }
  __name(processPacket, "processPacket");
  __name2(processPacket, "processPacket");
  let messageQueue = Promise.resolve();
  if (earlyData && earlyData.length > 0) {
    messageQueue = messageQueue.then(() => processPacket(earlyData)).catch((err) => {
      console.warn("Early-data packet processing error:", err?.message || err);
      closeAll(1011, "Early Data Error");
    });
  }
  ws.addEventListener("message", (event) => {
    messageQueue = messageQueue.then(async () => {
      if (isClosed)
        return;
      const chunk = await toUint8Array(event.data);
      if (!chunk || chunk.length === 0)
        return;
      await processPacket(chunk);
    }).catch((err) => {
      console.warn("WebSocket packet processing error:", err?.message || err);
      closeAll(1011, "Stream Error");
    });
  });
  ws.addEventListener("close", () => closeAll(1e3, "Client Disconnected"));
  ws.addEventListener("error", (e) => {
    console.warn("WebSocket client error:", e);
    closeAll(1006, "Abnormal Closure");
  });
  return new Promise((resolve) => {
    const interval = setInterval(() => {
      if (isClosed) {
        clearInterval(interval);
        resolve();
      }
    }, 1e3);
    ws.addEventListener("close", () => {
      clearInterval(interval);
      resolve();
    });
  });
}
async function pipeRemoteToWebSocket(readable, ws, onClose, retryIfEmpty = null) {
  const reader = readable.getReader();
  let received = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done)
        break;
      if (value && value.length > 0) {
        received = true;
        try {
          ws.send(value);
        } catch {
          break;
        }
      }
    }
  } catch (err) {
    console.warn("Pipe remote read error:", err?.message || err);
  } finally {
    try {
      reader.releaseLock();
    } catch {
    }
  }
  if (!received && retryIfEmpty) return retryIfEmpty();
  onClose(1e3, "Remote stream finished");
}
async function handleDnsQuery(request, env2) {
  const settings = await getOrInitSettings(env2);
  const upstreamUrl = settings.dnsCustom && settings.dnsCustom.trim().length > 0 ? settings.dnsCustom.trim() : settings.dnsDoH || "https://cloudflare-dns.com/dns-query";
  const url = new URL(request.url);
  try {
    if (request.method === "GET") {
      const dnsParam = url.searchParams.get("dns");
      if (!dnsParam) {
        return new Response("Missing 'dns' query parameter in GET /dns-query", {
          status: 400,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }
      const upstreamResponse = await fetchDnsWithFallback(upstreamUrl, settings.clientDns.gatewayFallbacks, {
        method: "GET",
        headers: {
          Accept: "application/dns-message"
        }
      }, env2.DNS_FETCH || fetch, dnsParam);
      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      responseHeaders.set("Content-Type", "application/dns-message");
      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: responseHeaders
      });
    }
    if (request.method === "POST") {
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.includes("application/dns-message")) {
        return new Response("Expected Content-Type: application/dns-message", {
          status: 415,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }
      const body = await request.arrayBuffer();
      const upstreamResponse = await fetchDnsWithFallback(upstreamUrl, settings.clientDns.gatewayFallbacks, {
        method: "POST",
        headers: {
          "Content-Type": "application/dns-message",
          Accept: "application/dns-message"
        },
        body
      }, env2.DNS_FETCH || fetch);
      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      responseHeaders.set("Content-Type", "application/dns-message");
      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: responseHeaders
      });
    }
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Accept"
        }
      });
    }
    return new Response("Method Not Allowed", { status: 405 });
  } catch (err) {
    console.warn("DoH upstream error:", err.message);
    return new Response(`DoH Upstream Gateway Error: ${err.message}`, {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
}
async function handleDnsJson(request, env2) {
  const settings = await getOrInitSettings(env2);
  const upstreamUrl = settings.dnsCustom && settings.dnsCustom.trim().length > 0 ? settings.dnsCustom.trim() : settings.dnsDoH || "https://cloudflare-dns.com/dns-query";
  const url = new URL(request.url);
  const name = url.searchParams.get("name");
  const type = url.searchParams.get("type") || "A";
  if (!name) {
    return new Response(JSON.stringify({ error: "Missing 'name' query parameter" }, null, 2), {
      status: 400,
      headers: { "Content-Type": "application/json; charset=utf-8" }
    });
  }
  try {
    const data = await queryDnsJson(upstreamUrl, name, type, (endpoint, init) => fetchDnsWithFallback(endpoint, settings.clientDns.gatewayFallbacks, init, env2.DNS_FETCH || fetch));
    return new Response(JSON.stringify(data, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*"
      }
    });
  } catch (err) {
    console.warn("DoH JSON upstream error:", err.message);
    return new Response(JSON.stringify({ error: "Bad Gateway", details: err.message }, null, 2), {
      status: err instanceof RangeError ? 400 : 502,
      headers: { "Content-Type": "application/json; charset=utf-8" }
    });
  }
}
async function authorizeShareRequest(request, env2, expectedToken) {
  const url = new URL(request.url);
  const queryToken = url.searchParams.get("token");
  const sessionToken = getSessionCookie(request);
  if (sessionToken) {
    const session = await verifySessionToken(sessionToken, env2);
    if (session) {
      return { authorized: true, isAdminSession: true };
    }
  }
  if (queryToken && constantTimeEquals(queryToken, expectedToken)) {
    return { authorized: true, isAdminSession: false };
  }
  return { authorized: false, isAdminSession: false };
}
async function handleNodeExport(request, env2) {
  const url = new URL(request.url);
  const settings = await getOrInitSettings(env2);
  const { authorized, isAdminSession } = await authorizeShareRequest(request, env2, settings.nodeShareToken);
  if (!authorized) {
    return new Response(
      JSON.stringify(
        {
          error: "Unauthorized",
          message: "A valid nodeShareToken is required to access the node export feed."
        },
        null,
        2
      ),
      {
        status: 401,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      }
    );
  }
  const includeSecrets = isAdminSession && url.searchParams.get("includeSecrets") === "true";
  const exportPayload = {
    schema: "hex-node-export/v1",
    app: "HEX Panel",
    version: APP_CONFIG.version,
    exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
    nodeShareToken: settings.nodeShareToken,
    settings: {
      proxyPath: settings.proxyPath,
      proxyIp: settings.proxyIp,
      relayIp: settings.relayIp,
      dnsDoH: settings.dnsDoH,
      dnsCustom: settings.dnsCustom,
      clientDns: settings.clientDns,
      allowLANConnection: settings.allowLANConnection,
      fragmentEnabled: settings.fragmentEnabled,
      fragmentPackets: settings.fragmentPackets,
      fragmentLength: settings.fragmentLength,
      fragmentInterval: settings.fragmentInterval,
      routingPreset: settings.routingPreset,
      // Warp Pro & AmneziaWG
      warpProEnabled: settings.warpProEnabled,
      warpPeerPublicKey: settings.warpPeerPublicKey,
      warpAmneziaVersion: settings.warpAmneziaVersion,
      warpNoiseCount: settings.warpNoiseCount,
      warpNoiseMin: settings.warpNoiseMin,
      warpNoiseMax: settings.warpNoiseMax,
      warpNoiseDelay: settings.warpNoiseDelay,
      warpAmneziaS1: settings.warpAmneziaS1,
      warpAmneziaS2: settings.warpAmneziaS2,
      warpAmneziaH1: settings.warpAmneziaH1,
      warpAmneziaH2: settings.warpAmneziaH2,
      warpAmneziaH3: settings.warpAmneziaH3,
      warpAmneziaH4: settings.warpAmneziaH4,
      // Chain Proxy
      chainEnabled: settings.chainEnabled,
      chainType: settings.chainType,
      chainAddress: settings.chainAddress,
      chainPort: settings.chainPort,
      chainPath: settings.chainPath,
      chainSecurity: settings.chainSecurity,
      chainTransport: settings.chainTransport,
      chainSni: settings.chainSni,
      chainHost: settings.chainHost
    }
  };
  if (includeSecrets) {
    exportPayload.secrets = {
      vlessUuid: settings.vlessUuid,
      trojanPassword: settings.trojanPassword,
      subToken: settings.subToken,
      chainAuth: settings.chainAuth,
      warpPrivateKey: settings.warpPrivateKey,
      warpIPv6: settings.warpIPv6,
      warpReserved: settings.warpReserved
    };
  }
  return new Response(JSON.stringify(exportPayload, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store"
    }
  });
}
async function handleNodeImport(request, env2) {
  const sessionToken = getSessionCookie(request);
  if (!sessionToken) {
    return new Response(JSON.stringify({ error: "Unauthorized", message: "Admin session required." }), {
      status: 401,
      headers: { "Content-Type": "application/json; charset=utf-8" }
    });
  }
  const session = await verifySessionToken(sessionToken, env2);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized", message: "Session expired." }), {
      status: 401,
      headers: { "Content-Type": "application/json; charset=utf-8" }
    });
  }
  try {
    const body = await request.json().catch(() => ({}));
    const importData = body.settings || body;
    if (!importData || typeof importData !== "object") {
      return new Response(JSON.stringify({ error: "Bad Request", message: "Invalid configuration JSON." }), {
        status: 400,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    const kv = getKV(env2);
    if (!kv) {
      return new Response(JSON.stringify({ error: "KV Missing", message: "KV binding WD_KV or BK_KV is required." }), {
        status: 500,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    const currentSettings = await getOrInitSettings(env2);
    const importedKeys = [];
    const pendingWrites = [];
    const queueWrite = /* @__PURE__ */ __name2((key, newVal, currentVal, fieldName) => {
      if (newVal !== void 0 && String(newVal).trim() !== String(currentVal).trim()) {
        pendingWrites.push({ key, value: String(newVal).trim(), fieldName });
      }
    }, "queueWrite");
    if (typeof importData.proxyPath === "string") {
      queueWrite(KV_KEYS.proxyPath, importData.proxyPath, currentSettings.proxyPath, "proxyPath");
    }
    if (typeof importData.proxyIp === "string") {
      queueWrite(KV_KEYS.proxyIp, importData.proxyIp, currentSettings.proxyIp, "proxyIp");
    }
    if (typeof importData.relayIp === "string") {
      queueWrite(KV_KEYS.relayIp, importData.relayIp.trim(), currentSettings.relayIp, "relayIp");
    }
    if (typeof importData.dnsDoH === "string") {
      queueWrite(KV_KEYS.dnsDoH, validateDoh(importData.dnsDoH.trim()), currentSettings.dnsDoH, "dnsDoH");
    }
    if (importData.clientDns !== void 0) {
      queueWrite(KV_KEYS.clientDnsSettings, JSON.stringify(normalizeDns(importData.clientDns)), JSON.stringify(currentSettings.clientDns), "clientDns");
    }
    if (typeof importData.dnsCustom === "string") {
      queueWrite(KV_KEYS.dnsCustom, validateDoh(importData.dnsCustom.trim()), currentSettings.dnsCustom, "dnsCustom");
    }
    if (importData.allowLANConnection !== void 0) {
      queueWrite(KV_KEYS.allowLANConnection, String(importData.allowLANConnection), currentSettings.allowLANConnection, "allowLANConnection");
    }
    if (importData.fragmentEnabled !== void 0) {
      queueWrite(KV_KEYS.fragmentEnabled, String(importData.fragmentEnabled), currentSettings.fragmentEnabled, "fragmentEnabled");
    }
    if (typeof importData.fragmentPackets === "string") {
      queueWrite(KV_KEYS.fragmentPackets, importData.fragmentPackets, currentSettings.fragmentPackets, "fragmentPackets");
    }
    if (typeof importData.fragmentLength === "string") {
      queueWrite(KV_KEYS.fragmentLength, importData.fragmentLength, currentSettings.fragmentLength, "fragmentLength");
    }
    if (typeof importData.fragmentInterval === "string") {
      queueWrite(KV_KEYS.fragmentInterval, importData.fragmentInterval, currentSettings.fragmentInterval, "fragmentInterval");
    }
    if (typeof importData.routingPreset === "string") {
      queueWrite(KV_KEYS.routingPreset, importData.routingPreset, currentSettings.routingPreset, "routingPreset");
    }
    if (importData.warpProEnabled !== void 0) {
      queueWrite(KV_KEYS.warpProEnabled, String(importData.warpProEnabled), currentSettings.warpProEnabled, "warpProEnabled");
    }
    if (typeof importData.warpAmneziaVersion === "string") {
      queueWrite(KV_KEYS.warpAmneziaVersion, importData.warpAmneziaVersion, currentSettings.warpAmneziaVersion, "warpAmneziaVersion");
    }
    if (typeof importData.warpNoiseCount === "string") {
      queueWrite(KV_KEYS.warpNoiseCount, importData.warpNoiseCount, currentSettings.warpNoiseCount, "warpNoiseCount");
    }
    if (typeof importData.warpNoiseMin === "string") {
      queueWrite(KV_KEYS.warpNoiseMin, importData.warpNoiseMin, currentSettings.warpNoiseMin, "warpNoiseMin");
    }
    if (typeof importData.warpNoiseMax === "string") {
      queueWrite(KV_KEYS.warpNoiseMax, importData.warpNoiseMax, currentSettings.warpNoiseMax, "warpNoiseMax");
    }
    if (typeof importData.warpNoiseDelay === "string") {
      queueWrite(KV_KEYS.warpNoiseDelay, importData.warpNoiseDelay, currentSettings.warpNoiseDelay, "warpNoiseDelay");
    }
    if (typeof importData.warpAmneziaS1 === "string") {
      queueWrite(KV_KEYS.warpAmneziaS1, importData.warpAmneziaS1, currentSettings.warpAmneziaS1, "warpAmneziaS1");
    }
    if (typeof importData.warpAmneziaS2 === "string") {
      queueWrite(KV_KEYS.warpAmneziaS2, importData.warpAmneziaS2, currentSettings.warpAmneziaS2, "warpAmneziaS2");
    }
    if (typeof importData.warpAmneziaH1 === "string") {
      queueWrite(KV_KEYS.warpAmneziaH1, importData.warpAmneziaH1, currentSettings.warpAmneziaH1, "warpAmneziaH1");
    }
    if (typeof importData.warpAmneziaH2 === "string") {
      queueWrite(KV_KEYS.warpAmneziaH2, importData.warpAmneziaH2, currentSettings.warpAmneziaH2, "warpAmneziaH2");
    }
    if (typeof importData.warpAmneziaH3 === "string") {
      queueWrite(KV_KEYS.warpAmneziaH3, importData.warpAmneziaH3, currentSettings.warpAmneziaH3, "warpAmneziaH3");
    }
    if (typeof importData.warpAmneziaH4 === "string") {
      queueWrite(KV_KEYS.warpAmneziaH4, importData.warpAmneziaH4, currentSettings.warpAmneziaH4, "warpAmneziaH4");
    }
    if (importData.chainEnabled !== void 0) {
      queueWrite(KV_KEYS.chainEnabled, String(importData.chainEnabled), currentSettings.chainEnabled, "chainEnabled");
    }
    if (typeof importData.chainType === "string") {
      queueWrite(KV_KEYS.chainType, importData.chainType, currentSettings.chainType, "chainType");
    }
    if (typeof importData.chainAddress === "string") {
      queueWrite(KV_KEYS.chainAddress, importData.chainAddress, currentSettings.chainAddress, "chainAddress");
    }
    if (importData.chainPort !== void 0) {
      queueWrite(KV_KEYS.chainPort, String(importData.chainPort), currentSettings.chainPort, "chainPort");
    }
    if (typeof importData.chainPath === "string") {
      queueWrite(KV_KEYS.chainPath, importData.chainPath, currentSettings.chainPath, "chainPath");
    }
    if (typeof importData.chainSecurity === "string") {
      queueWrite(KV_KEYS.chainSecurity, importData.chainSecurity, currentSettings.chainSecurity, "chainSecurity");
    }
    if (typeof importData.chainTransport === "string") {
      queueWrite(KV_KEYS.chainTransport, importData.chainTransport, currentSettings.chainTransport, "chainTransport");
    }
    if (typeof importData.chainSni === "string") {
      queueWrite(KV_KEYS.chainSni, importData.chainSni, currentSettings.chainSni, "chainSni");
    }
    if (typeof importData.chainHost === "string") {
      queueWrite(KV_KEYS.chainHost, importData.chainHost, currentSettings.chainHost, "chainHost");
    }
    const secrets = body.secrets;
    if (secrets && typeof secrets === "object") {
      if (typeof secrets.vlessUuid === "string" && secrets.vlessUuid && secrets.vlessUuid !== currentSettings.vlessUuid) {
        pendingWrites.push({ key: KV_KEYS.vlessUuid, value: secrets.vlessUuid, fieldName: "vlessUuid" });
      }
      if (typeof secrets.trojanPassword === "string" && secrets.trojanPassword && secrets.trojanPassword !== currentSettings.trojanPassword) {
        pendingWrites.push({ key: KV_KEYS.trojanPassword, value: secrets.trojanPassword, fieldName: "trojanPassword" });
      }
      if (typeof secrets.chainAuth === "string" && secrets.chainAuth && secrets.chainAuth !== currentSettings.chainAuth) {
        pendingWrites.push({ key: KV_KEYS.chainAuth, value: secrets.chainAuth, fieldName: "chainAuth" });
      }
      if (typeof secrets.warpPrivateKey === "string" && secrets.warpPrivateKey && secrets.warpPrivateKey !== currentSettings.warpPrivateKey) {
        pendingWrites.push({ key: KV_KEYS.warpPrivateKey, value: secrets.warpPrivateKey, fieldName: "warpPrivateKey" });
      }
    }
    for (const item of pendingWrites) {
      try {
        await kv.put(item.key, item.value);
        importedKeys.push(item.fieldName);
      } catch (putErr) {
        const isQuota = putErr?.message?.toLowerCase().includes("quota") || putErr?.message?.toLowerCase().includes("limit exceeded");
        throw new Error(isQuota ? "KV write quota exceeded \u2014 try again after daily reset" : putErr?.message || "Failed to write imported key to KV");
      }
    }
    if (importedKeys.length > 0) {
      invalidateSettingsCache();
    }
    return new Response(
      JSON.stringify(
        {
          ok: true,
          message: importedKeys.length > 0 ? `Successfully imported ${importedKeys.length} changed setting(s) into HEX KV.` : "No changes detected in imported payload \u2014 0 KV writes consumed.",
          importedCount: importedKeys.length,
          importedKeys
        },
        null,
        2
      ),
      {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      }
    );
  } catch (err) {
    const isQuota = err?.message?.toLowerCase().includes("quota") || err?.message?.toLowerCase().includes("limit exceeded");
    return new Response(
      JSON.stringify({
        error: isQuota ? "KV Quota Exceeded" : "Import Error",
        message: isQuota ? "KV write quota exceeded \u2014 try again after daily reset" : err.message || "Failed to process import payload."
      }),
      {
        status: isQuota ? 429 : 500,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      }
    );
  }
}
var __defProp2;
var __defNormalProp;
var __name2;
var __publicField;
var _timeOrigin;
var _performanceNow;
var nodeTiming;
var PerformanceEntry;
var PerformanceMark;
var PerformanceMeasure;
var PerformanceResourceTiming;
var PerformanceObserverEntryList;
var Performance;
var PerformanceObserver;
var performance;
var noop_default;
var _console;
var _ignoreErrors;
var _stderr;
var _stdout;
var log;
var info;
var trace;
var debug;
var table;
var error;
var warn;
var createTask;
var clear;
var count;
var countReset;
var dir;
var dirxml;
var group;
var groupEnd;
var groupCollapsed;
var profile;
var profileEnd;
var time;
var timeEnd;
var timeLog;
var timeStamp;
var Console;
var _times;
var _stdoutErrorHandler;
var _stderrErrorHandler;
var workerdConsole;
var assert;
var clear2;
var context;
var count2;
var countReset2;
var createTask2;
var debug2;
var dir2;
var dirxml2;
var error2;
var group2;
var groupCollapsed2;
var groupEnd2;
var info2;
var log2;
var profile2;
var profileEnd2;
var table2;
var time2;
var timeEnd2;
var timeLog2;
var timeStamp2;
var trace2;
var warn2;
var console_default;
var hrtime;
var ReadStream;
var WriteStream;
var Process;
var globalProcess;
var getBuiltinModule;
var exit;
var platform;
var nextTick;
var unenvProcess;
var abort;
var addListener;
var allowedNodeEnvironmentFlags;
var hasUncaughtExceptionCaptureCallback;
var setUncaughtExceptionCaptureCallback;
var loadEnvFile;
var sourceMapsEnabled;
var arch;
var argv;
var argv0;
var chdir;
var config;
var connected;
var constrainedMemory;
var availableMemory;
var cpuUsage;
var cwd;
var debugPort;
var dlopen;
var disconnect;
var emit;
var emitWarning;
var env;
var eventNames;
var execArgv;
var execPath;
var finalization;
var features;
var getActiveResourcesInfo;
var getMaxListeners;
var hrtime3;
var kill;
var listeners;
var listenerCount;
var memoryUsage;
var on;
var off;
var once;
var pid;
var ppid;
var prependListener;
var prependOnceListener;
var rawListeners;
var release;
var removeAllListeners;
var removeListener;
var report;
var resourceUsage;
var setMaxListeners;
var setSourceMapsEnabled;
var stderr;
var stdin;
var stdout;
var title;
var throwDeprecation;
var traceDeprecation;
var umask;
var uptime;
var version;
var versions;
var domain;
var initgroups;
var moduleLoadList;
var reallyExit;
var openStdin;
var assert2;
var binding;
var send;
var exitCode;
var channel;
var getegid;
var geteuid;
var getgid;
var getgroups;
var getuid;
var setegid;
var seteuid;
var setgid;
var setgroups;
var setuid;
var permission;
var mainModule;
var _events;
var _eventsCount;
var _exiting;
var _maxListeners;
var _debugEnd;
var _debugProcess;
var _fatalException;
var _getActiveHandles;
var _getActiveRequests;
var _kill;
var _preload_modules;
var _rawDebug;
var _startProfilerIdleNotifier;
var _stopProfilerIdleNotifier;
var _tickCallback;
var _disconnect;
var _handleQueue;
var _pendingMessage;
var _channel;
var _send;
var _linkedBinding;
var _process;
var process_default;
var APP_CONFIG;
var KV_KEYS;
var cachedSettings;
var cachedSettingsTimestamp;
var CACHE_TTL_MS;
var webcrypto_default;
var isCryptoKey;
var encoder;
var decoder;
var MAX_INT32;
var encodeBase64;
var encode;
var decodeBase64;
var decode;
var JOSEError;
var JWTClaimValidationFailed;
var JWTExpired;
var JOSEAlgNotAllowed;
var JOSENotSupported;
var JWEDecryptionFailed;
var JWEInvalid;
var JWSInvalid;
var JWTInvalid;
var JWKInvalid;
var JWKSInvalid;
var JWKSNoMatchingKey;
var JWKSMultipleMatchingKeys;
var JWKSTimeout;
var JWSSignatureVerificationFailed;
var invalid_key_input_default;
var is_key_like_default;
var types;
var isDisjoint;
var is_disjoint_default;
var check_key_length_default;
var parse;
var jwk_to_key_default;
var exportKeyValue;
var privCache;
var pubCache;
var isKeyObject;
var importAndCache;
var normalizePublicKey;
var normalizePrivateKey;
var normalize_key_default;
var tag;
var jwkMatchesOp;
var symmetricTypeCheck;
var asymmetricTypeCheck;
var check_key_type_default;
var checkKeyTypeWithJwk;
var validate_crit_default;
var validateAlgorithms;
var validate_algorithms_default;
var verify;
var verify_default;
var epoch_default;
var minute;
var hour;
var day;
var week;
var year;
var REGEX;
var secs_default;
var normalizeTyp;
var checkAudiencePresence;
var jwt_claims_set_default;
var sign;
var sign_default;
var FlattenedSign;
var CompactSign;
var ProduceJWT;
var SignJWT;
var cachedJwtSecret;
var cachedPasswordConfigured;
var cachedAdminPassword;
var MASCOT_SVG;
var BASE_STYLES;
var P;
var A24;
var connectImpl;
var THEME_BG_DATA_URIS;
var src_default;
var init_worker = __esm({
  "../worker.js"() {
    init_functionsRoutes_0_6698010974737841();
    __defProp2 = Object.defineProperty;
    __defNormalProp = /* @__PURE__ */ __name((obj, key, value) => key in obj ? __defProp2(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value, "__defNormalProp");
    __name2 = /* @__PURE__ */ __name((target, value) => __defProp2(target, "name", { value, configurable: true }), "__name");
    __publicField = /* @__PURE__ */ __name((obj, key, value) => {
      __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
      return value;
    }, "__publicField");
    __name(createNotImplementedError, "createNotImplementedError");
    __name2(createNotImplementedError, "createNotImplementedError");
    __name(notImplemented, "notImplemented");
    __name2(notImplemented, "notImplemented");
    __name(notImplementedClass, "notImplementedClass");
    __name2(notImplementedClass, "notImplementedClass");
    _timeOrigin = globalThis.performance?.timeOrigin ?? Date.now();
    _performanceNow = globalThis.performance?.now ? globalThis.performance.now.bind(globalThis.performance) : () => Date.now() - _timeOrigin;
    nodeTiming = {
      name: "node",
      entryType: "node",
      startTime: 0,
      duration: 0,
      nodeStart: 0,
      v8Start: 0,
      bootstrapComplete: 0,
      environment: 0,
      loopStart: 0,
      loopExit: 0,
      idleTime: 0,
      uvMetricsInfo: {
        loopCount: 0,
        events: 0,
        eventsWaiting: 0
      },
      detail: void 0,
      toJSON() {
        return this;
      }
    };
    PerformanceEntry = class {
      static {
        __name(this, "PerformanceEntry");
      }
      __unenv__ = true;
      detail;
      entryType = "event";
      name;
      startTime;
      constructor(name, options) {
        this.name = name;
        this.startTime = options?.startTime || _performanceNow();
        this.detail = options?.detail;
      }
      get duration() {
        return _performanceNow() - this.startTime;
      }
      toJSON() {
        return {
          name: this.name,
          entryType: this.entryType,
          startTime: this.startTime,
          duration: this.duration,
          detail: this.detail
        };
      }
    };
    __name2(PerformanceEntry, "PerformanceEntry");
    PerformanceMark = /* @__PURE__ */ __name2(class PerformanceMark2 extends PerformanceEntry {
      static {
        __name(this, "PerformanceMark2");
      }
      entryType = "mark";
      constructor() {
        super(...arguments);
      }
      get duration() {
        return 0;
      }
    }, "PerformanceMark");
    PerformanceMeasure = class extends PerformanceEntry {
      static {
        __name(this, "PerformanceMeasure");
      }
      entryType = "measure";
    };
    __name2(PerformanceMeasure, "PerformanceMeasure");
    PerformanceResourceTiming = class extends PerformanceEntry {
      static {
        __name(this, "PerformanceResourceTiming");
      }
      entryType = "resource";
      serverTiming = [];
      connectEnd = 0;
      connectStart = 0;
      decodedBodySize = 0;
      domainLookupEnd = 0;
      domainLookupStart = 0;
      encodedBodySize = 0;
      fetchStart = 0;
      initiatorType = "";
      name = "";
      nextHopProtocol = "";
      redirectEnd = 0;
      redirectStart = 0;
      requestStart = 0;
      responseEnd = 0;
      responseStart = 0;
      secureConnectionStart = 0;
      startTime = 0;
      transferSize = 0;
      workerStart = 0;
      responseStatus = 0;
    };
    __name2(PerformanceResourceTiming, "PerformanceResourceTiming");
    PerformanceObserverEntryList = class {
      static {
        __name(this, "PerformanceObserverEntryList");
      }
      __unenv__ = true;
      getEntries() {
        return [];
      }
      getEntriesByName(_name, _type) {
        return [];
      }
      getEntriesByType(type) {
        return [];
      }
    };
    __name2(PerformanceObserverEntryList, "PerformanceObserverEntryList");
    Performance = class {
      static {
        __name(this, "Performance");
      }
      __unenv__ = true;
      timeOrigin = _timeOrigin;
      eventCounts = /* @__PURE__ */ new Map();
      _entries = [];
      _resourceTimingBufferSize = 0;
      navigation = void 0;
      timing = void 0;
      timerify(_fn, _options) {
        throw createNotImplementedError("Performance.timerify");
      }
      get nodeTiming() {
        return nodeTiming;
      }
      eventLoopUtilization() {
        return {};
      }
      markResourceTiming() {
        return new PerformanceResourceTiming("");
      }
      onresourcetimingbufferfull = null;
      now() {
        if (this.timeOrigin === _timeOrigin) {
          return _performanceNow();
        }
        return Date.now() - this.timeOrigin;
      }
      clearMarks(markName) {
        this._entries = markName ? this._entries.filter((e) => e.name !== markName) : this._entries.filter((e) => e.entryType !== "mark");
      }
      clearMeasures(measureName) {
        this._entries = measureName ? this._entries.filter((e) => e.name !== measureName) : this._entries.filter((e) => e.entryType !== "measure");
      }
      clearResourceTimings() {
        this._entries = this._entries.filter((e) => e.entryType !== "resource" || e.entryType !== "navigation");
      }
      getEntries() {
        return this._entries;
      }
      getEntriesByName(name, type) {
        return this._entries.filter((e) => e.name === name && (!type || e.entryType === type));
      }
      getEntriesByType(type) {
        return this._entries.filter((e) => e.entryType === type);
      }
      mark(name, options) {
        const entry = new PerformanceMark(name, options);
        this._entries.push(entry);
        return entry;
      }
      measure(measureName, startOrMeasureOptions, endMark) {
        let start;
        let end;
        if (typeof startOrMeasureOptions === "string") {
          start = this.getEntriesByName(startOrMeasureOptions, "mark")[0]?.startTime;
          end = this.getEntriesByName(endMark, "mark")[0]?.startTime;
        } else {
          start = Number.parseFloat(startOrMeasureOptions?.start) || this.now();
          end = Number.parseFloat(startOrMeasureOptions?.end) || this.now();
        }
        const entry = new PerformanceMeasure(measureName, {
          startTime: start,
          detail: {
            start,
            end
          }
        });
        this._entries.push(entry);
        return entry;
      }
      setResourceTimingBufferSize(maxSize) {
        this._resourceTimingBufferSize = maxSize;
      }
      addEventListener(type, listener, options) {
        throw createNotImplementedError("Performance.addEventListener");
      }
      removeEventListener(type, listener, options) {
        throw createNotImplementedError("Performance.removeEventListener");
      }
      dispatchEvent(event) {
        throw createNotImplementedError("Performance.dispatchEvent");
      }
      toJSON() {
        return this;
      }
    };
    __name2(Performance, "Performance");
    PerformanceObserver = class {
      static {
        __name(this, "PerformanceObserver");
      }
      __unenv__ = true;
      _callback = null;
      constructor(callback) {
        this._callback = callback;
      }
      takeRecords() {
        return [];
      }
      disconnect() {
        throw createNotImplementedError("PerformanceObserver.disconnect");
      }
      observe(options) {
        throw createNotImplementedError("PerformanceObserver.observe");
      }
      bind(fn) {
        return fn;
      }
      runInAsyncScope(fn, thisArg, ...args) {
        return fn.call(thisArg, ...args);
      }
      asyncId() {
        return 0;
      }
      triggerAsyncId() {
        return 0;
      }
      emitDestroy() {
        return this;
      }
    };
    __name2(PerformanceObserver, "PerformanceObserver");
    __publicField(PerformanceObserver, "supportedEntryTypes", []);
    performance = globalThis.performance && "addEventListener" in globalThis.performance ? globalThis.performance : new Performance();
    globalThis.performance = performance;
    globalThis.Performance = Performance;
    globalThis.PerformanceEntry = PerformanceEntry;
    globalThis.PerformanceMark = PerformanceMark;
    globalThis.PerformanceMeasure = PerformanceMeasure;
    globalThis.PerformanceObserver = PerformanceObserver;
    globalThis.PerformanceObserverEntryList = PerformanceObserverEntryList;
    globalThis.PerformanceResourceTiming = PerformanceResourceTiming;
    noop_default = Object.assign(() => {
    }, { __unenv__: true });
    _console = globalThis.console;
    _ignoreErrors = true;
    _stderr = new Writable2();
    _stdout = new Writable2();
    log = _console?.log ?? noop_default;
    info = _console?.info ?? log;
    trace = _console?.trace ?? info;
    debug = _console?.debug ?? log;
    table = _console?.table ?? log;
    error = _console?.error ?? log;
    warn = _console?.warn ?? error;
    createTask = _console?.createTask ?? /* @__PURE__ */ notImplemented("console.createTask");
    clear = _console?.clear ?? noop_default;
    count = _console?.count ?? noop_default;
    countReset = _console?.countReset ?? noop_default;
    dir = _console?.dir ?? noop_default;
    dirxml = _console?.dirxml ?? noop_default;
    group = _console?.group ?? noop_default;
    groupEnd = _console?.groupEnd ?? noop_default;
    groupCollapsed = _console?.groupCollapsed ?? noop_default;
    profile = _console?.profile ?? noop_default;
    profileEnd = _console?.profileEnd ?? noop_default;
    time = _console?.time ?? noop_default;
    timeEnd = _console?.timeEnd ?? noop_default;
    timeLog = _console?.timeLog ?? noop_default;
    timeStamp = _console?.timeStamp ?? noop_default;
    Console = _console?.Console ?? /* @__PURE__ */ notImplementedClass("console.Console");
    _times = /* @__PURE__ */ new Map();
    _stdoutErrorHandler = noop_default;
    _stderrErrorHandler = noop_default;
    workerdConsole = globalThis["console"];
    ({
      assert,
      clear: clear2,
      context: (
        // @ts-expect-error undocumented public API
        context
      ),
      count: count2,
      countReset: countReset2,
      createTask: createTask2,
      debug: debug2,
      dir: dir2,
      dirxml: dirxml2,
      error: error2,
      group: group2,
      groupCollapsed: groupCollapsed2,
      groupEnd: groupEnd2,
      info: info2,
      log: log2,
      profile: profile2,
      profileEnd: profileEnd2,
      table: table2,
      time: time2,
      timeEnd: timeEnd2,
      timeLog: timeLog2,
      timeStamp: timeStamp2,
      trace: trace2,
      warn: warn2
    } = workerdConsole);
    Object.assign(workerdConsole, {
      Console,
      _ignoreErrors,
      _stderr,
      _stderrErrorHandler,
      _stdout,
      _stdoutErrorHandler,
      _times
    });
    console_default = workerdConsole;
    globalThis.console = console_default;
    hrtime = /* @__PURE__ */ Object.assign(/* @__PURE__ */ __name2(/* @__PURE__ */ __name(function hrtime2(startTime) {
      const now = Date.now();
      const seconds = Math.trunc(now / 1e3);
      const nanos = now % 1e3 * 1e6;
      if (startTime) {
        let diffSeconds = seconds - startTime[0];
        let diffNanos = nanos - startTime[0];
        if (diffNanos < 0) {
          diffSeconds = diffSeconds - 1;
          diffNanos = 1e9 + diffNanos;
        }
        return [diffSeconds, diffNanos];
      }
      return [seconds, nanos];
    }, "hrtime2"), "hrtime"), { bigint: /* @__PURE__ */ __name2(/* @__PURE__ */ __name(function bigint() {
      return BigInt(Date.now() * 1e6);
    }, "bigint"), "bigint") });
    ReadStream = class extends Socket {
      static {
        __name(this, "ReadStream");
      }
      fd;
      constructor(fd) {
        super();
        this.fd = fd;
      }
      isRaw = false;
      setRawMode(mode) {
        this.isRaw = mode;
        return this;
      }
      isTTY = false;
    };
    __name2(ReadStream, "ReadStream");
    WriteStream = class extends Socket2 {
      static {
        __name(this, "WriteStream");
      }
      fd;
      constructor(fd) {
        super();
        this.fd = fd;
      }
      clearLine(dir3, callback) {
        callback && callback();
        return false;
      }
      clearScreenDown(callback) {
        callback && callback();
        return false;
      }
      cursorTo(x, y, callback) {
        callback && typeof callback === "function" && callback();
        return false;
      }
      moveCursor(dx, dy, callback) {
        callback && callback();
        return false;
      }
      getColorDepth(env2) {
        return 1;
      }
      hasColors(count3, env2) {
        return false;
      }
      getWindowSize() {
        return [this.columns, this.rows];
      }
      columns = 80;
      rows = 24;
      isTTY = false;
    };
    __name2(WriteStream, "WriteStream");
    Process = class extends EventEmitter {
      static {
        __name(this, "Process");
      }
      env;
      hrtime;
      nextTick;
      constructor(impl) {
        super();
        this.env = impl.env;
        this.hrtime = impl.hrtime;
        this.nextTick = impl.nextTick;
        for (const prop of [...Object.getOwnPropertyNames(Process.prototype), ...Object.getOwnPropertyNames(EventEmitter.prototype)]) {
          const value = this[prop];
          if (typeof value === "function") {
            this[prop] = value.bind(this);
          }
        }
      }
      emitWarning(warning, type, code) {
        console.warn(`${code ? `[${code}] ` : ""}${type ? `${type}: ` : ""}${warning}`);
      }
      emit(...args) {
        return super.emit(...args);
      }
      listeners(eventName) {
        return super.listeners(eventName);
      }
      #stdin;
      #stdout;
      #stderr;
      get stdin() {
        return this.#stdin ??= new ReadStream(0);
      }
      get stdout() {
        return this.#stdout ??= new WriteStream(1);
      }
      get stderr() {
        return this.#stderr ??= new WriteStream(2);
      }
      #cwd = "/";
      chdir(cwd2) {
        this.#cwd = cwd2;
      }
      cwd() {
        return this.#cwd;
      }
      arch = "";
      platform = "";
      argv = [];
      argv0 = "";
      execArgv = [];
      execPath = "";
      title = "";
      pid = 200;
      ppid = 100;
      get version() {
        return "";
      }
      get versions() {
        return {};
      }
      get allowedNodeEnvironmentFlags() {
        return /* @__PURE__ */ new Set();
      }
      get sourceMapsEnabled() {
        return false;
      }
      get debugPort() {
        return 0;
      }
      get throwDeprecation() {
        return false;
      }
      get traceDeprecation() {
        return false;
      }
      get features() {
        return {};
      }
      get release() {
        return {};
      }
      get connected() {
        return false;
      }
      get config() {
        return {};
      }
      get moduleLoadList() {
        return [];
      }
      constrainedMemory() {
        return 0;
      }
      availableMemory() {
        return 0;
      }
      uptime() {
        return 0;
      }
      resourceUsage() {
        return {};
      }
      ref() {
      }
      unref() {
      }
      umask() {
        throw createNotImplementedError("process.umask");
      }
      getBuiltinModule() {
        return void 0;
      }
      getActiveResourcesInfo() {
        throw createNotImplementedError("process.getActiveResourcesInfo");
      }
      exit() {
        throw createNotImplementedError("process.exit");
      }
      reallyExit() {
        throw createNotImplementedError("process.reallyExit");
      }
      kill() {
        throw createNotImplementedError("process.kill");
      }
      abort() {
        throw createNotImplementedError("process.abort");
      }
      dlopen() {
        throw createNotImplementedError("process.dlopen");
      }
      setSourceMapsEnabled() {
        throw createNotImplementedError("process.setSourceMapsEnabled");
      }
      loadEnvFile() {
        throw createNotImplementedError("process.loadEnvFile");
      }
      disconnect() {
        throw createNotImplementedError("process.disconnect");
      }
      cpuUsage() {
        throw createNotImplementedError("process.cpuUsage");
      }
      setUncaughtExceptionCaptureCallback() {
        throw createNotImplementedError("process.setUncaughtExceptionCaptureCallback");
      }
      hasUncaughtExceptionCaptureCallback() {
        throw createNotImplementedError("process.hasUncaughtExceptionCaptureCallback");
      }
      initgroups() {
        throw createNotImplementedError("process.initgroups");
      }
      openStdin() {
        throw createNotImplementedError("process.openStdin");
      }
      assert() {
        throw createNotImplementedError("process.assert");
      }
      binding() {
        throw createNotImplementedError("process.binding");
      }
      permission = { has: /* @__PURE__ */ notImplemented("process.permission.has") };
      report = {
        directory: "",
        filename: "",
        signal: "SIGUSR2",
        compact: false,
        reportOnFatalError: false,
        reportOnSignal: false,
        reportOnUncaughtException: false,
        getReport: /* @__PURE__ */ notImplemented("process.report.getReport"),
        writeReport: /* @__PURE__ */ notImplemented("process.report.writeReport")
      };
      finalization = {
        register: /* @__PURE__ */ notImplemented("process.finalization.register"),
        unregister: /* @__PURE__ */ notImplemented("process.finalization.unregister"),
        registerBeforeExit: /* @__PURE__ */ notImplemented("process.finalization.registerBeforeExit")
      };
      memoryUsage = Object.assign(() => ({
        arrayBuffers: 0,
        rss: 0,
        external: 0,
        heapTotal: 0,
        heapUsed: 0
      }), { rss: /* @__PURE__ */ __name(() => 0, "rss") });
      mainModule = void 0;
      domain = void 0;
      send = void 0;
      exitCode = void 0;
      channel = void 0;
      getegid = void 0;
      geteuid = void 0;
      getgid = void 0;
      getgroups = void 0;
      getuid = void 0;
      setegid = void 0;
      seteuid = void 0;
      setgid = void 0;
      setgroups = void 0;
      setuid = void 0;
      _events = void 0;
      _eventsCount = void 0;
      _exiting = void 0;
      _maxListeners = void 0;
      _debugEnd = void 0;
      _debugProcess = void 0;
      _fatalException = void 0;
      _getActiveHandles = void 0;
      _getActiveRequests = void 0;
      _kill = void 0;
      _preload_modules = void 0;
      _rawDebug = void 0;
      _startProfilerIdleNotifier = void 0;
      _stopProfilerIdleNotifier = void 0;
      _tickCallback = void 0;
      _disconnect = void 0;
      _handleQueue = void 0;
      _pendingMessage = void 0;
      _channel = void 0;
      _send = void 0;
      _linkedBinding = void 0;
    };
    __name2(Process, "Process");
    globalProcess = globalThis["process"];
    getBuiltinModule = globalProcess.getBuiltinModule;
    ({ exit, platform, nextTick } = getBuiltinModule(
      "node:process"
    ));
    unenvProcess = new Process({
      env: globalProcess.env,
      hrtime,
      nextTick
    });
    ({
      abort,
      addListener,
      allowedNodeEnvironmentFlags,
      hasUncaughtExceptionCaptureCallback,
      setUncaughtExceptionCaptureCallback,
      loadEnvFile,
      sourceMapsEnabled,
      arch,
      argv,
      argv0,
      chdir,
      config,
      connected,
      constrainedMemory,
      availableMemory,
      cpuUsage,
      cwd,
      debugPort,
      dlopen,
      disconnect,
      emit,
      emitWarning,
      env,
      eventNames,
      execArgv,
      execPath,
      finalization,
      features,
      getActiveResourcesInfo,
      getMaxListeners,
      hrtime: hrtime3,
      kill,
      listeners,
      listenerCount,
      memoryUsage,
      on,
      off,
      once,
      pid,
      ppid,
      prependListener,
      prependOnceListener,
      rawListeners,
      release,
      removeAllListeners,
      removeListener,
      report,
      resourceUsage,
      setMaxListeners,
      setSourceMapsEnabled,
      stderr,
      stdin,
      stdout,
      title,
      throwDeprecation,
      traceDeprecation,
      umask,
      uptime,
      version,
      versions,
      domain,
      initgroups,
      moduleLoadList,
      reallyExit,
      openStdin,
      assert: assert2,
      binding,
      send,
      exitCode,
      channel,
      getegid,
      geteuid,
      getgid,
      getgroups,
      getuid,
      setegid,
      seteuid,
      setgid,
      setgroups,
      setuid,
      permission,
      mainModule,
      _events,
      _eventsCount,
      _exiting,
      _maxListeners,
      _debugEnd,
      _debugProcess,
      _fatalException,
      _getActiveHandles,
      _getActiveRequests,
      _kill,
      _preload_modules,
      _rawDebug,
      _startProfilerIdleNotifier,
      _stopProfilerIdleNotifier,
      _tickCallback,
      _disconnect,
      _handleQueue,
      _pendingMessage,
      _channel,
      _send,
      _linkedBinding
    } = unenvProcess);
    _process = {
      abort,
      addListener,
      allowedNodeEnvironmentFlags,
      hasUncaughtExceptionCaptureCallback,
      setUncaughtExceptionCaptureCallback,
      loadEnvFile,
      sourceMapsEnabled,
      arch,
      argv,
      argv0,
      chdir,
      config,
      connected,
      constrainedMemory,
      availableMemory,
      cpuUsage,
      cwd,
      debugPort,
      dlopen,
      disconnect,
      emit,
      emitWarning,
      env,
      eventNames,
      execArgv,
      execPath,
      exit,
      finalization,
      features,
      getBuiltinModule,
      getActiveResourcesInfo,
      getMaxListeners,
      hrtime: hrtime3,
      kill,
      listeners,
      listenerCount,
      memoryUsage,
      nextTick,
      on,
      off,
      once,
      pid,
      platform,
      ppid,
      prependListener,
      prependOnceListener,
      rawListeners,
      release,
      removeAllListeners,
      removeListener,
      report,
      resourceUsage,
      setMaxListeners,
      setSourceMapsEnabled,
      stderr,
      stdin,
      stdout,
      title,
      throwDeprecation,
      traceDeprecation,
      umask,
      uptime,
      version,
      versions,
      // @ts-expect-error old API
      domain,
      initgroups,
      moduleLoadList,
      reallyExit,
      openStdin,
      assert: assert2,
      binding,
      send,
      exitCode,
      channel,
      getegid,
      geteuid,
      getgid,
      getgroups,
      getuid,
      setegid,
      seteuid,
      setgid,
      setgroups,
      setuid,
      permission,
      mainModule,
      _events,
      _eventsCount,
      _exiting,
      _maxListeners,
      _debugEnd,
      _debugProcess,
      _fatalException,
      _getActiveHandles,
      _getActiveRequests,
      _kill,
      _preload_modules,
      _rawDebug,
      _startProfilerIdleNotifier,
      _stopProfilerIdleNotifier,
      _tickCallback,
      _disconnect,
      _handleQueue,
      _pendingMessage,
      _channel,
      _send,
      _linkedBinding
    };
    process_default = _process;
    globalThis.process = process_default;
    __name(getKV, "getKV");
    __name2(getKV, "getKV");
    APP_CONFIG = {
      name: "HEX Panel",
      tagline: "HEX Nebula // Encrypted Edge Proxy & DNS Panel",
      version: "5.3.0",
      // bk_* is the HEX cookie; wd_session is still accepted so sessions
      // issued before the rename keep working until they expire.
      cookieName: "hex_session",
      legacyCookieName: "wd_session",
      // No defaultJwtSecret here on purpose: a signing key committed to a
      // public repo is a master key to every deployment that uses it.
      defaultDevPassword: "hex123",
      // Development channel, surfaced in the sidebar and on the login page so
      // operators know where updates and support actually come from.
      telegramChannel: "https://t.me/HEX_Net",
      sessionMaxAgeSeconds: 60 * 60 * 24 * 7,
      // 7 days
      defaultProxyPath: "/hex-ws",
      defaultDohUpstream: "https://cloudflare-dns.com/dns-query",
      defaultWarpPeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    };
    KV_KEYS = {
      adminPassword: "config:admin_password",
      jwtSecret: "config:jwt_secret",
      settings: "config:settings",
      vlessUuid: "config:vless_uuid",
      trojanPassword: "config:trojan_password",
      proxyPath: "config:proxy_path",
      proxyIp: "config:proxy_ip",
      relayIp: "config:relay_ip",
      nat64Prefixes: "config:nat64_prefixes",
      subToken: "config:sub_token",
      dnsDoH: "config:dns_doh",
      allowLANConnection: "config:allow_lan_connection",
      fragmentEnabled: "config:fragment_enabled",
      fragmentPackets: "config:fragment_packets",
      fragmentLength: "config:fragment_length",
      fragmentInterval: "config:fragment_interval",
      routingPreset: "config:routing_preset",
      warpPrivateKey: "config:warp_private_key",
      warpPeerPublicKey: "config:warp_peer_public_key",
      warpIPv6: "config:warp_ipv6",
      warpReserved: "config:warp_reserved",
      // Warp Pro & AmneziaWG
      warpProEnabled: "config:warp_pro_enabled",
      warpAmneziaVersion: "config:warp_amnezia_version",
      warpNoiseCount: "config:warp_noise_count",
      warpNoiseMin: "config:warp_noise_min",
      warpNoiseMax: "config:warp_noise_max",
      warpNoiseDelay: "config:warp_noise_delay",
      warpAmneziaS1: "config:warp_amnezia_s1",
      warpAmneziaS2: "config:warp_amnezia_s2",
      warpAmneziaH1: "config:warp_amnezia_h1",
      warpAmneziaH2: "config:warp_amnezia_h2",
      warpAmneziaH3: "config:warp_amnezia_h3",
      warpAmneziaH4: "config:warp_amnezia_h4",
      // Chain Proxy
      chainEnabled: "config:chain_enabled",
      chainType: "config:chain_type",
      chainAddress: "config:chain_address",
      chainPort: "config:chain_port",
      chainAuth: "config:chain_auth",
      chainPath: "config:chain_path",
      chainSecurity: "config:chain_security",
      chainTransport: "config:chain_transport",
      chainSni: "config:chain_sni",
      chainHost: "config:chain_host",
      // Node Share
      nodeShareToken: "config:node_share_token",
      // Domain Fronting
      domainFrontingEnabled: "config:domain_fronting_enabled",
      frontingSni: "config:fronting_sni",
      frontingHost: "config:fronting_host",
      frontingCleanIps: "config:fronting_clean_ips",
      // Static IP Pool
      staticIpList: "config:static_ip_list",
      // OpenVPN
      openvpnEnabled: "config:openvpn_enabled",
      openvpnPort: "config:openvpn_port",
      openvpnProto: "config:openvpn_proto",
      openvpnCipher: "config:openvpn_cipher",
      // AnyTLS
      anytlsFingerprint: "config:anytls_fingerprint",
      anytlsAlpn: "config:anytls_alpn",
      // XHTTP & HTTP Upgrade
      xhttpEnabled: "config:xhttp_enabled",
      xhttpPath: "config:xhttp_path",
      xhttpMode: "config:xhttp_mode",
      httpUpgradeEnabled: "config:http_upgrade_enabled",
      // Shadowsocks
      ssEnabled: "config:ss_enabled",
      ssPassword: "config:ss_password",
      ssMethod: "config:ss_method",
      // Custom DNS
      dnsCustom: "config:dns_custom",
      clientDnsSettings: "config:client_dns"
    };
    __name(generateRandomToken, "generateRandomToken");
    __name2(generateRandomToken, "generateRandomToken");
    __name(generateRandomPassword, "generateRandomPassword");
    __name2(generateRandomPassword, "generateRandomPassword");
    cachedSettings = null;
    cachedSettingsTimestamp = 0;
    CACHE_TTL_MS = 36e5;
    __name(invalidateSettingsCache, "invalidateSettingsCache");
    __name2(invalidateSettingsCache, "invalidateSettingsCache");
    __name(getOrInitSettings, "getOrInitSettings");
    __name2(getOrInitSettings, "getOrInitSettings");
    __name(handleHealth, "handleHealth");
    __name2(handleHealth, "handleHealth");
    __name(handleProxyDebug, "handleProxyDebug");
    __name2(handleProxyDebug, "handleProxyDebug");
    webcrypto_default = crypto;
    isCryptoKey = /* @__PURE__ */ __name2((key) => key instanceof CryptoKey, "isCryptoKey");
    encoder = new TextEncoder();
    decoder = new TextDecoder();
    MAX_INT32 = 2 ** 32;
    __name(concat, "concat");
    __name2(concat, "concat");
    encodeBase64 = /* @__PURE__ */ __name2((input) => {
      let unencoded = input;
      if (typeof unencoded === "string") {
        unencoded = encoder.encode(unencoded);
      }
      const CHUNK_SIZE = 32768;
      const arr = [];
      for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
      }
      return btoa(arr.join(""));
    }, "encodeBase64");
    encode = /* @__PURE__ */ __name2((input) => {
      return encodeBase64(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    }, "encode");
    decodeBase64 = /* @__PURE__ */ __name2((encoded) => {
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }, "decodeBase64");
    decode = /* @__PURE__ */ __name2((input) => {
      let encoded = input;
      if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
      }
      encoded = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
      try {
        return decodeBase64(encoded);
      } catch {
        throw new TypeError("The input to be decoded is not correctly encoded.");
      }
    }, "decode");
    JOSEError = class extends Error {
      static {
        __name(this, "JOSEError");
      }
      constructor(message2, options) {
        super(message2, options);
        this.code = "ERR_JOSE_GENERIC";
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    __name2(JOSEError, "JOSEError");
    JOSEError.code = "ERR_JOSE_GENERIC";
    JWTClaimValidationFailed = class extends JOSEError {
      static {
        __name(this, "JWTClaimValidationFailed");
      }
      constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
        super(message2, { cause: { claim, reason, payload } });
        this.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
      }
    };
    __name2(JWTClaimValidationFailed, "JWTClaimValidationFailed");
    JWTClaimValidationFailed.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
    JWTExpired = class extends JOSEError {
      static {
        __name(this, "JWTExpired");
      }
      constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
        super(message2, { cause: { claim, reason, payload } });
        this.code = "ERR_JWT_EXPIRED";
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
      }
    };
    __name2(JWTExpired, "JWTExpired");
    JWTExpired.code = "ERR_JWT_EXPIRED";
    JOSEAlgNotAllowed = class extends JOSEError {
      static {
        __name(this, "JOSEAlgNotAllowed");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_ALG_NOT_ALLOWED";
      }
    };
    __name2(JOSEAlgNotAllowed, "JOSEAlgNotAllowed");
    JOSEAlgNotAllowed.code = "ERR_JOSE_ALG_NOT_ALLOWED";
    JOSENotSupported = class extends JOSEError {
      static {
        __name(this, "JOSENotSupported");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_NOT_SUPPORTED";
      }
    };
    __name2(JOSENotSupported, "JOSENotSupported");
    JOSENotSupported.code = "ERR_JOSE_NOT_SUPPORTED";
    JWEDecryptionFailed = class extends JOSEError {
      static {
        __name(this, "JWEDecryptionFailed");
      }
      constructor(message2 = "decryption operation failed", options) {
        super(message2, options);
        this.code = "ERR_JWE_DECRYPTION_FAILED";
      }
    };
    __name2(JWEDecryptionFailed, "JWEDecryptionFailed");
    JWEDecryptionFailed.code = "ERR_JWE_DECRYPTION_FAILED";
    JWEInvalid = class extends JOSEError {
      static {
        __name(this, "JWEInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWE_INVALID";
      }
    };
    __name2(JWEInvalid, "JWEInvalid");
    JWEInvalid.code = "ERR_JWE_INVALID";
    JWSInvalid = class extends JOSEError {
      static {
        __name(this, "JWSInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWS_INVALID";
      }
    };
    __name2(JWSInvalid, "JWSInvalid");
    JWSInvalid.code = "ERR_JWS_INVALID";
    JWTInvalid = class extends JOSEError {
      static {
        __name(this, "JWTInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWT_INVALID";
      }
    };
    __name2(JWTInvalid, "JWTInvalid");
    JWTInvalid.code = "ERR_JWT_INVALID";
    JWKInvalid = class extends JOSEError {
      static {
        __name(this, "JWKInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWK_INVALID";
      }
    };
    __name2(JWKInvalid, "JWKInvalid");
    JWKInvalid.code = "ERR_JWK_INVALID";
    JWKSInvalid = class extends JOSEError {
      static {
        __name(this, "JWKSInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWKS_INVALID";
      }
    };
    __name2(JWKSInvalid, "JWKSInvalid");
    JWKSInvalid.code = "ERR_JWKS_INVALID";
    JWKSNoMatchingKey = class extends JOSEError {
      static {
        __name(this, "JWKSNoMatchingKey");
      }
      constructor(message2 = "no applicable key found in the JSON Web Key Set", options) {
        super(message2, options);
        this.code = "ERR_JWKS_NO_MATCHING_KEY";
      }
    };
    __name2(JWKSNoMatchingKey, "JWKSNoMatchingKey");
    JWKSNoMatchingKey.code = "ERR_JWKS_NO_MATCHING_KEY";
    JWKSMultipleMatchingKeys = class extends JOSEError {
      static {
        __name(this, "JWKSMultipleMatchingKeys");
      }
      constructor(message2 = "multiple matching keys found in the JSON Web Key Set", options) {
        super(message2, options);
        this.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
      }
    };
    __name2(JWKSMultipleMatchingKeys, "JWKSMultipleMatchingKeys");
    JWKSMultipleMatchingKeys.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
    JWKSTimeout = class extends JOSEError {
      static {
        __name(this, "JWKSTimeout");
      }
      constructor(message2 = "request timed out", options) {
        super(message2, options);
        this.code = "ERR_JWKS_TIMEOUT";
      }
    };
    __name2(JWKSTimeout, "JWKSTimeout");
    JWKSTimeout.code = "ERR_JWKS_TIMEOUT";
    JWSSignatureVerificationFailed = class extends JOSEError {
      static {
        __name(this, "JWSSignatureVerificationFailed");
      }
      constructor(message2 = "signature verification failed", options) {
        super(message2, options);
        this.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
      }
    };
    __name2(JWSSignatureVerificationFailed, "JWSSignatureVerificationFailed");
    JWSSignatureVerificationFailed.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
    __name(unusable, "unusable");
    __name2(unusable, "unusable");
    __name(isAlgorithm, "isAlgorithm");
    __name2(isAlgorithm, "isAlgorithm");
    __name(getHashLength, "getHashLength");
    __name2(getHashLength, "getHashLength");
    __name(getNamedCurve, "getNamedCurve");
    __name2(getNamedCurve, "getNamedCurve");
    __name(checkUsage, "checkUsage");
    __name2(checkUsage, "checkUsage");
    __name(checkSigCryptoKey, "checkSigCryptoKey");
    __name2(checkSigCryptoKey, "checkSigCryptoKey");
    __name(message, "message");
    __name2(message, "message");
    invalid_key_input_default = /* @__PURE__ */ __name2((actual, ...types2) => {
      return message("Key must be ", actual, ...types2);
    }, "default");
    __name(withAlg, "withAlg");
    __name2(withAlg, "withAlg");
    is_key_like_default = /* @__PURE__ */ __name2((key) => {
      if (isCryptoKey(key)) {
        return true;
      }
      return key?.[Symbol.toStringTag] === "KeyObject";
    }, "default");
    types = ["CryptoKey"];
    isDisjoint = /* @__PURE__ */ __name2((...headers) => {
      const sources = headers.filter(Boolean);
      if (sources.length === 0 || sources.length === 1) {
        return true;
      }
      let acc;
      for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
          acc = new Set(parameters);
          continue;
        }
        for (const parameter of parameters) {
          if (acc.has(parameter)) {
            return false;
          }
          acc.add(parameter);
        }
      }
      return true;
    }, "isDisjoint");
    is_disjoint_default = isDisjoint;
    __name(isObjectLike, "isObjectLike");
    __name2(isObjectLike, "isObjectLike");
    __name(isObject, "isObject");
    __name2(isObject, "isObject");
    check_key_length_default = /* @__PURE__ */ __name2((alg, key) => {
      if (alg.startsWith("RS") || alg.startsWith("PS")) {
        const { modulusLength } = key.algorithm;
        if (typeof modulusLength !== "number" || modulusLength < 2048) {
          throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
        }
      }
    }, "default");
    __name(isJWK, "isJWK");
    __name2(isJWK, "isJWK");
    __name(isPrivateJWK, "isPrivateJWK");
    __name2(isPrivateJWK, "isPrivateJWK");
    __name(isPublicJWK, "isPublicJWK");
    __name2(isPublicJWK, "isPublicJWK");
    __name(isSecretJWK, "isSecretJWK");
    __name2(isSecretJWK, "isSecretJWK");
    __name(subtleMapping, "subtleMapping");
    __name2(subtleMapping, "subtleMapping");
    parse = /* @__PURE__ */ __name2(async (jwk) => {
      if (!jwk.alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
      }
      const { algorithm, keyUsages } = subtleMapping(jwk);
      const rest = [
        algorithm,
        jwk.ext ?? false,
        jwk.key_ops ?? keyUsages
      ];
      const keyData = { ...jwk };
      delete keyData.alg;
      delete keyData.use;
      return webcrypto_default.subtle.importKey("jwk", keyData, ...rest);
    }, "parse");
    jwk_to_key_default = parse;
    exportKeyValue = /* @__PURE__ */ __name2((k) => decode(k), "exportKeyValue");
    isKeyObject = /* @__PURE__ */ __name2((key) => {
      return key?.[Symbol.toStringTag] === "KeyObject";
    }, "isKeyObject");
    importAndCache = /* @__PURE__ */ __name2(async (cache, key, jwk, alg, freeze = false) => {
      let cached = cache.get(key);
      if (cached?.[alg]) {
        return cached[alg];
      }
      const cryptoKey = await jwk_to_key_default({ ...jwk, alg });
      if (freeze)
        Object.freeze(key);
      if (!cached) {
        cache.set(key, { [alg]: cryptoKey });
      } else {
        cached[alg] = cryptoKey;
      }
      return cryptoKey;
    }, "importAndCache");
    normalizePublicKey = /* @__PURE__ */ __name2((key, alg) => {
      if (isKeyObject(key)) {
        let jwk = key.export({ format: "jwk" });
        delete jwk.d;
        delete jwk.dp;
        delete jwk.dq;
        delete jwk.p;
        delete jwk.q;
        delete jwk.qi;
        if (jwk.k) {
          return exportKeyValue(jwk.k);
        }
        pubCache || (pubCache = /* @__PURE__ */ new WeakMap());
        return importAndCache(pubCache, key, jwk, alg);
      }
      if (isJWK(key)) {
        if (key.k)
          return decode(key.k);
        pubCache || (pubCache = /* @__PURE__ */ new WeakMap());
        const cryptoKey = importAndCache(pubCache, key, key, alg, true);
        return cryptoKey;
      }
      return key;
    }, "normalizePublicKey");
    normalizePrivateKey = /* @__PURE__ */ __name2((key, alg) => {
      if (isKeyObject(key)) {
        let jwk = key.export({ format: "jwk" });
        if (jwk.k) {
          return exportKeyValue(jwk.k);
        }
        privCache || (privCache = /* @__PURE__ */ new WeakMap());
        return importAndCache(privCache, key, jwk, alg);
      }
      if (isJWK(key)) {
        if (key.k)
          return decode(key.k);
        privCache || (privCache = /* @__PURE__ */ new WeakMap());
        const cryptoKey = importAndCache(privCache, key, key, alg, true);
        return cryptoKey;
      }
      return key;
    }, "normalizePrivateKey");
    normalize_key_default = { normalizePublicKey, normalizePrivateKey };
    __name(importJWK, "importJWK");
    __name2(importJWK, "importJWK");
    tag = /* @__PURE__ */ __name2((key) => key?.[Symbol.toStringTag], "tag");
    jwkMatchesOp = /* @__PURE__ */ __name2((alg, key, usage) => {
      if (key.use !== void 0 && key.use !== "sig") {
        throw new TypeError("Invalid key for this operation, when present its use must be sig");
      }
      if (key.key_ops !== void 0 && key.key_ops.includes?.(usage) !== true) {
        throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${usage}`);
      }
      if (key.alg !== void 0 && key.alg !== alg) {
        throw new TypeError(`Invalid key for this operation, when present its alg must be ${alg}`);
      }
      return true;
    }, "jwkMatchesOp");
    symmetricTypeCheck = /* @__PURE__ */ __name2((alg, key, usage, allowJwk) => {
      if (key instanceof Uint8Array)
        return;
      if (allowJwk && isJWK(key)) {
        if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
          return;
        throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
      }
      if (!is_key_like_default(key)) {
        throw new TypeError(withAlg(alg, key, ...types, "Uint8Array", allowJwk ? "JSON Web Key" : null));
      }
      if (key.type !== "secret") {
        throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
      }
    }, "symmetricTypeCheck");
    asymmetricTypeCheck = /* @__PURE__ */ __name2((alg, key, usage, allowJwk) => {
      if (allowJwk && isJWK(key)) {
        switch (usage) {
          case "sign":
            if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
              return;
            throw new TypeError(`JSON Web Key for this operation be a private JWK`);
          case "verify":
            if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
              return;
            throw new TypeError(`JSON Web Key for this operation be a public JWK`);
        }
      }
      if (!is_key_like_default(key)) {
        throw new TypeError(withAlg(alg, key, ...types, allowJwk ? "JSON Web Key" : null));
      }
      if (key.type === "secret") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
      }
      if (usage === "sign" && key.type === "public") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
      }
      if (usage === "decrypt" && key.type === "public") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
      }
      if (key.algorithm && usage === "verify" && key.type === "private") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
      }
      if (key.algorithm && usage === "encrypt" && key.type === "private") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
      }
    }, "asymmetricTypeCheck");
    __name(checkKeyType, "checkKeyType");
    __name2(checkKeyType, "checkKeyType");
    check_key_type_default = checkKeyType.bind(void 0, false);
    checkKeyTypeWithJwk = checkKeyType.bind(void 0, true);
    __name(validateCrit, "validateCrit");
    __name2(validateCrit, "validateCrit");
    validate_crit_default = validateCrit;
    validateAlgorithms = /* @__PURE__ */ __name2((option, algorithms) => {
      if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string"))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
      }
      if (!algorithms) {
        return void 0;
      }
      return new Set(algorithms);
    }, "validateAlgorithms");
    validate_algorithms_default = validateAlgorithms;
    __name(subtleDsa, "subtleDsa");
    __name2(subtleDsa, "subtleDsa");
    __name(getCryptoKey, "getCryptoKey");
    __name2(getCryptoKey, "getCryptoKey");
    verify = /* @__PURE__ */ __name2(async (alg, key, signature, data) => {
      const cryptoKey = await getCryptoKey(alg, key, "verify");
      check_key_length_default(alg, cryptoKey);
      const algorithm = subtleDsa(alg, cryptoKey.algorithm);
      try {
        return await webcrypto_default.subtle.verify(algorithm, cryptoKey, signature, data);
      } catch {
        return false;
      }
    }, "verify");
    verify_default = verify;
    __name(flattenedVerify, "flattenedVerify");
    __name2(flattenedVerify, "flattenedVerify");
    __name(compactVerify, "compactVerify");
    __name2(compactVerify, "compactVerify");
    epoch_default = /* @__PURE__ */ __name2((date) => Math.floor(date.getTime() / 1e3), "default");
    minute = 60;
    hour = minute * 60;
    day = hour * 24;
    week = day * 7;
    year = day * 365.25;
    REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
    secs_default = /* @__PURE__ */ __name2((str) => {
      const matched = REGEX.exec(str);
      if (!matched || matched[4] && matched[1]) {
        throw new TypeError("Invalid time period format");
      }
      const value = parseFloat(matched[2]);
      const unit = matched[3].toLowerCase();
      let numericDate;
      switch (unit) {
        case "sec":
        case "secs":
        case "second":
        case "seconds":
        case "s":
          numericDate = Math.round(value);
          break;
        case "minute":
        case "minutes":
        case "min":
        case "mins":
        case "m":
          numericDate = Math.round(value * minute);
          break;
        case "hour":
        case "hours":
        case "hr":
        case "hrs":
        case "h":
          numericDate = Math.round(value * hour);
          break;
        case "day":
        case "days":
        case "d":
          numericDate = Math.round(value * day);
          break;
        case "week":
        case "weeks":
        case "w":
          numericDate = Math.round(value * week);
          break;
        default:
          numericDate = Math.round(value * year);
          break;
      }
      if (matched[1] === "-" || matched[4] === "ago") {
        return -numericDate;
      }
      return numericDate;
    }, "default");
    normalizeTyp = /* @__PURE__ */ __name2((value) => value.toLowerCase().replace(/^application\//, ""), "normalizeTyp");
    checkAudiencePresence = /* @__PURE__ */ __name2((audPayload, audOption) => {
      if (typeof audPayload === "string") {
        return audOption.includes(audPayload);
      }
      if (Array.isArray(audPayload)) {
        return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
      }
      return false;
    }, "checkAudiencePresence");
    jwt_claims_set_default = /* @__PURE__ */ __name2((protectedHeader, encodedPayload, options = {}) => {
      let payload;
      try {
        payload = JSON.parse(decoder.decode(encodedPayload));
      } catch {
      }
      if (!isObject(payload)) {
        throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
      }
      const { typ } = options;
      if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
        throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, "typ", "check_failed");
      }
      const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
      const presenceCheck = [...requiredClaims];
      if (maxTokenAge !== void 0)
        presenceCheck.push("iat");
      if (audience !== void 0)
        presenceCheck.push("aud");
      if (subject !== void 0)
        presenceCheck.push("sub");
      if (issuer !== void 0)
        presenceCheck.push("iss");
      for (const claim of new Set(presenceCheck.reverse())) {
        if (!(claim in payload)) {
          throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, "missing");
        }
      }
      if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
        throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, "iss", "check_failed");
      }
      if (subject && payload.sub !== subject) {
        throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, "sub", "check_failed");
      }
      if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
        throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, "aud", "check_failed");
      }
      let tolerance;
      switch (typeof options.clockTolerance) {
        case "string":
          tolerance = secs_default(options.clockTolerance);
          break;
        case "number":
          tolerance = options.clockTolerance;
          break;
        case "undefined":
          tolerance = 0;
          break;
        default:
          throw new TypeError("Invalid clockTolerance option type");
      }
      const { currentDate } = options;
      const now = epoch_default(currentDate || /* @__PURE__ */ new Date());
      if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
        throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, "iat", "invalid");
      }
      if (payload.nbf !== void 0) {
        if (typeof payload.nbf !== "number") {
          throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, "nbf", "invalid");
        }
        if (payload.nbf > now + tolerance) {
          throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, "nbf", "check_failed");
        }
      }
      if (payload.exp !== void 0) {
        if (typeof payload.exp !== "number") {
          throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, "exp", "invalid");
        }
        if (payload.exp <= now - tolerance) {
          throw new JWTExpired('"exp" claim timestamp check failed', payload, "exp", "check_failed");
        }
      }
      if (maxTokenAge) {
        const age = now - payload.iat;
        const max = typeof maxTokenAge === "number" ? maxTokenAge : secs_default(maxTokenAge);
        if (age - tolerance > max) {
          throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, "iat", "check_failed");
        }
        if (age < 0 - tolerance) {
          throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, "iat", "check_failed");
        }
      }
      return payload;
    }, "default");
    __name(jwtVerify, "jwtVerify");
    __name2(jwtVerify, "jwtVerify");
    sign = /* @__PURE__ */ __name2(async (alg, key, data) => {
      const cryptoKey = await getCryptoKey(alg, key, "sign");
      check_key_length_default(alg, cryptoKey);
      const signature = await webcrypto_default.subtle.sign(subtleDsa(alg, cryptoKey.algorithm), cryptoKey, data);
      return new Uint8Array(signature);
    }, "sign");
    sign_default = sign;
    FlattenedSign = class {
      static {
        __name(this, "FlattenedSign");
      }
      constructor(payload) {
        if (!(payload instanceof Uint8Array)) {
          throw new TypeError("payload must be an instance of Uint8Array");
        }
        this._payload = payload;
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
      }
      async sign(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader) {
          throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
        }
        if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader)) {
          throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
        }
        const joseHeader = {
          ...this._protectedHeader,
          ...this._unprotectedHeader
        };
        const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, this._protectedHeader, joseHeader);
        let b64 = true;
        if (extensions.has("b64")) {
          b64 = this._protectedHeader.b64;
          if (typeof b64 !== "boolean") {
            throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
          }
        }
        const { alg } = joseHeader;
        if (typeof alg !== "string" || !alg) {
          throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        checkKeyTypeWithJwk(alg, key, "sign");
        let payload = this._payload;
        if (b64) {
          payload = encoder.encode(encode(payload));
        }
        let protectedHeader;
        if (this._protectedHeader) {
          protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        } else {
          protectedHeader = encoder.encode("");
        }
        const data = concat(protectedHeader, encoder.encode("."), payload);
        const signature = await sign_default(alg, key, data);
        const jws = {
          signature: encode(signature),
          payload: ""
        };
        if (b64) {
          jws.payload = decoder.decode(payload);
        }
        if (this._unprotectedHeader) {
          jws.header = this._unprotectedHeader;
        }
        if (this._protectedHeader) {
          jws.protected = decoder.decode(protectedHeader);
        }
        return jws;
      }
    };
    __name2(FlattenedSign, "FlattenedSign");
    CompactSign = class {
      static {
        __name(this, "CompactSign");
      }
      constructor(payload) {
        this._flattened = new FlattenedSign(payload);
      }
      setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
      }
      async sign(key, options) {
        const jws = await this._flattened.sign(key, options);
        if (jws.payload === void 0) {
          throw new TypeError("use the flattened module for creating JWS with b64: false");
        }
        return `${jws.protected}.${jws.payload}.${jws.signature}`;
      }
    };
    __name2(CompactSign, "CompactSign");
    __name(validateInput, "validateInput");
    __name2(validateInput, "validateInput");
    ProduceJWT = class {
      static {
        __name(this, "ProduceJWT");
      }
      constructor(payload = {}) {
        if (!isObject(payload)) {
          throw new TypeError("JWT Claims Set MUST be an object");
        }
        this._payload = payload;
      }
      setIssuer(issuer) {
        this._payload = { ...this._payload, iss: issuer };
        return this;
      }
      setSubject(subject) {
        this._payload = { ...this._payload, sub: subject };
        return this;
      }
      setAudience(audience) {
        this._payload = { ...this._payload, aud: audience };
        return this;
      }
      setJti(jwtId) {
        this._payload = { ...this._payload, jti: jwtId };
        return this;
      }
      setNotBefore(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, nbf: validateInput("setNotBefore", input) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, nbf: validateInput("setNotBefore", epoch_default(input)) };
        } else {
          this._payload = { ...this._payload, nbf: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input) };
        }
        return this;
      }
      setExpirationTime(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, exp: validateInput("setExpirationTime", input) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, exp: validateInput("setExpirationTime", epoch_default(input)) };
        } else {
          this._payload = { ...this._payload, exp: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input) };
        }
        return this;
      }
      setIssuedAt(input) {
        if (typeof input === "undefined") {
          this._payload = { ...this._payload, iat: epoch_default(/* @__PURE__ */ new Date()) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, iat: validateInput("setIssuedAt", epoch_default(input)) };
        } else if (typeof input === "string") {
          this._payload = {
            ...this._payload,
            iat: validateInput("setIssuedAt", epoch_default(/* @__PURE__ */ new Date()) + secs_default(input))
          };
        } else {
          this._payload = { ...this._payload, iat: validateInput("setIssuedAt", input) };
        }
        return this;
      }
    };
    __name2(ProduceJWT, "ProduceJWT");
    SignJWT = class extends ProduceJWT {
      static {
        __name(this, "SignJWT");
      }
      setProtectedHeader(protectedHeader) {
        this._protectedHeader = protectedHeader;
        return this;
      }
      async sign(key, options) {
        const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
        sig.setProtectedHeader(this._protectedHeader);
        if (Array.isArray(this._protectedHeader?.crit) && this._protectedHeader.crit.includes("b64") && this._protectedHeader.b64 === false) {
          throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
        }
        return sig.sign(key, options);
      }
    };
    __name2(SignJWT, "SignJWT");
    cachedJwtSecret = null;
    __name(getJwtSecret, "getJwtSecret");
    __name2(getJwtSecret, "getJwtSecret");
    __name(getSecretKey, "getSecretKey");
    __name2(getSecretKey, "getSecretKey");
    __name(createSessionToken, "createSessionToken");
    __name2(createSessionToken, "createSessionToken");
    __name(verifySessionToken, "verifySessionToken");
    __name2(verifySessionToken, "verifySessionToken");
    __name(parseCookies, "parseCookies");
    __name2(parseCookies, "parseCookies");
    __name(getSessionCookie, "getSessionCookie");
    __name2(getSessionCookie, "getSessionCookie");
    __name(createSessionCookie, "createSessionCookie");
    __name2(createSessionCookie, "createSessionCookie");
    __name(createClearCookie, "createClearCookie");
    __name2(createClearCookie, "createClearCookie");
    __name(constantTimeEquals, "constantTimeEquals");
    __name2(constantTimeEquals, "constantTimeEquals");
    cachedPasswordConfigured = null;
    cachedAdminPassword = null;
    __name(invalidatePasswordCache, "invalidatePasswordCache");
    __name2(invalidatePasswordCache, "invalidatePasswordCache");
    __name(hasConfiguredPassword, "hasConfiguredPassword");
    __name2(hasConfiguredPassword, "hasConfiguredPassword");
    __name(getExpectedPassword, "getExpectedPassword");
    __name2(getExpectedPassword, "getExpectedPassword");
    __name(verifyPassword, "verifyPassword");
    __name2(verifyPassword, "verifyPassword");
    __name(setPassword, "setPassword");
    __name2(setPassword, "setPassword");
    MASCOT_SVG = `<svg class="mascot-icon" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" width="48" height="48">
  <defs>
    <linearGradient id="hex-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00FFA3"/>
      <stop offset="50%" stop-color="#7C3AED"/>
      <stop offset="100%" stop-color="#06B6D4"/>
    </linearGradient>
    <filter id="hex-glow">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  <!-- Outer hex -->
  <path d="M50 8 L84 28 L84 72 L50 92 L16 72 L16 28 Z" stroke="url(#hex-gradient)" stroke-width="3" fill="rgba(124,58,237,0.08)" filter="url(#hex-glow)"/>
  <!-- Inner hex -->
  <path d="M50 18 L75 33 L75 67 L50 82 L25 67 L25 33 Z" stroke="#00FFA3" stroke-width="1.5" fill="none" opacity="0.6"/>
  <!-- Center H -->
  <path d="M38 38 L38 62 M62 38 L62 62 M38 50 L62 50" stroke="#FFFFFF" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  <!-- Corner dots -->
  <circle cx="50" cy="8" r="2.5" fill="#00FFA3"/>
  <circle cx="84" cy="28" r="2.5" fill="#7C3AED"/>
  <circle cx="84" cy="72" r="2.5" fill="#06B6D4"/>
  <circle cx="50" cy="92" r="2.5" fill="#00FFA3"/>
  <circle cx="16" cy="72" r="2.5" fill="#7C3AED"/>
  <circle cx="16" cy="28" r="2.5" fill="#06B6D4"/>
</svg>`;
    BASE_STYLES = `@import url('https://fonts.googleapis.com/css2?family=Quicksand:wght@500;600;700&family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ==========================================================================
   BLUEKNIGHT 5 DYNAMIC ADAPTIVE THEMES (LIGHT & DARK GLASS PALETTES)
   ========================================================================== */

:root, html[data-theme="theme-1"] {
  --theme-id: "theme-1";
  --theme-name: "Lunar Eclipse";
  --theme-primary: #7DD3FC;
  --theme-primary-hover: #38BDF8;
  --theme-primary-soft: rgba(125, 211, 252, 0.14);
  --theme-primary-rgb: 125, 211, 252;
  --theme-secondary: #94A3B8;
  --theme-accent: #38BDF8;

  --theme-bg-image: url('/assets/theme-bg-1.jpg?v=${APP_CONFIG.version}');
  --theme-bg-overlay: rgba(4, 8, 16, 0.38);
  --theme-bg-fallback: #070B14;

  --theme-surface: rgba(10, 16, 28, 0.80);
  --theme-surface-soft: rgba(255, 255, 255, 0.05);
  --theme-surface-strong: rgba(14, 22, 38, 0.94);

  --theme-border: rgba(255, 255, 255, 0.10);
  --theme-border-hover: rgba(125, 211, 252, 0.50);

  --theme-shadow: rgba(0, 0, 0, 0.55);
  --theme-glow: rgba(125, 211, 252, 0.30);

  --theme-text-primary: #F1F5F9;
  --theme-text-secondary: #CBD5E1;
  --theme-text-muted: #94A3B8;

  --theme-input-bg: rgba(6, 12, 24, 0.85);
  --theme-input-border: rgba(255, 255, 255, 0.14);

  --theme-btn-primary-bg: linear-gradient(135deg, #7DD3FC 0%, #3B82F6 100%);
  --theme-btn-primary-hover: linear-gradient(135deg, #3B82F6 0%, #3B82F6 100%);
  --theme-btn-primary-text: #04111F;

  --theme-btn-secondary-bg: rgba(255, 255, 255, 0.08);
  --theme-btn-secondary-hover: rgba(255, 255, 255, 0.15);
  --theme-btn-secondary-text: #F1F5F9;
  --theme-btn-secondary-border: rgba(255, 255, 255, 0.14);

  --theme-badge-bg: rgba(125, 211, 252, 0.14);
  --theme-badge-text: #BAE6FD;
}

html[data-theme="theme-2"] {
  --theme-id: "theme-2";
  --theme-name: "Emerald Forest";
  --theme-primary: #10B981;
  --theme-primary-hover: #059669;
  --theme-primary-soft: rgba(16, 185, 129, 0.14);
  --theme-primary-rgb: 16, 185, 129;
  --theme-secondary: #047857;
  --theme-accent: #34D399;

  --theme-bg-image: url('/assets/theme-bg-2.jpg?v=${APP_CONFIG.version}');
  --theme-bg-overlay: rgba(2, 12, 8, 0.45);
  --theme-bg-fallback: #04120C;

  --theme-surface: rgba(6, 24, 18, 0.80);
  --theme-surface-soft: rgba(255, 255, 255, 0.05);
  --theme-surface-strong: rgba(8, 32, 24, 0.94);

  --theme-border: rgba(255, 255, 255, 0.10);
  --theme-border-hover: rgba(16, 185, 129, 0.50);

  --theme-shadow: rgba(0, 0, 0, 0.55);
  --theme-glow: rgba(16, 185, 129, 0.30);

  --theme-text-primary: #ECFDF5;
  --theme-text-secondary: #D1FAE5;
  --theme-text-muted: #6EE7B7;

  --theme-input-bg: rgba(3, 16, 11, 0.85);
  --theme-input-border: rgba(255, 255, 255, 0.14);

  --theme-btn-primary-bg: linear-gradient(135deg, #10B981 0%, #047857 100%);
  --theme-btn-primary-hover: linear-gradient(135deg, #047857 0%, #047857 100%);
  --theme-btn-primary-text: #FFFFFF;

  --theme-btn-secondary-bg: rgba(255, 255, 255, 0.08);
  --theme-btn-secondary-hover: rgba(255, 255, 255, 0.15);
  --theme-btn-secondary-text: #ECFDF5;
  --theme-btn-secondary-border: rgba(255, 255, 255, 0.14);

  --theme-badge-bg: rgba(16, 185, 129, 0.18);
  --theme-badge-text: #A7F3D0;
}

html[data-theme="theme-3"] {
  --theme-id: "theme-3";
  --theme-name: "Blood Moon Ronin";
  --theme-primary: #EF4444;
  --theme-primary-hover: #DC2626;
  --theme-primary-soft: rgba(239, 68, 68, 0.14);
  --theme-primary-rgb: 239, 68, 68;
  --theme-secondary: #991B1B;
  --theme-accent: #F87171;

  --theme-bg-image: url('/assets/theme-bg-3.jpg?v=${APP_CONFIG.version}');
  --theme-bg-overlay: rgba(14, 2, 4, 0.42);
  --theme-bg-fallback: #12060A;

  --theme-surface: rgba(26, 8, 10, 0.80);
  --theme-surface-soft: rgba(255, 255, 255, 0.05);
  --theme-surface-strong: rgba(36, 10, 14, 0.94);

  --theme-border: rgba(255, 255, 255, 0.10);
  --theme-border-hover: rgba(239, 68, 68, 0.50);

  --theme-shadow: rgba(127, 29, 29, 0.45);
  --theme-glow: rgba(239, 68, 68, 0.30);

  --theme-text-primary: #FEF2F2;
  --theme-text-secondary: #FECACA;
  --theme-text-muted: #FCA5A5;

  --theme-input-bg: rgba(18, 5, 7, 0.85);
  --theme-input-border: rgba(255, 255, 255, 0.14);

  --theme-btn-primary-bg: linear-gradient(135deg, #EF4444 0%, #B91C1C 100%);
  --theme-btn-primary-hover: linear-gradient(135deg, #B91C1C 0%, #B91C1C 100%);
  --theme-btn-primary-text: #FFFFFF;

  --theme-btn-secondary-bg: rgba(255, 255, 255, 0.08);
  --theme-btn-secondary-hover: rgba(255, 255, 255, 0.15);
  --theme-btn-secondary-text: #FEF2F2;
  --theme-btn-secondary-border: rgba(255, 255, 255, 0.14);

  --theme-badge-bg: rgba(239, 68, 68, 0.18);
  --theme-badge-text: #FECACA;
}

html[data-theme="theme-4"] {
  --theme-id: "theme-4";
  --theme-name: "Neon Night";
  --theme-primary: #8B5CF6;
  --theme-primary-hover: #7C3AED;
  --theme-primary-soft: rgba(139, 92, 246, 0.14);
  --theme-primary-rgb: 139, 92, 246;
  --theme-secondary: #6366F1;
  --theme-accent: #38BDF8;

  --theme-bg-image: url('/assets/theme-bg-4.jpg?v=${APP_CONFIG.version}');
  --theme-bg-overlay: rgba(5, 3, 16, 0.40);
  --theme-bg-fallback: #07051A;

  --theme-surface: rgba(14, 10, 34, 0.80);
  --theme-surface-soft: rgba(255, 255, 255, 0.05);
  --theme-surface-strong: rgba(20, 14, 46, 0.94);

  --theme-border: rgba(255, 255, 255, 0.10);
  --theme-border-hover: rgba(139, 92, 246, 0.50);

  --theme-shadow: rgba(49, 46, 129, 0.5);
  --theme-glow: rgba(139, 92, 246, 0.30);

  --theme-text-primary: #F5F3FF;
  --theme-text-secondary: #DDD6FE;
  --theme-text-muted: #A5B4FC;

  --theme-input-bg: rgba(9, 6, 24, 0.85);
  --theme-input-border: rgba(255, 255, 255, 0.14);

  --theme-btn-primary-bg: linear-gradient(135deg, #8B5CF6 0%, #4F46E5 100%);
  --theme-btn-primary-hover: linear-gradient(135deg, #4F46E5 0%, #4F46E5 100%);
  --theme-btn-primary-text: #FFFFFF;

  --theme-btn-secondary-bg: rgba(255, 255, 255, 0.08);
  --theme-btn-secondary-hover: rgba(255, 255, 255, 0.15);
  --theme-btn-secondary-text: #F5F3FF;
  --theme-btn-secondary-border: rgba(255, 255, 255, 0.14);

  --theme-badge-bg: rgba(139, 92, 246, 0.20);
  --theme-badge-text: #DDD6FE;
}

html[data-theme="theme-5"] {
  --theme-id: "theme-5";
  --theme-name: "Dark Knight";
  --theme-primary: ##05080FBF24;
  --theme-primary-hover: #F59E0B;
  --theme-primary-soft: rgba(251, 191, 36, 0.14);
  --theme-primary-rgb: 251, 191, 36;
  --theme-secondary: #94A3B8;
  --theme-accent: #60A5FA;

  --theme-bg-image: url('/assets/theme-bg-5.jpg?v=${APP_CONFIG.version}');
  --theme-bg-overlay: rgba(3, 6, 14, 0.40);
  --theme-bg-fallback: #05080F;

  --theme-surface: rgba(10, 14, 24, 0.82);
  --theme-surface-soft: rgba(255, 255, 255, 0.05);
  --theme-surface-strong: rgba(14, 20, 34, 0.95);

  --theme-border: rgba(255, 255, 255, 0.10);
  --theme-border-hover: rgba(251, 191, 36, 0.50);

  --theme-shadow: rgba(0, 0, 0, 0.6);
  --theme-glow: rgba(251, 191, 36, 0.30);

  --theme-text-primary: #F1F5F9;
  --theme-text-secondary: #CBD5E1;
  --theme-text-muted: #94A3B8;

  --theme-input-bg: rgba(6, 10, 20, 0.88);
  --theme-input-border: rgba(255, 255, 255, 0.14);

  --theme-btn-primary-bg: linear-gradient(135deg, #FBBF24 0%, #D97706 100%);
  --theme-btn-primary-hover: linear-gradient(135deg, #D97706 0%, #D97706 100%);
  --theme-btn-primary-text: #111827;

  --theme-btn-secondary-bg: rgba(255, 255, 255, 0.08);
  --theme-btn-secondary-hover: rgba(255, 255, 255, 0.15);
  --theme-btn-secondary-text: #F1F5F9;
  --theme-btn-secondary-border: rgba(255, 255, 255, 0.14);

  --theme-badge-bg: rgba(251, 191, 36, 0.14);
  --theme-badge-text: #FDE68A;
}



/* ==========================================================================
   GLOBAL RESET & TYPOGRAPHY
   ========================================================================== */

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--theme-bg-fallback);
  background-image: var(--theme-bg-image);
  background-size: cover;
  background-position: center center;
  background-attachment: fixed;
  background-repeat: no-repeat;
  color: var(--theme-text-primary);
  font-family: 'Nunito', system-ui, -apple-system, sans-serif;
  font-size: 14.5px;
  line-height: 1.55;
  min-height: 100vh;
  position: relative;
  overflow-x: hidden;
}

/* Subtle atmosphere overlay: keeps wallpaper vibrant while maintaining AAA text contrast */
body::before {
  content: "";
  position: fixed;
  inset: 0;
  background: var(--theme-bg-overlay);
  z-index: 0;
  pointer-events: none;
}

body > * {
  position: relative;
  z-index: 1;
}

h1, h2, h3, h4, .brand-title {
  font-family: 'Quicksand', system-ui, sans-serif;
  font-weight: 700;
  color: var(--theme-text-primary);
  line-height: 1.25;
}

a {
  color: var(--theme-primary);
  text-decoration: none;
  transition: all 0.2s ease;
}

a:hover {
  color: var(--theme-primary-hover);
}

/* ==========================================================================
   PERSISTENT FLOATING APPLICATION SHELL
   ========================================================================== */

.app-layout {
  --sidebar-w: 320px;
  /* A circle has constant curvature, so the sweep reads the whole way down.
     The old ellipse was 112px wide and 110vh tall: through the middle 70% of
     the height its edge moved barely 13px, which is a straight line to the eye,
     with all the bend crammed into the top and bottom caps.
     R = 240vh puts the bulge at 5.27vh (depth = R - sqrt(R^2 - (H/2)^2)). */
  --arc-r: 170vh;
  --arc-depth: 7.52vh;
  --arc-inset: 20px;
  display: flex;
  min-height: 100vh;
  width: 100%;
  position: relative;
  z-index: 1;
  background: transparent;
}

@media (max-width: 1024px) {
  .app-layout { --sidebar-w: 264px; --arc-r: 170vh; --arc-depth: 7.52vh; --arc-inset: 16px; }
}
/* Below 860px the arc moves onto the drawer itself -- see the .app-sidebar::before
   rule in the mobile block further down, which re-anchors this panel with
   position:absolute so it travels with the drawer's transform. */

/* The sidebar is flush to the viewport and full height. Its visible surface is
   the frosted ::before panel below; the element itself stays transparent so the
   arc can be masked out of the surface without touching the nav. */
.app-sidebar {
  width: var(--sidebar-w, 288px);
  min-width: var(--sidebar-w, 288px);
  flex-shrink: 0;
  position: sticky;
  top: 0;
  height: 100vh;
  margin: 0;
  background: transparent;
  border: 0;
  isolation: isolate;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  /* The cut reaches its deepest at mid-height, so rows stop short of it.
     Logical, not physical: the arc mirrors in RTL (see the [dir="rtl"] mask
     below), so the clearance has to mirror with it or RTL rows run into the
     cut while 100px sits empty on the flush edge. */
  padding-block: 22px 18px;
  padding-inline: 16px calc(var(--arc-depth) + var(--arc-inset) + 18px);
  z-index: 100;
  transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  box-sizing: border-box;
}

/* The sidebar's frosted surface. It is a pseudo-element rather than the
   sidebar's own background so the arc can be masked out of it without also
   masking the nav sitting on top.
   The mask is one circle: everything inside it is cut away, so the panel's
   trailing edge follows that circle -- receding to (sidebar-w - depth) at the
   middle of the viewport and returning to sidebar-w at top and bottom. Same
   curve as before; the difference is that what shows through the cut is the
   page wallpaper, not a flat theme colour. */
.app-sidebar::before {
  content: "";
  position: fixed;
  top: 0;
  bottom: 0;
  inset-inline-start: 0;
  width: var(--sidebar-w);
  z-index: -1;
  pointer-events: none;
  /* --theme-surface (0.84) not -strong (0.95): the original sidebar was glass,
     and at 95% the wallpaper stops reading through it. */
  background: var(--theme-surface);
  backdrop-filter: blur(17px);
  -webkit-backdrop-filter: blur(17px);
  -webkit-mask-image: radial-gradient(circle var(--arc-r) at
    calc(var(--sidebar-w) - var(--arc-depth) - var(--arc-inset) + var(--arc-r)) 50vh,
    transparent 99.8%, #000 99.9%);
  mask-image: radial-gradient(circle var(--arc-r) at
    calc(var(--sidebar-w) - var(--arc-depth) - var(--arc-inset) + var(--arc-r)) 50vh,
    transparent 99.8%, #000 99.9%);
}

/* Sidebar sits on the trailing edge in RTL, so the cut mirrors. */
[dir="rtl"] .app-sidebar::before {
  -webkit-mask-image: radial-gradient(circle var(--arc-r) at
    calc(var(--arc-depth) + var(--arc-inset) - var(--arc-r)) 50vh,
    transparent 99.8%, #000 99.9%);
  mask-image: radial-gradient(circle var(--arc-r) at
    calc(var(--arc-depth) + var(--arc-inset) - var(--arc-r)) 50vh,
    transparent 99.8%, #000 99.9%);
}

/* Brand lockup: mark in a tinted tile, wordmark and tagline stacked beside it. */
.sidebar-brand {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 2px 6px 16px 6px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--theme-border);
}

.brand-mark {
  width: 40px;
  height: 40px;
  border-radius: 13px;
  display: grid;
  place-items: center;
  flex-shrink: 0;
  background: linear-gradient(145deg,
    rgba(var(--theme-primary-rgb), 0.22),
    rgba(var(--theme-primary-rgb), 0.10));
  border: 1px solid rgba(var(--theme-primary-rgb), 0.28);
  box-shadow: 0 4px 12px var(--theme-glow);
}
.brand-mark svg { width: 24px; height: 24px; display: block; }

.brand-tagline {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--theme-text-muted);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  margin-top: 1px;
}

/* Small caption above a group of nav rows. */
.nav-section {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.11em;
  text-transform: uppercase;
  color: var(--theme-text-muted);
  padding: 0 12px;
  margin: 14px 0 6px;
}
.nav-section:first-child { margin-top: 2px; }

.sidebar-nav {
  display: flex;
  flex-direction: column;
  gap: 4px;
  overflow-y: auto;
  flex: 1;
  padding-right: 2px;
}

.sidebar-nav::-webkit-scrollbar {
  width: 4px;
}
.sidebar-nav::-webkit-scrollbar-thumb {
  background: var(--theme-border);
  border-radius: 4px;
}

/* Slim, comfortable navigation buttons */
/* Nav row: an icon tile plus a label, not a bare glyph beside text. */
.nav-btn {
  display: flex;
  align-items: center;
  gap: 11px;
  width: 100%;
  height: 46px;
  padding: 0 10px;
  border-radius: 14px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--theme-text-secondary);
  font-family: 'Quicksand', system-ui, sans-serif;
  font-weight: 700;
  font-size: 13.5px;
  cursor: pointer;
  transition: background 0.16s ease, color 0.16s ease, border-color 0.16s ease;
  text-decoration: none;
  box-sizing: border-box;
  position: relative;
}

/* A nav label is a single row at every width -- wrapping it to two lines
   inside a fixed 46px button clips the descenders. Narrow enough and it
   ellipsizes instead, which stays legible. */
.nav-btn > span:not(.nav-icon):not(.nav-tag) {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}

/* Trailing status pill on the external links. */
.nav-tag {
  flex-shrink: 0;
  margin-inline-start: auto;
  font-size: 9.5px;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--theme-primary);
  background: rgba(var(--theme-primary-rgb), 0.12);
  border: 1px solid rgba(var(--theme-primary-rgb), 0.18);
  border-radius: 999px;
  padding: 2px 7px;
}

/* Tinted from the theme accent, not the white-on-glass surface tokens: those
   were tuned to read against a photo, and the sidebar now sits on the flat
   shell colour where white-on-white would disappear. */
.nav-btn .nav-icon,
.nav-icon {
  font-size: 15px;
  line-height: 1;
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border-radius: 10px;
  flex-shrink: 0;
  background: rgba(var(--theme-primary-rgb), 0.10);
  border: 1px solid rgba(var(--theme-primary-rgb), 0.16);
  transition: background 0.16s ease, border-color 0.16s ease;
}

/* Same reason: hairlines inside the sidebar need a colour with contrast on a
   light flat surface. */
.sidebar-brand { border-bottom-color: rgba(var(--theme-primary-rgb), 0.18); }
.sidebar-footer { border-top-color: rgba(var(--theme-primary-rgb), 0.18); }
.nav-btn:hover { background: rgba(var(--theme-primary-rgb), 0.07); }

/* No translateX: nudging the row on hover made the whole list feel loose. */
.nav-btn:hover {
  background: var(--theme-surface-soft);
  color: var(--theme-text-primary);
}
.nav-btn:hover .nav-icon {
  border-color: rgba(var(--theme-primary-rgb), 0.28);
}

.nav-btn.active {
  background: var(--theme-primary-soft) !important;
  color: var(--theme-primary) !important;
  border-color: rgba(var(--theme-primary-rgb), 0.22) !important;
}
/* A filled tile marks the active row. The old 3.5px inline-start border shifted
   the label sideways every time the selection moved. */
.nav-btn.active .nav-icon {
  background: var(--theme-primary) !important;
  border-color: var(--theme-primary) !important;
  box-shadow: 0 4px 12px var(--theme-glow);
}
.nav-btn.active::before {
  content: "";
  position: absolute;
  inset-inline-start: -14px;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 22px;
  border-radius: 0 3px 3px 0;
  background: var(--theme-primary);
}

/* Sidebar bottom status & logout */
.sidebar-footer {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--theme-border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

/* Footer status card: dot, two-line label, trailing badge. */
.sidebar-status-pill {
  background: rgba(var(--theme-primary-rgb), 0.09);
  border: 1px solid rgba(var(--theme-primary-rgb), 0.20);
  border-radius: 14px;
  padding: 11px 12px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.sidebar-status-pill .badge {
  font-size: 9.5px;
  padding: 2px 7px;
  flex-shrink: 0;
}

.sidebar-status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--theme-primary);
  box-shadow: 0 0 8px var(--theme-primary);
  flex-shrink: 0;
}

/* Transparent main canvas - NO giant frosted container! */
/* The slab. Its inline-start corners are the curve; the overlay tint is layered
   into background-image rather than a pseudo-element so the radius clips it for
   free. No auto margins: content belongs beside the nav, not adrift in the
   middle of the viewport. */
.app-main {
  flex: 1;
  min-width: 0;
  padding: 30px 34px 44px 42px;
  width: 100%;
  min-height: 100vh;
  box-sizing: border-box;
  position: relative;
  z-index: 3;
  background: transparent;
}

/* Inner column: wide enough to use the space, capped so text lines do not run
   the full width of an ultrawide monitor. */
.app-main > * {
  max-width: 1500px;
}



/* ==========================================================================
   HEADER & TOP ACTION BAR
   ========================================================================== */

.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--theme-surface);
  border: 1px solid var(--theme-border);
  border-radius: 16px;
  backdrop-filter: blur(17px);
  -webkit-backdrop-filter: blur(17px);
  box-shadow: 0 8px 24px -4px var(--theme-shadow);
  padding: 10px 18px;
  margin-bottom: 18px;
  gap: 12px;
  flex-wrap: wrap;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-icon-box {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  background: var(--theme-primary-soft);
  border: 1px solid var(--theme-border-hover);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

/* Theme selector pill */
.theme-pill-control {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--theme-input-bg);
  border: 1px solid var(--theme-border);
  padding: 4px 10px;
  border-radius: 9999px;
  box-shadow: 0 2px 6px rgba(0,0,0,0.04);
  /* The select sizes to its longest option ("Theme 10 -- Obsidian Amethyst"),
     which is wider than a 320px phone. Cap the pill and let the select shrink
     below min-content (see min-width: 0 below) so it ellipsizes instead. */
  max-width: 100%;
}

.theme-pill-control select {
  min-width: 0;
  text-overflow: ellipsis;
  border: none;
  background: transparent;
  font-family: 'Quicksand', system-ui, sans-serif;
  font-size: 12.5px;
  font-weight: 700;
  color: var(--theme-text-primary);
  cursor: pointer;
  outline: none;
}

.theme-pill-control select option {
  background: #FFFFFF;
  color: #0F172A;
}

.theme-dice-btn {
  border: none;
  background: var(--theme-primary-soft);
  border-radius: 50%;
  width: 24px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  font-size: 12px;
  transition: transform 0.2s ease;
}

.theme-dice-btn:hover {
  transform: rotate(45deg);
}

/* Mobile toggle button */
.mobile-nav-toggle {
  display: none;
  background: var(--theme-surface);
  border: 1px solid var(--theme-border);
  color: var(--theme-text-primary);
  border-radius: 8px;
  width: 36px;
  height: 36px;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  cursor: pointer;
}

/* ==========================================================================
   CARD SYSTEM & GRIDS (BALANCED, COMPACT, CONTENT-DRIVEN)
   ========================================================================== */

.card {
  background: var(--theme-surface);
  border: 1px solid var(--theme-border);
  border-radius: 16px;
  box-shadow: 0 10px 30px -4px var(--theme-shadow), 0 2px 6px rgba(0,0,0,0.04);
  padding: 16px 18px;
  backdrop-filter: blur(17px);
  -webkit-backdrop-filter: blur(17px);
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
  box-sizing: border-box;
}

.card:hover {
  border-color: var(--theme-border-hover);
  box-shadow: 0 14px 36px -4px var(--theme-shadow), 0 0 16px var(--theme-glow);
}

.card-primary {
  border-radius: 18px;
  padding: 20px 22px;
  border-top: 3.5px solid var(--theme-primary);
}

.card-title {
  font-size: 15.5px;
  font-weight: 700;
  color: var(--theme-text-primary);
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.card-desc {
  font-size: 12px;
  color: var(--theme-text-muted);
  line-height: 1.45;
  margin-bottom: 14px;
}

/* Responsive Grid layouts */
.grid-2col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.grid-3col {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.grid-main-right {
  display: grid;
  grid-template-columns: 2.3fr 1fr;
  gap: 16px;
}

/* Quick Action Tiles */
.quick-action-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.action-tile {
  background: var(--theme-surface-strong);
  border: 1px solid var(--theme-border);
  border-radius: 14px;
  padding: 12px 14px;
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  transition: all 0.2s ease;
  text-decoration: none;
  color: var(--theme-text-primary);
}

.action-tile:hover {
  border-color: var(--theme-primary);
  background: var(--theme-primary-soft);
  color: var(--theme-primary);
  transform: translateY(-2px);
  box-shadow: 0 6px 18px var(--theme-glow);
}

.action-tile-icon {
  font-size: 20px;
  line-height: 1;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: var(--theme-primary-soft);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.action-tile-text h4 {
  font-size: 13px;
  font-weight: 700;
  line-height: 1.2;
}

.action-tile-text p {
  font-size: 11px;
  color: var(--theme-text-muted);
  margin-top: 2px;
}

/* ==========================================================================
   COMPACT SETTING ROWS & FORM CONTROLS
   ========================================================================== */

.setting-group {
  display: flex;
  flex-direction: column;
}

.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid var(--theme-border);
  gap: 14px;
}

.setting-row:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.setting-row:first-child {
  padding-top: 0;
}

.setting-label-col {
  flex: 1;
  min-width: 0;
}

.setting-title {
  font-size: 13.5px;
  font-weight: 700;
  color: var(--theme-text-primary);
  margin-bottom: 2px;
  font-family: 'Quicksand', system-ui, sans-serif;
}

.setting-subtitle {
  font-size: 11.5px;
  color: var(--theme-text-muted);
  line-height: 1.35;
}

.setting-control-col {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* Form Groups & Inputs */
.form-group {
  margin-bottom: 14px;
}

.form-label {
  display: block;
  font-family: 'Quicksand', system-ui, sans-serif;
  font-weight: 700;
  font-size: 12.5px;
  color: var(--theme-text-primary);
  margin-bottom: 5px;
}

.form-control {
  width: 100%;
  height: 38px;
  padding: 0 12px;
  border-radius: 10px;
  border: 1.5px solid var(--theme-input-border);
  background: var(--theme-input-bg);
  color: var(--theme-text-primary);
  font-family: 'Nunito', system-ui, sans-serif;
  font-size: 13.5px;
  transition: all 0.18s ease;
  outline: none;
  box-sizing: border-box;
}

.form-control:focus {
  border-color: var(--theme-primary);
  box-shadow: 0 0 0 3px var(--theme-glow);
}

.form-control.code-input {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}

textarea.form-control {
  height: auto;
  min-height: 72px;
  padding: 8px 12px;
  resize: vertical;
}

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  font-family: 'Quicksand', system-ui, sans-serif;
  font-weight: 700;
  font-size: 13.5px;
  height: 38px;
  padding: 0 16px;
  border-radius: 10px;
  border: 1px solid transparent;
  cursor: pointer;
  transition: all 0.18s ease;
  text-decoration: none;
  box-sizing: border-box;
  white-space: nowrap;
}

.btn-primary {
  background: var(--theme-btn-primary-bg);
  color: var(--theme-btn-primary-text);
  box-shadow: 0 4px 14px var(--theme-glow);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 18px var(--theme-glow);
  color: var(--theme-btn-primary-text);
}

.btn-secondary {
  background: var(--theme-btn-secondary-bg);
  color: var(--theme-btn-secondary-text);
  border: 1px solid var(--theme-btn-secondary-border);
}

.btn-secondary:hover {
  background: var(--theme-btn-secondary-hover);
  border-color: var(--theme-primary);
  color: var(--theme-primary);
  transform: translateY(-1px);
}

.btn-sm {
  height: 30px;
  padding: 0 10px;
  font-size: 12px;
  border-radius: 8px;
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: 9999px;
  font-size: 11.5px;
  font-weight: 700;
  font-family: 'Quicksand', system-ui, sans-serif;
  letter-spacing: 0.2px;
  white-space: nowrap;
}

.badge-mint {
  background: rgba(16, 185, 129, 0.15);
  color: #10B981;
  border: 1px solid rgba(16, 185, 129, 0.35);
}

.badge-lavender {
  background: rgba(139, 92, 246, 0.15);
  color: #8B5CF6;
  border: 1px solid rgba(139, 92, 246, 0.35);
}

.badge-sky {
  background: rgba(2, 132, 199, 0.15);
  color: #0284C7;
  border: 1px solid rgba(2, 132, 199, 0.35);
}

.badge-sakura {
  background: rgba(244, 63, 94, 0.15);
  color: #F43F5E;
  border: 1px solid rgba(244, 63, 94, 0.35);
}

.badge-amber {
  background: rgba(245, 158, 11, 0.15);
  color: #F59E0B;
  border: 1px solid rgba(245, 158, 11, 0.35);
}

/* Copy wrapper */
.copy-wrapper {
  position: relative;
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
}

.copy-wrapper input {
  flex: 1;
  min-width: 0;
}

.copy-actions {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
}

/* Tab pane animation */
.tab-pane {
  display: none;
}

.tab-pane.active {
  display: block;
  animation: fadeInTab 0.2s ease forwards;
}

@keyframes fadeInTab {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Toast */
.toast-msg {
  position: fixed;
  bottom: 20px;
  right: 20px;
  padding: 10px 18px;
  background: var(--theme-surface-strong);
  color: var(--theme-text-primary);
  border-radius: 9999px;
  font-family: 'Quicksand', system-ui, sans-serif;
  font-weight: 700;
  font-size: 13px;
  box-shadow: 0 12px 30px rgba(0,0,0,0.25);
  transform: translateY(80px);
  opacity: 0;
  transition: all 0.25s cubic-bezier(0.18, 0.89, 0.32, 1.28);
  z-index: 2000;
  display: flex;
  align-items: center;
  gap: 8px;
  border: 1px solid var(--theme-border);
}

.toast-msg.show {
  transform: translateY(0);
  opacity: 1;
}

/* Modal */
.modal-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(10, 15, 26, 0.65);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  z-index: 1500;
  align-items: center;
  justify-content: center;
  padding: 16px;
}

.modal-backdrop.show {
  display: flex !important;
}

.modal-card {
  background: var(--theme-surface-strong);
  border: 1px solid var(--theme-border);
  border-radius: 18px;
  padding: 20px;
  max-width: 380px;
  width: 100%;
  box-shadow: 0 20px 48px var(--theme-shadow);
  box-sizing: border-box;
}

/* Mobile drawer backdrop */
.drawer-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(10, 15, 26, 0.50);
  z-index: 90;
  opacity: 0;
  transition: opacity 0.25s ease;
}

/* ==========================================================================
   RESPONSIVE BREAKPOINTS
   ========================================================================== */

@media (max-width: 1024px) {
  .app-sidebar {
    padding-inline-end: calc(var(--arc-depth) + var(--arc-inset) + 14px);
  }
  .grid-main-right {
    grid-template-columns: 1fr !important;
  }
  .grid-3col {
    grid-template-columns: 1fr 1fr !important;
  }
}

@media (max-width: 860px) {
  .app-layout {
    flex-direction: column !important;
    /* z-index:1 here (and from the "body > *" rule) made .app-layout a
       stacking context,
       which trapped the drawer's z-index:1000 inside it. The backdrop is a root
       sibling at z-index:90, so 90 beat the whole subtree and the backdrop
       painted over the open drawer -- every tap on a nav row hit the backdrop
       and closed the drawer instead of navigating.
       z-index:auto keeps the position:relative but creates no context, so the
       drawer (1000) sits above the backdrop (90) and .app-main (3) below it,
       which is what the dimming wanted in the first place. */
    z-index: auto !important;
  }
  .mobile-nav-toggle {
    display: flex !important;
  }
  .app-sidebar {
    position: fixed !important;
    top: 0 !important;
    bottom: 0 !important;
    left: 0 !important;
    margin: 0 !important;
    height: 100vh !important;
    width: min(80vw, 280px) !important;
    /* width alone loses to the desktop min-width, so reset that too. */
    min-width: 0 !important;
    transform: translateX(-100%) !important;
    z-index: 1000 !important;
    /* Surface and radius live on ::before so the arc can be masked out of them
       without also masking the nav. Keep the element itself transparent. */
    background: transparent !important;
    /* A shallower arc than desktop. Same circle, larger radius:
       depth = R - sqrt(R^2 - (H/2)^2), so R=280vh gives 4.5vh instead of the
       7.52vh a 170vh radius would. The desktop cut is 21% of a 320px sidebar;
       at 7.52vh it would take 22% of a 280px drawer but out of far less
       absolute room, which pushed "API Health" onto two lines. */
    --arc-r: 280vh;
    --arc-depth: 4.5vh;
    --arc-inset: 12px;
    padding-inline-end: calc(var(--arc-depth) + var(--arc-inset) + 12px) !important;
  }

  /* The arc, on the drawer. The desktop ::before is position:fixed to the
     viewport edge, so it cannot travel with a translateX drawer -- that is why
     it used to be display:none here. Anchored to the drawer with
     position:absolute instead, it moves with the transform and keeps the arc.
     The mask circle is measured from 100% (the panel's own trailing edge)
     rather than --sidebar-w, because the drawer is min(80vw,280px) wide.
     50vh, not 50%, centres it on the viewport -- same reason as desktop. */
  .app-sidebar::before {
    display: block;
    position: absolute;
    inset: 0;
    width: auto;
    border-radius: 0 18px 18px 0;
    /* -strong (0.95), not -surface (0.84): on desktop the glass sits over
       wallpaper, but a drawer sits over text, which reads through at 0.84. */
    background: var(--theme-surface-strong);
    -webkit-mask-image: radial-gradient(circle var(--arc-r) at
      calc(100% - var(--arc-depth) - var(--arc-inset) + var(--arc-r)) 50vh,
      transparent 99.8%, #000 99.9%);
    mask-image: radial-gradient(circle var(--arc-r) at
      calc(100% - var(--arc-depth) - var(--arc-inset) + var(--arc-r)) 50vh,
      transparent 99.8%, #000 99.9%);
  }

  /* Mirrored drawer: the arc cuts the left edge, so the circle sits on that side. */
  [dir="rtl"] .app-sidebar::before {
    border-radius: 18px 0 0 18px;
    -webkit-mask-image: radial-gradient(circle var(--arc-r) at
      calc(var(--arc-depth) + var(--arc-inset) - var(--arc-r)) 50vh,
      transparent 99.8%, #000 99.9%);
    mask-image: radial-gradient(circle var(--arc-r) at
      calc(var(--arc-depth) + var(--arc-inset) - var(--arc-r)) 50vh,
      transparent 99.8%, #000 99.9%);
  }
  .app-sidebar.open {
    transform: translateX(0) !important;
  }
  .drawer-backdrop.show {
    display: block !important;
    opacity: 1 !important;
  }
  .app-main {
    padding: 12px 14px 28px 14px !important;
  }
  .grid-2col {
    grid-template-columns: 1fr !important;
  }
  .grid-3col {
    grid-template-columns: 1fr !important;
  }
  .header-right {
    width: 100%;
    justify-content: flex-start;
  }
  /* Touch targets: the theme select was an 18px-tall strip and the dice a
     24px circle, both well under a finger. */
  .theme-pill-control { padding: 5px 12px; }
  .theme-pill-control select { min-height: 34px; font-size: 13.5px; }
  .theme-dice-btn { width: 34px; height: 34px; font-size: 15px; }
}

@media (max-width: 480px) {
  .setting-row {
    flex-direction: column !important;
    align-items: flex-start !important;
  }
  .setting-control-col {
    width: 100%;
    justify-content: flex-start;
    margin-top: 6px;
  }
  .copy-wrapper {
    flex-direction: column !important;
    align-items: stretch !important;
  }
  .copy-actions {
    width: 100%;
    margin-top: 6px;
  }
  .copy-actions button, .copy-actions a {
    flex: 1;
    justify-content: center;
  }
}

/* RTL Support */
[dir="rtl"] {
  direction: rtl;
  text-align: right;
}

/* No [dir="rtl"] .app-sidebar margin/radius rule here: it survived from the
   old floating-card sidebar and was never scoped to a breakpoint. On desktop
   it shifted the nav 16px off the flush ::before glass panel and pushed the
   sidebar 16px past the bottom of the viewport; on mobile it did the same to
   the drawer. The sidebar is flush in both directions now, and the drawer's
   inner radius is set in the mobile block below. */

@media (max-width: 860px) {
  [dir="rtl"] .app-sidebar {
    left: auto !important;
    right: 0 !important;
    border-radius: 18px 0 0 18px !important;
    transform: translateX(100%) !important;
  }
  [dir="rtl"] .app-sidebar.open {
    transform: translateX(0) !important;
  }
}

[dir="rtl"] .nav-btn:hover {
  transform: translateX(-2px) !important;
}

[dir="rtl"] .toast-msg {
  right: auto !important;
  left: 20px !important;
}

/* ===================================================================
   Polish pass \u2014 refinements to the existing layout. No structural
   changes; every value is a theme token so all ten themes still work.
   =================================================================== */

/* Card headings get a tinted icon tile, so every tab reads as one system. */
.card-title > span:first-child {
  width: 30px;
  height: 30px;
  border-radius: 9px;
  display: inline-grid;
  place-items: center;
  background: rgba(var(--theme-primary-rgb), 0.12);
  border: 1px solid rgba(var(--theme-primary-rgb), 0.16);
  font-size: 15px;
  line-height: 1;
  flex-shrink: 0;
}

/* Softer corners and a lighter, better-layered shadow. */
.card {
  border-radius: 18px;
  box-shadow: 0 8px 26px -8px var(--theme-shadow), 0 1px 3px rgba(0,0,0,0.03);
}
.card:hover { transform: translateY(-1px); }
.card-primary { border-radius: 20px; }

/* The four read-only info boxes on the overview. */
.card-primary .form-label { letter-spacing: 0.01em; }

/* Action tiles: give the icon the same tile treatment and a calmer hover. */
.action-tile-icon {
  border: 1px solid rgba(var(--theme-primary-rgb), 0.16);
  border-radius: 10px;
}
.action-tile:hover { box-shadow: 0 8px 20px -6px var(--theme-glow); }

/* Tables: readable rows with a hover cue. */
table tbody tr { transition: background 0.15s ease; }
table tbody tr:hover { background: rgba(var(--theme-primary-rgb), 0.05); }
table thead th {
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 700;
}

/* Inputs: clearer focus ring. */
.form-control:focus {
  outline: none;
  border-color: var(--theme-primary);
  box-shadow: 0 0 0 3px rgba(var(--theme-primary-rgb), 0.16);
}

/* Keyboard focus must stay visible for everything interactive. */
a:focus-visible,
button:focus-visible,
select:focus-visible,
input:focus-visible,
textarea:focus-visible,
.action-tile:focus-visible,
.nav-btn:focus-visible {
  outline: 2px solid var(--theme-primary);
  outline-offset: 2px;
  border-radius: 8px;
}

/* Badges: slightly tighter, more legible. */
.badge {
  letter-spacing: 0.01em;
  border-radius: 999px;
}

/* Scrollbars that match the theme instead of the OS default. */
* { scrollbar-width: thin; scrollbar-color: var(--theme-border-hover) transparent; }
*::-webkit-scrollbar { width: 9px; height: 9px; }
*::-webkit-scrollbar-track { background: transparent; }
*::-webkit-scrollbar-thumb {
  background: var(--theme-border-hover);
  border-radius: 999px;
  border: 2px solid transparent;
  background-clip: content-box;
}
*::-webkit-scrollbar-thumb:hover { background-color: var(--theme-primary); }

/* Respect users who ask for less motion. */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
  .card:hover, .action-tile:hover { transform: none; }
}

/* ===================================================================
   Content-area styling to match the sidebar: tiles instead of bare
   glyphs, quieter field labels, softer controls.
   =================================================================== */

/* Action tiles read as cards, with the same icon-tile treatment as the nav. */
.action-tile {
  border-radius: 16px;
  padding: 13px 14px;
  gap: 12px;
}
.action-tile-icon {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  font-size: 19px;
  background: rgba(var(--theme-primary-rgb), 0.12);
  border: 1px solid rgba(var(--theme-primary-rgb), 0.18);
}
.action-tile:hover .action-tile-icon {
  background: rgba(var(--theme-primary-rgb), 0.20);
  border-color: rgba(var(--theme-primary-rgb), 0.34);
}

/* Field labels sit back so the values lead, as in the reference. */
.form-label {
  font-size: 11.5px;
  font-weight: 700;
  letter-spacing: 0.02em;
  color: var(--theme-text-secondary);
  margin-bottom: 6px;
}

/* Controls share the card corner radius rather than being noticeably squarer. */
.btn {
  border-radius: 12px;
  height: 40px;
}
.btn-sm { border-radius: 10px; }
.form-control { border-radius: 12px; }

/* Card heading: tile, title, and a badge pushed to the trailing edge. */
.card-title {
  font-size: 14.5px;
  gap: 10px;
  margin-bottom: 6px;
}
.card-desc { font-size: 12.5px; }

/* A card's own section divider, for the longer settings tabs. */
.card-divider {
  height: 1px;
  background: var(--theme-border);
  margin: 16px -20px;
}

/* Read-only value boxes on the overview. */
.card-primary code,
.code-input {
  letter-spacing: 0.01em;
}

@media (max-width: 1024px) {
  .quick-action-grid { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
}
/* ===== HEX PANEL — theme-aware glass (wallpapers stay visible) ===== */
html { background: var(--theme-bg-fallback); }
body { min-height: 100vh; }
.card {
  background: var(--theme-surface) !important;
  backdrop-filter: blur(16px) saturate(160%) !important;
  border: 1px solid var(--theme-border) !important;
  box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 24px var(--theme-glow), inset 0 1px 0 rgba(255,255,255,0.06) !important;
}
.card::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--theme-accent), var(--theme-primary), transparent);
  opacity: 0.6;
}
.btn-primary {
  background: var(--theme-btn-primary-bg) !important;
  color: var(--theme-btn-primary-text) !important;
  border: none !important;
  box-shadow: 0 4px 16px var(--theme-glow) !important;
  font-weight: 700 !important;
  letter-spacing: 0.5px !important;
}
.btn-primary:hover {
  background: var(--theme-btn-primary-hover) !important;
  transform: translateY(-1px);
}
.badge-sky {
  background: var(--theme-primary-soft) !important;
  border: 1px solid var(--theme-border-hover) !important;
  color: var(--theme-primary) !important;
}

/* ==========================================================================
   HEX NEO-GLASS REDESIGN (applies to every theme via --theme-* tokens)
   ========================================================================== */

:root {
  --neo-radius: 22px;
  --neo-glass: linear-gradient(145deg, rgba(255,255,255,0.10) 0%, rgba(255,255,255,0.03) 45%, rgba(255,255,255,0.06) 100%);
  --neo-edge: linear-gradient(135deg, rgba(var(--theme-primary-rgb),0.65), rgba(255,255,255,0.10) 40%, rgba(var(--theme-primary-rgb),0.05) 60%, rgba(var(--theme-primary-rgb),0.45));
  --neo-blur: blur(22px) saturate(180%);
}

body { font-family: 'Nunito', 'Vazirmatn', system-ui, sans-serif; letter-spacing: 0.1px; }
[dir="rtl"] body, [dir="rtl"] h1, [dir="rtl"] h2, [dir="rtl"] h3, [dir="rtl"] h4 { font-family: 'Vazirmatn', 'Nunito', sans-serif; }

/* Animated aurora layer on top of each theme wallpaper */
body::after {
  content: "";
  position: fixed;
  inset: -20%;
  z-index: 0;
  pointer-events: none;
  background:
    radial-gradient(38% 32% at 18% 22%, rgba(var(--theme-primary-rgb), 0.28), transparent 70%),
    radial-gradient(30% 28% at 82% 18%, var(--theme-glow), transparent 70%),
    radial-gradient(36% 34% at 70% 85%, rgba(var(--theme-primary-rgb), 0.18), transparent 70%),
    radial-gradient(26% 24% at 25% 80%, var(--theme-glow), transparent 70%);
  filter: blur(30px);
  animation: neoAurora 26s ease-in-out infinite alternate;
  mix-blend-mode: screen;
  opacity: 0.85;
}
@keyframes neoAurora {
  0%   { transform: translate3d(0,0,0) rotate(0deg) scale(1); }
  50%  { transform: translate3d(3%,-2%,0) rotate(6deg) scale(1.08); }
  100% { transform: translate3d(-3%,3%,0) rotate(-5deg) scale(1.02); }
}
body::before {
  background:
    linear-gradient(180deg, rgba(0,0,0,0.10), rgba(0,0,0,0.35)),
    var(--theme-bg-overlay) !important;
}
@media (prefers-reduced-motion: reduce) { body::after { animation: none; } }

/* ---------------- Floating glass sidebar ---------------- */
.app-layout { --sidebar-w: 292px; }
.app-sidebar {
  padding-block: 30px 26px !important;
  padding-inline: 28px 28px !important;
}
.app-sidebar::before {
  top: 14px !important;
  bottom: 14px !important;
  inset-inline-start: 14px !important;
  width: calc(var(--sidebar-w) - 28px) !important;
  border-radius: 28px !important;
  background: var(--neo-glass), rgba(var(--theme-primary-rgb), 0.04) !important;
  backdrop-filter: var(--neo-blur) !important;
  -webkit-backdrop-filter: var(--neo-blur) !important;
  -webkit-mask-image: none !important;
  mask-image: none !important;
  border: 1px solid rgba(255,255,255,0.14);
  box-shadow:
    0 30px 60px -20px rgba(0,0,0,0.65),
    0 0 0 1px rgba(var(--theme-primary-rgb), 0.10),
    inset 0 1px 0 rgba(255,255,255,0.22),
    inset 0 -1px 0 rgba(255,255,255,0.04),
    0 0 40px -10px var(--theme-glow);
}
/* glossy highlight sweep across the sidebar glass */
.app-sidebar::after {
  content: "";
  position: fixed;
  top: 14px;
  inset-inline-start: 14px;
  width: calc(var(--sidebar-w) - 28px);
  height: 42%;
  border-radius: 28px 28px 60% 60% / 28px 28px 22% 22%;
  background: linear-gradient(180deg, rgba(255,255,255,0.10), rgba(255,255,255,0) 75%);
  pointer-events: none;
  z-index: -1;
}

.sidebar-brand {
  border-bottom: 1px solid rgba(255,255,255,0.08) !important;
  padding: 4px 4px 18px !important;
  margin-bottom: 16px !important;
}
.brand-mark {
  filter: drop-shadow(0 0 14px var(--theme-glow));
  animation: neoFloat 6s ease-in-out infinite;
}
@keyframes neoFloat { 50% { transform: translateY(-3px) rotate(-3deg); } }
.brand-title {
  font-size: 20px !important;
  letter-spacing: 3px;
  background: linear-gradient(90deg, var(--theme-text-primary), var(--theme-primary), var(--theme-accent));
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}
.brand-tagline { opacity: 0.75; letter-spacing: 0.6px; }

.nav-section {
  font-size: 10px !important;
  letter-spacing: 1.6px !important;
  text-transform: uppercase;
  color: var(--theme-text-muted) !important;
  opacity: 0.75;
  margin: 14px 8px 6px !important;
  display: flex; align-items: center; gap: 8px;
}
.nav-section::after {
  content: ""; flex: 1; height: 1px;
  background: linear-gradient(90deg, rgba(255,255,255,0.14), transparent);
}
[dir="rtl"] .nav-section::after { background: linear-gradient(270deg, rgba(255,255,255,0.14), transparent); }

.nav-btn {
  height: 48px !important;
  border-radius: 16px !important;
  padding: 0 8px !important;
  gap: 12px !important;
  color: var(--theme-text-secondary) !important;
  transition: background .25s ease, color .25s ease, border-color .25s ease, box-shadow .25s ease, transform .25s ease !important;
}
/* glass icon chips */
.nav-btn .nav-icon, .nav-icon {
  width: 34px !important;
  height: 34px !important;
  border-radius: 12px !important;
  font-size: 16px !important;
  background: linear-gradient(145deg, rgba(255,255,255,0.18), rgba(255,255,255,0.04)) !important;
  border: 1px solid rgba(255,255,255,0.18) !important;
  backdrop-filter: blur(10px) saturate(160%);
  -webkit-backdrop-filter: blur(10px) saturate(160%);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.30), 0 6px 14px -6px rgba(0,0,0,0.6) !important;
  transition: transform .3s cubic-bezier(.34,1.56,.64,1), box-shadow .25s ease, background .25s ease !important;
}
.nav-btn:hover {
  background: linear-gradient(90deg, rgba(255,255,255,0.09), rgba(255,255,255,0.02)) !important;
  border-color: rgba(255,255,255,0.10) !important;
  color: var(--theme-text-primary) !important;
}
.nav-btn:hover .nav-icon {
  transform: translateY(-1px) scale(1.08) rotate(-4deg);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.35), 0 0 18px -2px var(--theme-glow) !important;
}
.nav-btn.active {
  background: linear-gradient(100deg, rgba(var(--theme-primary-rgb),0.26), rgba(var(--theme-primary-rgb),0.06) 70%, transparent) !important;
  border-color: rgba(var(--theme-primary-rgb),0.35) !important;
  color: var(--theme-text-primary) !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.12), 0 10px 26px -12px var(--theme-glow) !important;
}
[dir="rtl"] .nav-btn.active { background: linear-gradient(260deg, rgba(var(--theme-primary-rgb),0.26), rgba(var(--theme-primary-rgb),0.06) 70%, transparent) !important; }
.nav-btn.active .nav-icon {
  background: linear-gradient(145deg, rgba(var(--theme-primary-rgb),0.95), rgba(var(--theme-primary-rgb),0.45)) !important;
  border-color: rgba(255,255,255,0.35) !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.5), 0 0 22px var(--theme-glow) !important;
}
.nav-btn.active::before {
  inset-inline-start: -8px !important;
  width: 4px !important;
  height: 26px !important;
  border-radius: 4px !important;
  background: linear-gradient(180deg, var(--theme-accent), var(--theme-primary)) !important;
  box-shadow: 0 0 12px var(--theme-primary);
}
.nav-tag {
  background: rgba(255,255,255,0.08) !important;
  border-color: rgba(255,255,255,0.16) !important;
  backdrop-filter: blur(6px);
}
.sidebar-footer { border-top: 1px solid rgba(255,255,255,0.08) !important; }
.sidebar-status-pill {
  background: linear-gradient(145deg, rgba(255,255,255,0.10), rgba(255,255,255,0.03)) !important;
  border: 1px solid rgba(255,255,255,0.14) !important;
  border-radius: 18px !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.15);
}
.sidebar-status-dot { animation: neoPulse 2s ease-in-out infinite; }
@keyframes neoPulse {
  0%,100% { box-shadow: 0 0 0 0 rgba(var(--theme-primary-rgb),0.6), 0 0 8px var(--theme-primary); }
  50%     { box-shadow: 0 0 0 6px rgba(var(--theme-primary-rgb),0), 0 0 14px var(--theme-primary); }
}

/* Users panel: Persian labels and controls stay readable in every theme. */
#tab-users, #tab-users * { font-family: 'Vazirmatn', 'Nunito', system-ui, sans-serif; }
#tab-users table { direction: rtl; text-align: right !important; }
#tab-users input, #tab-users select, #tab-users button { direction: rtl; }
#tab-users .code-input { direction: ltr; text-align: left; }

/* ---------------- Header ---------------- */
.app-main { padding: 26px 32px 44px 18px !important; }
[dir="rtl"] .app-main { padding: 26px 18px 44px 32px !important; }
.app-header {
  position: sticky;
  top: 14px;
  z-index: 50;
  background: var(--neo-glass), rgba(0,0,0,0.12) !important;
  backdrop-filter: var(--neo-blur) !important;
  -webkit-backdrop-filter: var(--neo-blur) !important;
  border: 1px solid rgba(255,255,255,0.12) !important;
  border-radius: var(--neo-radius) !important;
  padding: 12px 16px !important;
  margin-bottom: 20px !important;
  box-shadow: 0 18px 40px -22px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.14) !important;
}
.header-icon-box {
  background: linear-gradient(145deg, rgba(var(--theme-primary-rgb),0.85), rgba(var(--theme-primary-rgb),0.35)) !important;
  border: 1px solid rgba(255,255,255,0.3) !important;
  border-radius: 14px !important;
  box-shadow: 0 0 24px var(--theme-glow), inset 0 1px 0 rgba(255,255,255,0.4) !important;
}
#page-heading {
  background: linear-gradient(90deg, var(--theme-text-primary), var(--theme-primary));
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
.theme-pill-control {
  background: rgba(255,255,255,0.07) !important;
  border: 1px solid rgba(255,255,255,0.14) !important;
  border-radius: 999px !important;
  backdrop-filter: blur(10px);
}

/* ---------------- Cards ---------------- */
.card {
  position: relative;
  border-radius: var(--neo-radius) !important;
  background: var(--neo-glass), var(--theme-surface) !important;
  backdrop-filter: var(--neo-blur) !important;
  -webkit-backdrop-filter: var(--neo-blur) !important;
  border: 1px solid rgba(255,255,255,0.10) !important;
  box-shadow: 0 24px 50px -28px rgba(0,0,0,0.8), inset 0 1px 0 rgba(255,255,255,0.10) !important;
  transition: transform .35s cubic-bezier(.2,.8,.2,1), box-shadow .35s ease, border-color .35s ease !important;
  overflow: hidden;
}
.card::before {
  height: 100% !important;
  inset: 0 !important;
  padding: 1px;
  border-radius: inherit;
  background: var(--neo-edge) !important;
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  opacity: 0.55 !important;
  pointer-events: none;
}
.card:hover {
  transform: translateY(-3px);
  border-color: rgba(var(--theme-primary-rgb),0.30) !important;
  box-shadow: 0 30px 60px -28px rgba(0,0,0,0.85), 0 0 34px -8px var(--theme-glow), inset 0 1px 0 rgba(255,255,255,0.14) !important;
}
.card:hover::before { opacity: 1 !important; }
.card-primary {
  background:
    radial-gradient(120% 140% at 0% 0%, rgba(var(--theme-primary-rgb),0.22), transparent 55%),
    var(--neo-glass), var(--theme-surface) !important;
}
.card-title { font-size: 15.5px !important; letter-spacing: .2px; }
.card-title > span:first-child {
  display: inline-grid; place-items: center;
  width: 32px; height: 32px; border-radius: 11px;
  background: linear-gradient(145deg, rgba(255,255,255,0.16), rgba(255,255,255,0.03));
  border: 1px solid rgba(255,255,255,0.16);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.25);
}

/* Quick action tiles */
.action-tile {
  border-radius: 20px !important;
  background: var(--neo-glass), rgba(var(--theme-primary-rgb),0.04) !important;
  backdrop-filter: var(--neo-blur);
  -webkit-backdrop-filter: var(--neo-blur);
  border: 1px solid rgba(255,255,255,0.10) !important;
  transition: transform .35s cubic-bezier(.34,1.56,.64,1), box-shadow .3s ease, border-color .3s ease !important;
  position: relative; overflow: hidden;
}
.action-tile::after {
  content: ""; position: absolute; inset: 0;
  background: linear-gradient(115deg, transparent 30%, rgba(255,255,255,0.14) 50%, transparent 70%);
  transform: translateX(-120%);
  transition: transform .8s ease;
  pointer-events: none;
}
.action-tile:hover { transform: translateY(-4px) scale(1.015); border-color: rgba(var(--theme-primary-rgb),0.4) !important; box-shadow: 0 18px 36px -18px var(--theme-glow) !important; }
.action-tile:hover::after { transform: translateX(120%); }
.action-tile-icon {
  border-radius: 14px !important;
  background: linear-gradient(145deg, rgba(var(--theme-primary-rgb),0.40), rgba(var(--theme-primary-rgb),0.08)) !important;
  border: 1px solid rgba(255,255,255,0.2) !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.3), 0 0 18px -6px var(--theme-glow);
}

/* ---------------- Controls ---------------- */
.btn { border-radius: 14px !important; transition: transform .2s ease, box-shadow .25s ease, background .25s ease !important; }
.btn-primary { position: relative; overflow: hidden; }
.btn-primary::after {
  content: ""; position: absolute; top: 0; bottom: 0; width: 40%; left: -60%;
  background: linear-gradient(100deg, transparent, rgba(255,255,255,0.45), transparent);
  transform: skewX(-20deg);
  animation: neoShine 4.5s ease-in-out infinite;
}
@keyframes neoShine { 0%, 60% { left: -60%; } 100% { left: 130%; } }
.btn-primary:hover { box-shadow: 0 10px 28px -8px var(--theme-glow), 0 0 0 1px rgba(255,255,255,0.2) inset !important; }
.btn-secondary {
  background: linear-gradient(145deg, rgba(255,255,255,0.12), rgba(255,255,255,0.03)) !important;
  border: 1px solid rgba(255,255,255,0.16) !important;
  backdrop-filter: blur(10px);
}
.btn-secondary:hover { border-color: rgba(var(--theme-primary-rgb),0.45) !important; transform: translateY(-1px); }
.form-control {
  background: rgba(0,0,0,0.28) !important;
  border: 1px solid rgba(255,255,255,0.12) !important;
  border-radius: 14px !important;
  box-shadow: inset 0 2px 6px rgba(0,0,0,0.25);
  transition: border-color .2s ease, box-shadow .2s ease !important;
}
.form-control:focus {
  border-color: rgba(var(--theme-primary-rgb),0.7) !important;
  box-shadow: 0 0 0 4px rgba(var(--theme-primary-rgb),0.15), inset 0 2px 6px rgba(0,0,0,0.25) !important;
  outline: none;
}
.badge {
  backdrop-filter: blur(8px);
  border-radius: 999px !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.12);
}

/* Tables */
table tbody tr { transition: background .2s ease; }
table tbody tr:hover { background: rgba(var(--theme-primary-rgb),0.07); }
table thead tr { text-transform: uppercase; font-size: 11px; letter-spacing: 1px; }

/* Tab transitions */
.tab-pane.active { animation: neoRise .45s cubic-bezier(.2,.8,.2,1); }
@keyframes neoRise { from { opacity: 0; transform: translateY(10px); filter: blur(4px); } to { opacity: 1; transform: none; filter: none; } }

/* Scrollbars */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: rgba(var(--theme-primary-rgb),0.35); border-radius: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::selection { background: rgba(var(--theme-primary-rgb),0.35); }

/* Modal / toast glass */
.modal-card, .toast-msg {
  background: var(--neo-glass), var(--theme-surface-strong) !important;
  backdrop-filter: var(--neo-blur) !important;
  -webkit-backdrop-filter: var(--neo-blur) !important;
  border: 1px solid rgba(255,255,255,0.14) !important;
  border-radius: 22px !important;
}

/* ---------------- Mobile drawer ---------------- */
@media (max-width: 860px) {
  .app-sidebar { padding-inline: 22px 22px !important; }
  .app-sidebar::before {
    position: absolute !important;
    top: 10px !important; bottom: 10px !important;
    inset-inline-start: 10px !important;
    width: calc(100% - 20px) !important;
    border-radius: 24px !important;
    background: var(--neo-glass), var(--theme-surface-strong) !important;
  }
  .app-sidebar::after {
    position: absolute;
    top: 10px; inset-inline-start: 10px;
    width: calc(100% - 20px);
  }
  .app-main, [dir="rtl"] .app-main { padding: 12px 14px 28px !important; }
  .app-header { top: 8px; }
  .card:hover, .action-tile:hover { transform: none; }
}

`;
    __name(renderPageLayout, "renderPageLayout");
    __name2(renderPageLayout, "renderPageLayout");
    __name(renderLoginPage, "renderLoginPage");
    __name2(renderLoginPage, "renderLoginPage");
    __name(renderSetupPage, "renderSetupPage");
    __name2(renderSetupPage, "renderSetupPage");
    __name(handleSetup, "handleSetup");
    __name2(handleSetup, "handleSetup");
    __name(handleLogin, "handleLogin");
    __name2(handleLogin, "handleLogin");
    __name(handleLogout, "handleLogout");
    __name2(handleLogout, "handleLogout");
    __name(renderDashboardPage, "renderDashboardPage");
    __name2(renderDashboardPage, "renderDashboardPage");
    P = (1n << 255n) - 19n;
    A24 = 121665n;
    __name(x25519, "x25519");
    __name2(x25519, "x25519");
    __name(bytesToBase64, "bytesToBase64");
    __name2(bytesToBase64, "bytesToBase64");
    __name(generateWireGuardKeyPair, "generateWireGuardKeyPair");
    __name2(generateWireGuardKeyPair, "generateWireGuardKeyPair");
    __name(parseReservedBytes, "parseReservedBytes");
    __name2(parseReservedBytes, "parseReservedBytes");
    __name(registerWarpAccount, "registerWarpAccount");
    __name2(registerWarpAccount, "registerWarpAccount");
    __name(generateRandomToken2, "generateRandomToken2");
    __name2(generateRandomToken2, "generateRandomToken");
    __name(handlePanel, "handlePanel");
    __name2(handlePanel, "handlePanel");
    __name(authorizeSubscription, "authorizeSubscription");
    __name2(authorizeSubscription, "authorizeSubscription");
    __name(buildClashChainProxy, "buildClashChainProxy");
    __name2(buildClashChainProxy, "buildClashChainProxy");
    __name(buildSingboxChainOutbound, "buildSingboxChainOutbound");
    __name2(buildSingboxChainOutbound, "buildSingboxChainOutbound");
    __name(generateOpenVpnProfile, "generateOpenVpnProfile");
    __name2(generateOpenVpnProfile, "generateOpenVpnProfile");
    __name(handleXhttpProxy, "handleXhttpProxy");
    __name2(handleXhttpProxy, "handleXhttpProxy");
    __name(handleSubscription, "handleSubscription");
    __name2(handleSubscription, "handleSubscription");
    connectImpl = null;
    __name(getConnect, "getConnect");
    __name2(getConnect, "getConnect");
    __name(bytesToUuid, "bytesToUuid");
    __name2(bytesToUuid, "bytesToUuid");
    __name(parseVlessHeader, "parseVlessHeader");
    __name2(parseVlessHeader, "parseVlessHeader");
    __name(createVlessResponseHeader, "createVlessResponseHeader");
    __name2(createVlessResponseHeader, "createVlessResponseHeader");
    __name(sha224Hex, "sha224Hex");
    __name2(sha224Hex, "sha224Hex");
    __name(isTrojanPacket, "isTrojanPacket");
    __name2(isTrojanPacket, "isTrojanPacket");
    __name(parseTrojanHeader, "parseTrojanHeader");
    __name2(parseTrojanHeader, "parseTrojanHeader");
    __name(toUint8Array, "toUint8Array");
    __name2(toUint8Array, "toUint8Array");
    __name(decodeBase64Url, "decodeBase64Url");
    __name2(decodeBase64Url, "decodeBase64Url");
    __name(extractEarlyData, "extractEarlyData");
    __name2(extractEarlyData, "extractEarlyData");
    __name(handleWebSocketProxy, "handleWebSocketProxy");
    __name2(handleWebSocketProxy, "handleWebSocketProxy");
    __name(dialHttpChain, "dialHttpChain");
    __name2(dialHttpChain, "dialHttpChain");
    __name(dialSocks5Chain, "dialSocks5Chain");
    __name2(dialSocks5Chain, "dialSocks5Chain");
    __name(establishOutboundSocket, "establishOutboundSocket");
    __name2(establishOutboundSocket, "establishOutboundSocket");
    __name(handleProxySession, "handleProxySession");
    __name2(handleProxySession, "handleProxySession");
    __name(pipeRemoteToWebSocket, "pipeRemoteToWebSocket");
    __name2(pipeRemoteToWebSocket, "pipeRemoteToWebSocket");
    __name(handleDnsQuery, "handleDnsQuery");
    __name2(handleDnsQuery, "handleDnsQuery");
    __name(handleDnsJson, "handleDnsJson");
    __name2(handleDnsJson, "handleDnsJson");
    __name(authorizeShareRequest, "authorizeShareRequest");
    __name2(authorizeShareRequest, "authorizeShareRequest");
    __name(handleNodeExport, "handleNodeExport");
    __name2(handleNodeExport, "handleNodeExport");
    __name(handleNodeImport, "handleNodeImport");
    __name2(handleNodeImport, "handleNodeImport");
    THEME_BG_DATA_URIS = {
  "theme-bg-1.jpg": "data:image/jpeg;base64,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",
  "theme-bg-2.jpg": "data:image/jpeg;base64,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",
  "theme-bg-3.jpg": "data:image/jpeg;base64,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",
  "theme-bg-4.jpg": "data:image/jpeg;base64,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",
  "theme-bg-5.jpg": "data:image/jpeg;base64,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"
};
    src_default = {
      async fetch(request, env2, ctx) {
        try {
          return withSecurityHeaders(await handleFetch(request, env2, ctx));
        } catch (fatal) {
          console.error("HEX top-level exception:", fatal);
          return new Response(JSON.stringify({ error: "Internal Server Error", message: String(fatal && fatal.message || fatal || "unexpected error") }), {
            status: 500,
            headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
          });
        }
      }
    };
    async function handleFetch(request, env2, ctx) {
      const url = new URL(request.url);
      const pathname = url.pathname.replace(/\/+$/, "") || "/";
      const upgrade = request.headers.get("Upgrade");
      try {
        const settings = await getOrInitSettings(env2);
        const configuredPath = settings.proxyPath.replace(/\/+$/, "") || "/wd-ws";
        const xhttpConfiguredPath = (settings.xhttpPath || "/bk-xhttp").replace(/\/+$/, "") || "/bk-xhttp";
        if (env2.DISABLE_PROXY === "true" && (upgrade || pathname === configuredPath || pathname === xhttpConfiguredPath || ["/hex-ws", "/wd-ws", "/bk-xhttp", "/wd-xhttp"].includes(pathname))) return Response.json({ error: "This adapter supports the panel, DNS and subscriptions only; use a tunnel host for proxy traffic." }, { status: 501 });
        if (request.method === "POST" && (pathname === xhttpConfiguredPath || pathname === "/bk-xhttp" || pathname === "/wd-xhttp")) {
          if (!settings.xhttpEnabled) return new Response("HTTP streaming disabled", { status: 404 });
          return await handleXhttpProxy(request, env2, ctx);
        }
        if (upgrade && (upgrade.toLowerCase() === "websocket" || upgrade.toLowerCase() === "httpupgrade" || upgrade.toLowerCase() === "tcp")) {
          const isMatchedWs = pathname === configuredPath || pathname === `${configuredPath}/vless` || pathname === `${configuredPath}/trojan` || pathname === `${configuredPath}/ss` || pathname === "/hex-ws" || pathname === "/wd-ws" || pathname === "/wd-ws/vless" || pathname === "/wd-ws/trojan" || pathname === "/hex-ws" || pathname === "/hex-ws/vless" || pathname === "/hex-ws/trojan" || pathname === "/bk-upgrade" || pathname === "/wd-upgrade" || pathname === xhttpConfiguredPath;
          if (isMatchedWs) {
            return await handleWebSocketProxy(request, env2, ctx);
          } else {
            return new Response(
              JSON.stringify(
                {
                  error: "Invalid WebSocket Path",
                  message: `WebSocket connection requested on path '${pathname}', but HEX proxy is configured on '${configuredPath}'.`,
                  configuredPath
                },
                null,
                2
              ),
              {
                status: 404,
                headers: { "Content-Type": "application/json; charset=utf-8" }
              }
            );
          }
        }
        if (pathname === "/dns-query") {
          return await handleDnsQuery(request, env2);
        }
        if (pathname === "/dns-json") {
          return await handleDnsJson(request, env2);
        }
        if (pathname === "/api/node/export") {
          return await handleNodeExport(request, env2);
        }
        if (pathname === "/api/node/import" && request.method === "POST") {
          return await handleNodeImport(request, env2);
        }
        const themeMatch = pathname.match(/^\/(?:assets\/)?theme-bg(?:-([1-9]|10))?\.jpg$/);
        if (pathname.startsWith("/assets/")) {
          const embedded = THEME_BG_DATA_URIS[pathname.slice("/assets/".length)];
          if (embedded) {
            const comma = embedded.indexOf(",");
            const meta = embedded.slice(5, comma);
            const bytes = decodeBase64(embedded.slice(comma + 1));
            return new Response(bytes, {
              headers: {
                "Content-Type": meta.replace(";base64", "") || "image/jpeg",
                "Cache-Control": "public, max-age=31536000, immutable"
              }
            });
          }
          if (env2.ASSETS) {
            return env2.ASSETS.fetch(request);
          }
          return new Response("Asset not found", { status: 404 });
        }
        if (pathname === "/") {
          return Response.redirect(`${url.origin}/panel/login`, 302);
        }
        if (pathname === "/api/health") {
          return handleHealth(request, env2);
        }
        if (pathname === "/api/proxy-debug") {
          return await handleProxyDebug(request, env2);
        }
        if (pathname === "/panel/setup") {
          return await handleSetup(request, env2);
        }
        if (pathname === "/panel/login") {
          return await handleLogin(request, env2);
        }
        if (pathname === "/panel/logout") {
          return handleLogout(request);
        }
        if (pathname === "/panel" || pathname.startsWith("/panel/settings")) {
          return await handlePanel(request, env2);
        }
        if (pathname.startsWith("/sub/")) {
          return await handleSubscription(pathname, request, env2);
        }
        return new Response(
          JSON.stringify(
            {
              error: "Not Found",
              message: "The requested HEX endpoint does not exist.",
              path: pathname
            },
            null,
            2
          ),
          {
            status: 404,
            headers: { "Content-Type": "application/json; charset=utf-8" }
          }
        );
      } catch (err) {
        console.error("HEX Worker Exception:", err);
        return new Response(
          JSON.stringify(
            {
              error: "Internal Server Error",
              message: err && err.message || "An unexpected error occurred in HEX Worker."
            },
            null,
            2
          ),
          {
            status: 500,
            headers: { "Content-Type": "application/json; charset=utf-8" }
          }
        );
      }
    }
  }
});
async function onRequest(context2) {
  const { request, env: env2, waitUntil } = context2;
  return await src_default.fetch(request, env2, { waitUntil: waitUntil.bind(context2) });
}
var init_path = __esm({
  "[[path]].js"() {
    init_functionsRoutes_0_6698010974737841();
    init_worker();
    __name(onRequest, "onRequest");
  }
});
var routes;
var init_functionsRoutes_0_6698010974737841 = __esm({
  "../.wrangler/tmp/pages-3cFsSW/functionsRoutes-0.6698010974737841.mjs"() {
    init_path();
    routes = [
      {
        routePath: "/:path*",
        mountPath: "/",
        method: "",
        middlewares: [],
        modules: [onRequest]
      }
    ];
  }
});
init_worker();
export {
  src_default as default,
  getOrInitSettings,
  invalidateSettingsCache
};

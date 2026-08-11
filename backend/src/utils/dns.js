import $ from '@/core/app';
import dnsPacket from 'dns-packet';
import { Buffer } from 'buffer';
import { isIPv4, isIPv6 } from '@/utils';
import { safeLoad } from '@/utils/yaml';

const DNS_DEFAULT_PORT = 53;
const DNS_TLS_DEFAULT_PORT = 853;
const DNS_TCP_LENGTH_BYTES = 2;

function buildDnsQuery({ domain, type = 'A', edns }) {
    const additionals = [];
    if (edns) {
        additionals.push({
            type: 'OPT',
            name: '.',
            udpPayloadSize: 4096,
            flags: 0,
            options: [
                {
                    code: 'CLIENT_SUBNET',
                    ip: edns,
                    sourcePrefixLength: isIPv4(edns) ? 24 : 56,
                    scopePrefixLength: 0,
                },
            ],
        });
    }

    return dnsPacket.encode({
        type: 'query',
        id: 0,
        flags: dnsPacket.RECURSION_DESIRED,
        questions: [
            {
                type,
                name: domain,
            },
        ],
        additionals,
    });
}

function normalizeDnsTimeout(timeout) {
    return timeout || 8000;
}

function normalizeDnsHost(host) {
    return host?.replace(/^\[(.*)\]$/, '$1');
}

function isIP(host) {
    return isIPv4(host) || isIPv6(host);
}

function parseDnsPort(port, defaultPort = DNS_DEFAULT_PORT) {
    if (!port) return defaultPort;
    const parsed = Number(port);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
        throw new Error('自定义 DNS 端口号应为 1-65535 的整数');
    }
    return parsed;
}

function assertNoDnsServerUrlExtraParts(parsed, raw) {
    if (
        parsed.username ||
        parsed.password ||
        (parsed.pathname && parsed.pathname !== '/') ||
        parsed.search ||
        parsed.hash
    ) {
        throw new Error(`自定义 DNS 地址格式无效: ${raw}`);
    }
}

function parseDnsServerUrl(raw, protocol) {
    try {
        const value = protocol
            ? raw
            : `udp://${isIPv6(raw) ? `[${raw}]` : raw}`;
        const parsed = new URL(value);
        assertNoDnsServerUrlExtraParts(parsed, raw);
        const host = normalizeDnsHost(parsed.hostname);
        if (!host) throw new Error(`自定义 DNS 地址格式无效: ${raw}`);
        return {
            protocol: protocol || 'udp',
            host,
            port: parseDnsPort(
                parsed.port,
                protocol === 'tls' ? DNS_TLS_DEFAULT_PORT : DNS_DEFAULT_PORT,
            ),
        };
    } catch (e) {
        if (e?.message?.includes('自定义 DNS')) throw e;
        throw new Error(`自定义 DNS 地址格式无效: ${raw}`);
    }
}

export function parseDnsResolver(url) {
    const raw = `${url || ''}`.trim();
    if (!raw) throw new Error('自定义 DNS 不能为空');
    if (/^https?:\/\//i.test(raw)) {
        return {
            protocol: 'doh',
            url: raw,
        };
    }

    const protocol = raw.match(/^([a-z][a-z\d+.-]*):\/\//i)?.[1];
    const normalizedProtocol = protocol?.toLowerCase();
    if (
        normalizedProtocol &&
        !['udp', 'tcp', 'tls'].includes(normalizedProtocol)
    ) {
        throw new Error(`自定义 DNS 不支持 ${protocol} 协议`);
    }

    return parseDnsServerUrl(raw, normalizedProtocol);
}

export async function doh({
    url,
    domain,
    type = 'A',
    timeout,
    edns,
    skipCertVerify,
}) {
    const buf = buildDnsQuery({
        domain,
        type,
        edns,
    });

    const b64 = Buffer.from(buf).toString('base64');
    const b64url = b64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    const res = await $.http.get({
        url: `${url}?dns=${encodeURIComponent(b64url)}`,
        headers: {
            Accept: 'application/dns-message',
            // 'Content-Type': 'application/dns-message',
        },
        // body: buf,
        'binary-mode': true,
        encoding: null, // 使用 null 编码以确保响应是原始二进制数据
        timeout,
        insecure: skipCertVerify === true,
    });

    return dnsPacket.decode(Buffer.from($.env.isQX ? res.bodyBytes : res.body));
}

async function queryDnsOverUdp({ server, domain, type = 'A', timeout, edns }) {
    const dgram = eval("require('dgram')");
    const buf = buildDnsQuery({
        domain,
        type,
        edns,
    });

    return new Promise((resolve, reject) => {
        let settled = false;
        const socket = dgram.createSocket(isIPv6(server.host) ? 'udp6' : 'udp4');
        const timer = setTimeout(() => {
            finish(new Error('DNS UDP query timeout'));
        }, normalizeDnsTimeout(timeout));

        function cleanup() {
            clearTimeout(timer);
            socket.removeAllListeners();
            try {
                socket.close();
            } catch (e) {
                // Socket may already be closed by the time cleanup runs.
            }
        }

        function finish(error, result) {
            if (settled) return;
            settled = true;
            cleanup();
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        }

        socket.on('error', (error) => finish(error));
        socket.on('message', (message) => {
            try {
                finish(null, dnsPacket.decode(message));
            } catch (e) {
                finish(e);
            }
        });
        socket.send(buf, server.port, server.host, (error) => {
            if (error) finish(error);
        });
    });
}

async function queryDnsOverTcp({
    server,
    domain,
    type = 'A',
    timeout,
    edns,
    skipCertVerify,
}) {
    const transport =
        server.protocol === 'tls'
            ? eval("require('tls')")
            : eval("require('net')");
    const transportName = server.protocol === 'tls' ? 'TLS' : 'TCP';
    const payload = buildDnsQuery({
        domain,
        type,
        edns,
    });
    const length = Buffer.alloc(DNS_TCP_LENGTH_BYTES);
    length.writeUInt16BE(payload.length, 0);
    const request = Buffer.concat([length, payload]);

    return new Promise((resolve, reject) => {
        let settled = false;
        let response = Buffer.alloc(0);
        let responseLength;
        const socket =
            server.protocol === 'tls'
                ? transport.connect({
                      host: server.host,
                      port: server.port,
                      servername: isIP(server.host) ? undefined : server.host,
                      rejectUnauthorized:
                          skipCertVerify === true ? false : undefined,
                  })
                : transport.createConnection({
                      host: server.host,
                      port: server.port,
                  });

        function cleanup() {
            socket.removeAllListeners();
            socket.destroy();
        }

        function finish(error, result) {
            if (settled) return;
            settled = true;
            cleanup();
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        }

        socket.setTimeout(normalizeDnsTimeout(timeout), () => {
            finish(new Error(`DNS ${transportName} query timeout`));
        });
        socket.on(
            server.protocol === 'tls' ? 'secureConnect' : 'connect',
            () => {
                socket.write(request);
            },
        );
        socket.on('error', (error) => finish(error));
        socket.on('end', () => {
            finish(
                new Error(
                    `DNS ${transportName} connection ended before response`,
                ),
            );
        });
        socket.on('data', (chunk) => {
            try {
                response = Buffer.concat([response, chunk]);
                if (
                    responseLength == null &&
                    response.length >= DNS_TCP_LENGTH_BYTES
                ) {
                    responseLength = response.readUInt16BE(0);
                }
                if (
                    responseLength != null &&
                    response.length >= responseLength + DNS_TCP_LENGTH_BYTES
                ) {
                    const message = response.slice(
                        DNS_TCP_LENGTH_BYTES,
                        responseLength + DNS_TCP_LENGTH_BYTES,
                    );
                    finish(null, dnsPacket.decode(message));
                }
            } catch (e) {
                finish(e);
            }
        });
    });
}

export async function resolveDns({
    url,
    domain,
    type = 'A',
    timeout,
    edns,
    skipCertVerify,
}) {
    const raw = `${url || ''}`.trim();
    const protocol = raw.match(/^([a-z][a-z\d+.-]*):\/\//i)?.[1];
    if (
        raw &&
        !$.env.isNode &&
        !/^https?:\/\//i.test(raw) &&
        (!protocol || ['udp', 'tcp', 'tls'].includes(protocol.toLowerCase()))
    ) {
        throw new Error('DoT 和 TCP/UDP DNS 仅支持 Node.js 环境');
    }

    const resolver = parseDnsResolver(url);
    if (resolver.protocol === 'doh') {
        return doh({
            url: resolver.url,
            domain,
            type,
            timeout,
            edns,
            skipCertVerify,
        });
    }

    if (!$.env.isNode) {
        throw new Error('DoT 和 TCP/UDP DNS 仅支持 Node.js 环境');
    }

    if (['tcp', 'tls'].includes(resolver.protocol)) {
        return queryDnsOverTcp({
            server: resolver,
            domain,
            type,
            timeout,
            edns,
            skipCertVerify,
        });
    }

    return queryDnsOverUdp({
        server: resolver,
        domain,
        type,
        timeout,
        edns,
    });
}

function filterSupportedDnsUrls(urls) {
    if (!Array.isArray(urls)) return [];
    const set = new Set();
    urls.forEach((item) => {
        if (!item) return;
        const str = `${item}`.trim();
        if (str && !/^(system|dhcp:|quic:|rcode:)/i.test(str)) {
            set.add(str);
        }
    });
    return Array.from(set);
}

export function extractDnsServersFromRaw(raw, opts = {}) {
    if (!raw || typeof raw !== 'string') return [];
    const { includeFallback = false } = opts;
    const extracted = [];

    const trimmed = raw.trim();

    // 1. Try JSON / sing-box JSON
    if (trimmed.startsWith('{')) {
        try {
            const parsed = JSON.parse(raw);
            if (
                parsed &&
                typeof parsed === 'object' &&
                parsed.dns &&
                Array.isArray(parsed.dns.servers)
            ) {
                parsed.dns.servers.forEach((srv) => {
                    if (typeof srv === 'string') {
                        extracted.push(srv);
                    } else if (srv && typeof srv === 'object' && srv.address) {
                        extracted.push(srv.address);
                    }
                });
                if (extracted.length > 0) {
                    return filterSupportedDnsUrls(extracted);
                }
            }
        } catch (e) {
            // Ignore JSON parse error
        }
    }

    // 2. Try mihomo / Clash / Stash / Egern YAML
    if (/\bdns\s*:/i.test(raw) || /\bnameserver\s*:/i.test(raw)) {
        try {
            const parsed = safeLoad(raw);
            if (
                parsed &&
                typeof parsed === 'object' &&
                parsed.dns &&
                typeof parsed.dns === 'object'
            ) {
                if (Array.isArray(parsed.dns.nameserver)) {
                    extracted.push(...parsed.dns.nameserver);
                }
                if (includeFallback && Array.isArray(parsed.dns.fallback)) {
                    extracted.push(...parsed.dns.fallback);
                }
                if (extracted.length > 0) {
                    return filterSupportedDnsUrls(extracted);
                }
            }
        } catch (e) {
            // Ignore YAML parse error
        }
    }

    // 3. Try QX INI format: [dns] section
    if (/\[\s*dns\s*\]/i.test(raw)) {
        const dnsSectionMatch = raw.match(
            /\[\s*dns\s*\]([\s\S]*?)(?:^\[|$)/im,
        );
        if (dnsSectionMatch && dnsSectionMatch[1]) {
            const lines = dnsSectionMatch[1].split(/\r?\n/);
            for (let line of lines) {
                line = line.trim();
                if (!line || line.startsWith('#') || line.startsWith(';'))
                    continue;
                const eqIndex = line.indexOf('=');
                if (eqIndex !== -1) {
                    const key = line.slice(0, eqIndex).trim().toLowerCase();
                    const val = line.slice(eqIndex + 1).trim();
                    if (key === 'server') {
                        val.split(',').forEach((item) => {
                            const trimmedItem = item.trim();
                            const dnsVal = trimmedItem.split(/\s+/)[0];
                            if (dnsVal) extracted.push(dnsVal);
                        });
                    } else if (key === 'doh-server' || key === 'doq-server') {
                        val.split(',').forEach((item) => {
                            const trimmedItem = item.trim();
                            const dnsVal = trimmedItem.split(/\s+/)[0];
                            if (dnsVal) extracted.push(dnsVal);
                        });
                    }
                }
            }
            if (extracted.length > 0) {
                return filterSupportedDnsUrls(extracted);
            }
        }
    }

    // 4. Try Surge / Loon INI format: [General] section
    if (
        /\[\s*General\s*\]/i.test(raw) ||
        /dns-server\s*=/i.test(raw) ||
        /doh-server\s*=/i.test(raw)
    ) {
        const lines = raw.split(/\r?\n/);
        for (let line of lines) {
            line = line.trim();
            if (!line || line.startsWith('#') || line.startsWith(';'))
                continue;
            const eqIndex = line.indexOf('=');
            if (eqIndex !== -1) {
                const key = line.slice(0, eqIndex).trim().toLowerCase();
                const val = line.slice(eqIndex + 1).trim();
                if (key === 'dns-server' || key === 'doh-server') {
                    val.split(',').forEach((item) => {
                        const trimmedItem = item.trim();
                        const dnsVal = trimmedItem.split(/\s+/)[0];
                        if (dnsVal) extracted.push(dnsVal);
                    });
                }
            }
        }
        if (extracted.length > 0) {
            return filterSupportedDnsUrls(extracted);
        }
    }

    return filterSupportedDnsUrls(extracted);
}

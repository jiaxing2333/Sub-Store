import { expect } from 'chai';
import { describe, it } from 'mocha';
import { extractDnsServersFromRaw } from '../../utils/dns.js';

describe('extractDnsServersFromRaw', () => {
    it('should extract DNS servers from mihomo / Clash YAML format', () => {
        const yaml = `
dns:
  enable: true
  nameserver:
    - https://dns.example.com/dns-query
    - tls://dns.example.org
    - 192.0.2.1
    - dhcp://en0
  fallback:
    - tls://198.51.100.1
    - quic://dns.example.net
`;
        const res = extractDnsServersFromRaw(yaml);
        expect(res).to.deep.equal([
            'https://dns.example.com/dns-query',
            'tls://dns.example.org',
            '192.0.2.1',
        ]);

        const resWithFallback = extractDnsServersFromRaw(yaml, { includeFallback: true });
        expect(resWithFallback).to.deep.equal([
            'https://dns.example.com/dns-query',
            'tls://dns.example.org',
            '192.0.2.1',
            'tls://198.51.100.1',
        ]);
    });

    it('should extract DNS servers from sing-box JSON format', () => {
        const json = JSON.stringify({
            dns: {
                servers: [
                    { tag: 'dns_proxy', address: 'https://dns.example.com/dns-query' },
                    { tag: 'dns_direct', address: '192.0.2.1' },
                    { tag: 'dns_block', address: 'rcode://refused' },
                    'tls://198.51.100.1'
                ]
            }
        });
        const res = extractDnsServersFromRaw(json);
        expect(res).to.deep.equal([
            'https://dns.example.com/dns-query',
            '192.0.2.1',
            'tls://198.51.100.1'
        ]);
    });

    it('should extract DNS servers from QuantumultX INI format', () => {
        const qxConf = `
[dns]
server = 192.0.2.1
server = 198.51.100.1
doh-server = https://dns1.example.com/dns-query, https://dns2.example.com/dns-query
doq-server = quic://dns.example.org
`;
        const res = extractDnsServersFromRaw(qxConf);
        expect(res).to.deep.equal([
            '192.0.2.1',
            '198.51.100.1',
            'https://dns1.example.com/dns-query',
            'https://dns2.example.com/dns-query'
        ]);
    });

    it('should extract DNS servers from Surge / Loon INI format', () => {
        const surgeConf = `
[General]
dns-server = system, 192.0.2.1, 198.51.100.1, tcp://203.0.113.1:53
doh-server = https://dns.example.com/dns-query
`;
        const res = extractDnsServersFromRaw(surgeConf);
        expect(res).to.deep.equal([
            '192.0.2.1',
            '198.51.100.1',
            'tcp://203.0.113.1:53',
            'https://dns.example.com/dns-query'
        ]);
    });

    it('should return empty array for invalid / pure node list raw content', () => {
        const plainNodes = `
ss://YWVzLTEyOC1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjgzODg=#node1
vmess://eyJ2IjoiMiIsInBzIjoibm9kZTIiLCJhZGQiOiIxOTIuMC4yLjIiLCJwb3J0Ijo0NDN9
`;
        const res = extractDnsServersFromRaw(plainNodes);
        expect(res).to.deep.equal([]);
    });
});

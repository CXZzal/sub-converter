import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { groupProxiesByCountry } from '../utils.js';
import {
    SING_BOX_CONFIG,
    generateRules,
    PREDEFINED_RULE_SETS,
    DIRECT_DEFAULT_RULES,
    SITE_RULE_SET_BASE_URL,
    IP_RULE_SET_BASE_URL
} from '../config/index.js';
import { uniqueNames } from './helpers/groupBuilder.js';

const RESERVED_OUTBOUND_TYPES = new Set(['direct', 'block', 'selector', 'urltest', 'dns']);

export class SingboxConfigBuilder extends BaseConfigBuilder {
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent, groupByCountry, includeAutoSelect = true) {
        super(inputString, baseConfig ?? SING_BOX_CONFIG, lang, userAgent, groupByCountry, includeAutoSelect);
        this.selectedRules = selectedRules;
        this.customRules = customRules;
        this.subscriptionUrl = null;
        this.countryGroupNames = [];
        this.manualGroupName = null;
        this._seenRuleSets = new Set();
    }

    setSubscriptionUrl(url) {
        this.subscriptionUrl = url;
        return this;
    }

    // ★★★ 关键修复：让它返回 false，订阅内容就会被解析出节点 ★★★
    isCompatibleProviderFormat(format) {
        return false;
    }

    getProxies() {
        return this.config.outbounds || [];
    }

    getValidProxies() {
        return (this.config.outbounds || []).filter(p =>
            p && typeof p === 'object' && p.type && p.tag && !RESERVED_OUTBOUND_TYPES.has(p.type)
        );
    }

    getProxyName(proxy) {
        return proxy?.tag;
    }

    convertProxy(proxy) {
        const base = {
            tag: proxy.tag,
            server: proxy.server,
            server_port: proxy.server_port
        };
        const tls = this.buildTls(proxy.tls);
        const transport = this.convertTransport(proxy.transport);

        switch (proxy.type) {
            case 'shadowsocks': {
                const out = {
                    ...base,
                    type: 'shadowsocks',
                    method: proxy.method,
                    password: proxy.password
                };
                if (proxy.plugin) {
                    out.plugin = proxy.plugin;
                    out.plugin_opts = proxy.plugin_opts;
                }
                return out;
            }

            case 'vmess':
                return {
                    ...base,
                    type: 'vmess',
                    uuid: proxy.uuid,
                    alter_id: proxy.alter_id ?? 0,
                    security: proxy.cipher ?? 'auto',
                    tls,
                    transport
                };

            case 'vless': {
                const out = {
                    ...base,
                    type: 'vless',
                    uuid: proxy.uuid,
                    tls,
                    transport
                };
                if (proxy.flow) out.flow = proxy.flow;
                if (proxy.packet_encoding) out.packet_encoding = proxy.packet_encoding;
                return out;
            }

            case 'trojan':
                return {
                    ...base,
                    type: 'trojan',
                    password: proxy.password,
                    tls,
                    transport
                };

            case 'hysteria2': {
                const out = {
                    ...base,
                    type: 'hysteria2',
                    password: proxy.password,
                    tls
                };
                if (proxy.obfs) out.obfs = { type: proxy.obfs, password: proxy.obfs_password };
                if (proxy.up_mbps) out.up_mbps = proxy.up_mbps;
                if (proxy.down_mbps) out.down_mbps = proxy.down_mbps;
                if (proxy.hop_interval_max) out.hop_interval_max = proxy.hop_interval_max;
                if (proxy.bbr_profile) out.bbr_profile = proxy.bbr_profile;
                if (proxy.realm) out.realm = proxy.realm;
                if (out.obfs) {
                    if (proxy.obfs_min_packet_size) out.obfs.min_packet_size = proxy.obfs_min_packet_size;
                    if (proxy.obfs_max_packet_size) out.obfs.max_packet_size = proxy.obfs_max_packet_size;
                }
                return out;
            }

            case 'hysteria': {
                const out = {
                    ...base,
                    type: 'hysteria',
                    auth_str: proxy.auth_str || proxy.auth,
                    tls
                };
                if (proxy.protocol) out.protocol = proxy.protocol;
                if (proxy.up_mbps) out.up_mbps = proxy.up_mbps;
                if (proxy.down_mbps) out.down_mbps = proxy.down_mbps;
                return out;
            }

            case 'tuic':
                return {
                    ...base,
                    type: 'tuic',
                    uuid: proxy.uuid,
                    password: proxy.password,
                    congestion_control: proxy.congestion_control,
                    udp_relay_mode: proxy.udp_relay_mode,
                    tls
                };

            case 'http':
                return {
                    ...base,
                    type: 'http',
                    username: proxy.username,
                    password: proxy.password,
                    tls
                };

            case 'socks5':
                return {
                    ...base,
                    type: 'socks',
                    username: proxy.username,
                    password: proxy.password
                };

            case 'snell': {
                const out = {
                    ...base,
                    type: 'snell',
                    psk: proxy.psk,
                    version: proxy.version ?? 5
                };
                if (proxy.obfs_mode) out.obfs_mode = proxy.obfs_mode;
                return out;
            }

            case 'anytls': {
                return {
                    ...base,
                    type: 'anytls',
                    password: proxy.password,
                    tls: tls ?? { enabled: true }
                };
            }

            case 'shadowtls': {
                const out = {
                    ...base,
                    type: 'shadowtls',
                    version: proxy.version ?? 3,
                    password: proxy.password
                };
                if (proxy.sni) out.tls = { enabled: true, server_name: proxy.sni };
                else if (tls) out.tls = tls;
                return out;
            }

            case 'naive': {
                return {
                    ...base,
                    type: 'naive',
                    username: proxy.username,
                    password: proxy.password,
                    tls: tls ?? { enabled: true }
                };
            }

            default:
                console.error('[SB-DIAG] UNHANDLED type =', proxy?.type,
                    '| full =', JSON.stringify(proxy).slice(0, 300));
                return null;
        }
    }

    buildTls(tlsConf) {
        if (!tlsConf || !tlsConf.enabled) return undefined;
        const tls = { enabled: true };
        if (tlsConf.server_name) tls.server_name = tlsConf.server_name;
        if (tlsConf.insecure) tls.insecure = true;
        if (Array.isArray(tlsConf.alpn) && tlsConf.alpn.length) tls.alpn = tlsConf.alpn;
        if (tlsConf.fingerprint) tls.utls = { enabled: true, fingerprint: tlsConf.fingerprint };
        return tls;
    }

    convertTransport(t) {
        if (!t) return undefined;
        switch (t.type) {
            case 'ws': {
                const ws = { type: 'ws' };
                if (t.path) ws.path = t.path;
                if (t.headers) ws.headers = t.headers;
                if (t.max_early_data) ws.max_early_data = t.max_early_data;
                if (t.early_data_header_name) ws.early_data_header_name = t.early_data_header_name;
                return ws;
            }
            case 'grpc':
                return { type: 'grpc', service_name: t.service_name };
            case 'http':
            case 'h2':
                return { type: 'http', host: t.host, path: t.path };
            case 'quic':
                return { type: 'quic' };
            default:
                return undefined;
        }
    }

    addProxyToConfig(proxy) {
        if (!proxy || !proxy.tag) return;
        this.config.outbounds = this.config.outbounds || [];
        if (this.config.outbounds.some(o => o.tag === proxy.tag)) {
            let i = 2;
            let newTag = `${proxy.tag}_${i}`;
            while (this.config.outbounds.some(o => o.tag === newTag)) {
                i++;
                newTag = `${proxy.tag}_${i}`;
            }
            proxy.tag = newTag;
        }
        this.config.outbounds.push(proxy);
    }

    addSelectors() {
        const proxyList = this.getProxyList();
        this.addCountryGroups();
        this.addAutoSelectGroup(proxyList);
        this.addNodeSelectGroup(proxyList);
        const outbounds = this.getOutboundsList();
        this.addOutboundGroups(outbounds, proxyList);
        this.addCustomRuleGroups(proxyList);
        this.addFallBackGroup(proxyList);
    }

    hasOutboundTag(tag) {
        return (this.config.outbounds || []).some(o => o.tag === tag);
    }

    buildNodeSelectOptions(proxyList) {
        const options = [];
        if (this.includeAutoSelect) options.push(this.t('outboundNames.Auto Select'));
        if (this.manualGroupName) options.push(this.manualGroupName);
        this.countryGroupNames.forEach(g => options.push(g));
        proxyList.forEach(p => { if (!options.includes(p)) options.push(p); });
        if (!options.includes('DIRECT')) options.push('DIRECT');
        return uniqueNames(options);
    }

    buildAggregatedOptions(proxyList) {
        const options = [];
        if (this.includeAutoSelect) options.push(this.t('outboundNames.Auto Select'));
        options.push(this.t('outboundNames.Node Select'));
        if (this.manualGroupName) options.push(this.manualGroupName);
        this.countryGroupNames.forEach(g => options.push(g));
        proxyList.forEach(p => { if (!options.includes(p)) options.push(p); });
        if (!options.includes('DIRECT')) options.push('DIRECT');
        return uniqueNames(options);
    }

    addAutoSelectGroup(proxyList) {
        if (!this.includeAutoSelect) return;
        this.config.outbounds = this.config.outbounds || [];
        const tag = this.t('outboundNames.Auto Select');
        if (this.hasOutboundTag(tag)) return;
        this.config.outbounds.push({
            type: 'urltest',
            tag,
            outbounds: uniqueNames(proxyList),
            url: 'http://www.gstatic.com/generate_204',
            interval: '5m',
            tolerance: 50
        });
    }

    addNodeSelectGroup(proxyList) {
        this.config.outbounds = this.config.outbounds || [];
        const tag = this.t('outboundNames.Node Select');
        if (this.hasOutboundTag(tag)) return;
        const options = this.buildNodeSelectOptions(proxyList);
        this.config.outbounds.push({
            type: 'selector',
            tag,
            outbounds: options,
            default: options[0]
        });
    }

    addOutboundGroups(outbounds, proxyList) {
        this.config.outbounds = this.config.outbounds || [];
        outbounds.forEach(outbound => {
            if (outbound === this.t('outboundNames.Node Select')) return;
            const tag = this.t(`outboundNames.${outbound}`);
            if (this.hasOutboundTag(tag)) return;
            let options = this.buildAggregatedOptions(proxyList);
            if (DIRECT_DEFAULT_RULES.has(outbound)) {
                options = ['DIRECT', ...options.filter(p => p !== 'DIRECT')];
            }
            this.config.outbounds.push({
                type: 'selector',
                tag,
                outbounds: options,
                default: options[0]
            });
        });
    }

    addCustomRuleGroups(proxyList) {
        if (!Array.isArray(this.customRules)) return;
        this.config.outbounds = this.config.outbounds || [];
        this.customRules.forEach(rule => {
            if (!rule || !rule.name) return;
            if (this.hasOutboundTag(rule.name)) return;
            const options = this.buildAggregatedOptions(proxyList);
            this.config.outbounds.push({
                type: 'selector',
                tag: rule.name,
                outbounds: options,
                default: options[0]
            });
        });
    }

    addFallBackGroup(proxyList) {
        this.config.outbounds = this.config.outbounds || [];
        const tag = this.t('outboundNames.Fall Back');
        if (this.hasOutboundTag(tag)) return;
        const options = this.buildAggregatedOptions(proxyList);
        this.config.outbounds.push({
            type: 'selector',
            tag,
            outbounds: options,
            default: options[0]
        });
    }

    addCountryGroups() {
        const proxies = this.getValidProxies();
        if (proxies.length === 0) {
            this.countryGroupNames = [];
            this.manualGroupName = null;
            return;
        }

        const countryGroups = groupProxiesByCountry(proxies, {
            getName: p => p.tag
        });

        this.config.outbounds = this.config.outbounds || [];
        const existing = new Set(this.config.outbounds.map(o => o.tag).filter(Boolean));

        const manualNames = proxies.map(p => p.tag).filter(Boolean);
        const manualGroupName = manualNames.length > 0 ? this.t('outboundNames.Manual Switch') : null;
        if (manualGroupName && !existing.has(manualGroupName)) {
            this.config.outbounds.push({
                type: 'selector',
                tag: manualGroupName,
                outbounds: uniqueNames(manualNames),
                default: manualNames[0]
            });
            existing.add(manualGroupName);
        }

        const countryGroupNames = [];
        Object.keys(countryGroups).sort((a, b) => a.localeCompare(b)).forEach(country => {
            const { emoji, name, proxies: tags } = countryGroups[country];
            const groupName = `${emoji} ${name}`;
            countryGroupNames.push(groupName);
            if (!existing.has(groupName)) {
                this.config.outbounds.push({
                    type: 'urltest',
                    tag: groupName,
                    outbounds: uniqueNames(tags),
                    url: 'https://www.gstatic.com/generate_204',
                    interval: '5m',
                    tolerance: 50
                });
                existing.add(groupName);
            }
        });

        this.countryGroupNames = countryGroupNames;
        this.manualGroupName = manualGroupName;
    }

    _addRuleSet(ruleSets, tag, url) {
        if (this._seenRuleSets.has(tag)) return;
        ruleSets.push({
            type: 'remote',
            tag,
            format: 'binary',
            url,
            download_detour: 'DIRECT'
        });
        this._seenRuleSets.add(tag);
    }

    buildRoute(rules) {
        const route = {};
        route.rule_set = [];
        route.rules = [];
        this._seenRuleSets = new Set();

        this._addRuleSet(
            route.rule_set,
            'geolocation-!cn',
            `${SITE_RULE_SET_BASE_URL}geolocation-!cn.srs`
        );

        rules.forEach(rule => {
            const outbound = this.t('outboundNames.' + rule.outbound);

            if (Array.isArray(rule.src_ip_cidr) && rule.src_ip_cidr.length) {
                rule.src_ip_cidr.forEach(cidr => {
                    const v = typeof cidr === 'string' ? cidr.trim() : cidr;
                    if (!v) return;
                    route.rules.push({ source_ip_cidr: [v], outbound });
                });
            }

            if (Array.isArray(rule.domain_suffix) && rule.domain_suffix.length) {
                route.rules.push({
                    domain_suffix: rule.domain_suffix.filter(Boolean),
                    outbound
                });
            }

            if (Array.isArray(rule.domain_keyword) && rule.domain_keyword.length) {
                route.rules.push({
                    domain_keyword: rule.domain_keyword.filter(Boolean),
                    outbound
                });
            }

            if (Array.isArray(rule.site_rules) && rule.site_rules.length) {
                rule.site_rules.forEach(site => {
                    if (!site) return;
                    this._addRuleSet(
                        route.rule_set,
                        site,
                        `${SITE_RULE_SET_BASE_URL}${site}.srs`
                    );
                    route.rules.push({ rule_set: [site], outbound });
                });
            }

            if (Array.isArray(rule.ip_rules) && rule.ip_rules.length) {
                rule.ip_rules.forEach(ip => {
                    if (!ip) return;
                    const tag = `${ip}-ip`;
                    this._addRuleSet(
                        route.rule_set,
                        tag,
                        `${IP_RULE_SET_BASE_URL}${ip}.srs`
                    );
                    route.rules.push({ rule_set: [tag], outbound });
                });
            }

            if (Array.isArray(rule.ip_cidr) && rule.ip_cidr.length) {
                route.rules.push({
                    ip_cidr: rule.ip_cidr.filter(Boolean),
                    outbound
                });
            }
        });

        route.final = this.t('outboundNames.Fall Back');
        route.auto_detect_interface = true;
        route.default_domain_resolver = 'dns_resolver';
        return route;
    }

    formatConfig() {
        this.config.outbounds = this.config.outbounds || [];

        if (!this.config.outbounds.some(o => o.tag === 'DIRECT')) {
            this.config.outbounds.push({ type: 'direct', tag: 'DIRECT' });
        }
        if (!this.config.outbounds.some(o => o.tag === 'REJECT')) {
            this.config.outbounds.push({ type: 'block', tag: 'REJECT' });
        }

        const rules = generateRules(this.selectedRules, this.customRules);
        this.config.route = this.buildRoute(rules);

        return JSON.stringify(this.config, null, 2);
    }
}
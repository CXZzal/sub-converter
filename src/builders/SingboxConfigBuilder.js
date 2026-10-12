import { SING_BOX_CONFIG, generateRuleSets, generateRules, DIRECT_DEFAULT_RULES, REJECT_ACTION_RULES } from '../config/index.js';
import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { deepCopy, groupProxiesByCountry } from '../utils.js';
import { addProxyWithDedup } from './helpers/proxyHelpers.js';
import { buildSelectorMembers as buildSelectorMemberList, buildNodeSelectMembers, buildCustomRuleMembers, uniqueNames } from './helpers/groupBuilder.js';
import { normalizeGroupName } from './helpers/groupNameUtils.js';

/**
 * Generates a regular sing-box configuration for SFA / sing-box 1.14+.
 * Airport subscriptions supply nodes only; their top-level client config is
 * intentionally not allowed to overwrite this converter's working template.
 */
export class SingboxConfigBuilder extends BaseConfigBuilder {
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent, groupByCountry = false, enableClashUI = false, externalController, externalUiDownloadUrl, singboxVersion = '1.12', includeAutoSelect = true) {
        super(inputString, baseConfig ?? SING_BOX_CONFIG, lang, userAgent, groupByCountry, includeAutoSelect);
        this.selectedRules = selectedRules;
        this.customRules = customRules;
        this.countryGroupNames = [];
        this.manualGroupName = null;
        this.enableClashUI = enableClashUI;
        this.externalController = externalController;
        this.externalUiDownloadUrl = externalUiDownloadUrl;
        this.singboxVersion = singboxVersion;

        // Provider-backed subscriptions are deliberately disabled: every node
        // is emitted as a normal outbound for broad SFA compatibility.
        delete this.config.outbound_providers;
        for (const outbound of this.config.outbounds || []) {
            if (outbound && typeof outbound === 'object') delete outbound.providers;
        }

        // In modern sing-box DNS rules that select a server use action=route.
        this.normalizeDnsRules();
        if (this.config?.dns?.servers?.length > 0) {
            this.config.dns.servers[0].detour = this.t('outboundNames.Node Select');
        }
    }

    /** Do not let an airport's Clash/Sing-box config replace our base template. */
    applyConfigOverrides(overrides) {
        if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) return;
        const safeOverrides = { ...overrides };

        // Nodes and proxy-groups are extracted separately by BaseConfigBuilder.
        // Ignore client-level settings from the airport subscription, because
        // those commonly contain legacy DNS/route/inbound fields.
                for (const key of [
            'dns', 'outbounds', 'outbound_providers', 'route',
            'ntp', 'experimental', 'endpoints', 'services',
            'certificate_providers', 'providers',

            // Ignore Clash client-level settings that are invalid
            // in a sing-box configuration.
            'port', 'socks-port', 'mixed-port', 'redir-port',
            'tproxy-port', 'allow-lan', 'bind-address',
            'mode', 'log-level', 'ipv6',
            'external-controller', 'external-ui', 'external-ui-url',
            'secret', 'profile', 'hosts', 'tun',
            'geodata-mode', 'geodata-loader',
            'geo-auto-update', 'geo-update-interval',
            'unified-delay', 'tcp-concurrent',
            'find-process-mode', 'global-client-fingerprint'
        ]) {
            delete safeOverrides[key];
        }

        super.applyConfigOverrides(safeOverrides);
    }

    isCompatibleProviderFormat() {
        return false;
    }

    normalizeDnsRules() {
        if (!this.config.dns || typeof this.config.dns !== 'object') this.config.dns = {};
        if (!Array.isArray(this.config.dns.rules)) this.config.dns.rules = [];

        for (const rule of this.config.dns.rules) {
            if (rule && typeof rule === 'object' && rule.server && !rule.action) {
                rule.action = 'route';
            }
        }
    }

    getProxies() {
        return (this.config.outbounds || []).filter(outbound =>
            outbound && typeof outbound === 'object' && outbound.server !== undefined && outbound.tag
        );
    }

    getProxyName(proxy) {
        return proxy.tag;
    }

    convertProxy(proxy) {
        const sanitized = { ...proxy };
        delete sanitized.udp;
        // Convert Clash port to sing-box server_port.
        if (sanitized.server_port === undefined && sanitized.port !== undefined) {
            sanitized.server_port = sanitized.port;
        }
        delete sanitized.port;
        // Remove invalid VLESS flow values.
        if (sanitized.type === 'vless') {
            const flow = typeof sanitized.flow === 'string'
                ? sanitized.flow.trim()
                : '';

            if (flow === 'xtls-rprx-vision') {
                sanitized.flow = flow;
            } else {
                delete sanitized.flow;
            }
        }

        // Convert Clash-style Hysteria2 port hopping to sing-box format.
               // Convert Clash-style Hysteria2 bandwidth fields to sing-box format.
        if (sanitized.type === 'hysteria2') {
            if (sanitized.up !== undefined) {
                sanitized.up_mbps = Number(
                    String(sanitized.up).replace(/[^0-9.]/g, '')
                );
                delete sanitized.up;
            }

            if (sanitized.down !== undefined) {
                sanitized.down_mbps = Number(
                    String(sanitized.down).replace(/[^0-9.]/g, '')
                );
                delete sanitized.down;
            }
        }
 if (sanitized.type === 'hysteria2' && sanitized.ports !== undefined) {
            const rawPorts = Array.isArray(sanitized.ports)
                ? sanitized.ports
                : String(sanitized.ports).split(',');

            const serverPorts = rawPorts
                .map(port => String(port).trim())
                .filter(Boolean)
                .map(port => port.replace(/^(\d+)\s*-\s*(\d+)$/, '$1:$2'));

            if (serverPorts.length > 0) {
                sanitized.server_ports = serverPorts;
                delete sanitized.server_port;
            }

            // "ports" is not a valid sing-box outbound field.
            delete sanitized.ports;
        // Remove invalid or missing VLESS flow values.
        if (
            typeof sanitized.flow !== 'string' ||
            !sanitized.flow.trim() ||
            ['undefined', 'null'].includes(sanitized.flow.trim().toLowerCase())
        ) {
            delete sanitized.flow;
        }
        }

        // Convert Clash WebSocket transport to sing-box format.
        if (sanitized.network === 'ws') {
            const wsOpts = sanitized['ws-opts'] || sanitized.ws_opts || {};

            sanitized.transport = {
                ...(sanitized.transport || {}),
                type: 'ws'
            };

            if (wsOpts.path !== undefined) {
                sanitized.transport.path = wsOpts.path;
            }

            if (wsOpts.headers && typeof wsOpts.headers === 'object') {
                sanitized.transport.headers = wsOpts.headers;
            }

            delete sanitized.network;
            delete sanitized['ws-opts'];
            delete sanitized.ws_opts;
        }       
 if (sanitized.alpn && sanitized.tls) {
            if (!sanitized.tls.alpn) {
                sanitized.tls = { ...sanitized.tls, alpn: sanitized.alpn };
            }
            delete sanitized.alpn;
        } else if (sanitized.alpn && !sanitized.tls) {
            delete sanitized.alpn;
        }

        // Clash-only setting; sing-box chooses the supported packet encoding.
        delete sanitized.packet_encoding;
        delete sanitized.providers;
        return sanitized;
    }

    addProxyToConfig(proxy) {
        this.config.outbounds = this.config.outbounds || [];

        addProxyWithDedup(this.config.outbounds, proxy, {
            getName: item => item?.tag,
            setName: (item, name) => {
                if (item) item.tag = name;
            },
            isSame: (existing = {}, incoming = {}) => {
                const { tag: _incomingTag, ...restIncoming } = incoming;
                const { tag: _existingTag, ...restExisting } = existing;

                return JSON.stringify(restIncoming) === JSON.stringify(restExisting);
            }
        });
    }

    hasOutboundTag(tag) {
        const target = normalizeGroupName(tag);

        return (this.config.outbounds || []).some(
            outbound => normalizeGroupName(outbound?.tag) === target
        );
    }

    hasAutoSelectCandidates(proxyList = this.getProxyList()) {
        return Array.isArray(proxyList) && proxyList.length > 0;
    }

    /**
     * Keep only two generated proxy groups:
     * manual node selector and automatic URLTest.
     */
addSelectors() {
    // 只保留两个代理组：
    // 1. 🚀 节点选择 selector
    // 2. ♻️ 自动选择 urltest

    this.config.outbounds = (this.config.outbounds || []).filter(outbound =>
        outbound &&
        outbound.type !== 'selector' &&
        outbound.type !== 'urltest'
    );

    const proxyList = this.getProxyList();

    this.addAutoSelectGroup(proxyList);
    this.addNodeSelectGroup(proxyList);

    // 删除机场自带 proxy-groups
    this.pendingUserProxyGroups = [];
}
    addAutoSelectGroup(proxyList) {
        if (!this.includeAutoSelect) return;

        this.config.outbounds = this.config.outbounds || [];

        const tag = this.t('outboundNames.Auto Select');
        if (this.hasOutboundTag(tag)) return;

        const members = deepCopy(uniqueNames(proxyList));
        if (members.length === 0) return;

        this.config.outbounds.unshift({
            type: 'urltest',
            tag,
            interval: '30m',
            outbounds: members
        });
    }

    addNodeSelectGroup(proxyList) {
        this.config.outbounds = this.config.outbounds || [];

        const tag = this.t('outboundNames.Node Select');
        if (this.hasOutboundTag(tag)) return;

        const members = buildNodeSelectMembers({
            proxyList,
            translator: this.t,
            groupByCountry: this.groupByCountry,
            manualGroupName: this.manualGroupName,
            countryGroupNames: this.countryGroupNames,
            includeAutoSelect: this.includeAutoSelect && this.hasAutoSelectCandidates(proxyList),
            includeReject: false
        });

        this.config.outbounds.unshift({
            type: 'selector',
            tag,
            outbounds: members
        });
    }

    buildSelectorMembers(proxyList = []) {
        return buildSelectorMemberList({
            proxyList,
            translator: this.t,
            groupByCountry: this.groupByCountry,
            manualGroupName: this.manualGroupName,
            countryGroupNames: this.countryGroupNames,
            includeAutoSelect: this.includeAutoSelect && this.hasAutoSelectCandidates(proxyList),
            includeReject: false
        });
    }

    addOutboundGroups(outbounds, proxyList) {
    // 不生成 Google / Telegram / Netflix 等额外 selector
    return;
}

    addCustomRuleGroups(proxyList) {
    // 不生成额外代理组
    return;
}

    addFallBackGroup(proxyList) {
    // 不生成 Fall Back
    return;
}

    addCountryGroups() {
        const proxies = this.getProxies();

        const countryGroups = groupProxiesByCountry(proxies, {
            getName: proxy => this.getProxyName(proxy)
        });

        const existingTags = new Set(
            (this.config.outbounds || [])
                .map(item => normalizeGroupName(item?.tag))
                .filter(Boolean)
        );

        const proxyNames = proxies.map(proxy => proxy?.tag).filter(Boolean);

        const manualGroupName = proxyNames.length
            ? this.t('outboundNames.Manual Switch')
            : null;

        if (manualGroupName && !existingTags.has(normalizeGroupName(manualGroupName))) {
            this.config.outbounds.push({
                type: 'selector',
                tag: manualGroupName,
                outbounds: proxyNames
            });

            existingTags.add(normalizeGroupName(manualGroupName));
        }

        const countryGroupNames = [];

        Object.keys(countryGroups)
            .sort((a, b) => a.localeCompare(b))
            .forEach(country => {
                const { emoji, name, proxies: countryProxies } = countryGroups[country];

                if (!Array.isArray(countryProxies) || !countryProxies.length) return;

                const tag = `${emoji} ${name}`;

                if (!existingTags.has(normalizeGroupName(tag))) {
                    this.config.outbounds.push({
                        type: 'urltest',
                        tag,
                        outbounds: countryProxies
                    });

                    existingTags.add(normalizeGroupName(tag));
                }

                countryGroupNames.push(tag);
            });

        const nodeSelect = this.config.outbounds.find(
            item => normalizeGroupName(item?.tag) ===
                normalizeGroupName(this.t('outboundNames.Node Select'))
        );

        if (nodeSelect && Array.isArray(nodeSelect.outbounds)) {
            nodeSelect.outbounds = buildNodeSelectMembers({
                proxyList: [],
                translator: this.t,
                groupByCountry: true,
                manualGroupName,
                countryGroupNames,
                includeAutoSelect: this.includeAutoSelect && this.hasAutoSelectCandidates(),
                includeReject: false
            });
        }

        this.countryGroupNames = countryGroupNames;
        this.manualGroupName = manualGroupName;
    }

    mergeUserProxyGroups(userGroups) {
        // Ignore airport proxy-groups.
        // The converter only keeps its own generated groups.
        return;
    }

    validateOutbounds() {
        const proxyList = this.getProxyList();
        const invalidTags = new Set();

        (this.config.outbounds || []).forEach(outbound => {
            if (!outbound || (outbound.type !== 'urltest' && outbound.type !== 'selector')) {
                return;
            }

            delete outbound.providers;

            if (!Array.isArray(outbound.outbounds) || outbound.outbounds.length === 0) {
                if (proxyList.length) {
                    outbound.outbounds = [...proxyList];
                } else {
                    invalidTags.add(normalizeGroupName(outbound.tag));
                }
            }
        });

        if (invalidTags.size) {
            this.config.outbounds = (this.config.outbounds || [])
                .filter(outbound => !invalidTags.has(normalizeGroupName(outbound?.tag)))
                .map(outbound => {
                    if (Array.isArray(outbound.outbounds)) {
                        outbound.outbounds = outbound.outbounds.filter(
                            tag => !invalidTags.has(normalizeGroupName(tag))
                        );
                    }

                    return outbound;
                });
        }
    }

    sanitizeLegacySpecialOutbounds() {
        const legacyTags = new Set(
            (this.config.outbounds || [])
                .filter(outbound => outbound?.type === 'block' || outbound?.type === 'dns')
                .map(outbound => normalizeGroupName(outbound?.tag))
                .filter(Boolean)
        );

        legacyTags.add(normalizeGroupName('REJECT'));

        this.config.outbounds = (this.config.outbounds || [])
            .filter(outbound => !legacyTags.has(normalizeGroupName(outbound?.tag)))
            .map(outbound => {
                delete outbound.providers;

                if (Array.isArray(outbound.outbounds)) {
                    outbound.outbounds = outbound.outbounds.filter(
                        tag => !legacyTags.has(normalizeGroupName(tag))
                    );
                }

                return outbound;
            })
            .filter(outbound => {
                if (outbound?.type !== 'selector' && outbound?.type !== 'urltest') {
                    return true;
                }

                return Array.isArray(outbound.outbounds) && outbound.outbounds.length > 0;
            });
    }

    buildRouteTarget(rule) {
        if (
            REJECT_ACTION_RULES.has(rule?.outbound) ||
            rule?.outbound === 'REJECT'
        ) {
            return { action: 'reject' };
        }

        if (
            DIRECT_DEFAULT_RULES.has(rule?.outbound) ||
            rule?.outbound === 'DIRECT' ||
            rule?.outbound === 'direct'
        ) {
            return { outbound: 'DIRECT' };
        }

        return {
            outbound: this.t('outboundNames.Node Select')
        };
    }

    formatConfig() {
        const rules = generateRules(this.selectedRules, this.customRules);
        const { site_rule_sets, ip_rule_sets } = generateRuleSets(
            this.selectedRules,
            this.customRules
        );

        this.config.route = this.config.route || {};
        this.config.route.rules = Array.isArray(this.config.route.rules)
            ? this.config.route.rules
            : [];

        this.config.route.rule_set = [...site_rule_sets, ...ip_rule_sets];

        this.normalizeDnsRules();

        const attachProtocolIfNeeded = (entry, rule) => {
            if (Array.isArray(rule?.protocol) && rule.protocol.length) {
                entry.protocol = rule.protocol;
            }

            return entry;
        };

        const hasMatchValues = value => Array.isArray(value)
            ? value.length > 0
            : typeof value === 'string' && value.trim() !== '';

        rules
            .filter(rule => Array.isArray(rule.src_ip_cidr) && rule.src_ip_cidr.length)
            .forEach(rule => {
                this.config.route.rules.push(
                    attachProtocolIfNeeded({
                        source_ip_cidr: rule.src_ip_cidr,
                        ...this.buildRouteTarget(rule)
                    }, rule)
                );
            });

        rules
            .filter(rule => hasMatchValues(rule.domain_suffix) || hasMatchValues(rule.domain_keyword))
            .forEach(rule => {
                const entry = { ...this.buildRouteTarget(rule) };

                if (hasMatchValues(rule.domain_suffix)) {
                    entry.domain_suffix = rule.domain_suffix;
                }

                if (hasMatchValues(rule.domain_keyword)) {
                    entry.domain_keyword = rule.domain_keyword;
                }

                this.config.route.rules.push(attachProtocolIfNeeded(entry, rule));
            });

        rules
            .filter(rule => !!rule.site_rules?.[0])
            .forEach(rule => {
                this.config.route.rules.push(
                    attachProtocolIfNeeded({
                        rule_set: rule.site_rules.filter(Boolean),
                        ...this.buildRouteTarget(rule)
                    }, rule)
                );
            });

        rules
            .filter(rule => !!rule.ip_rules?.[0])
            .forEach(rule => {
                this.config.route.rules.push(
                    attachProtocolIfNeeded({
                        rule_set: rule.ip_rules
                            .map(ip => ip.trim())
                            .filter(Boolean)
                            .map(ip => `${ip}-ip`),
                        ...this.buildRouteTarget(rule)
                    }, rule)
                );
            });

        rules
            .filter(rule => hasMatchValues(rule.ip_cidr))
            .forEach(rule => {
                this.config.route.rules.push(
                    attachProtocolIfNeeded({
                        ip_cidr: rule.ip_cidr,
                        ...this.buildRouteTarget(rule)
                    }, rule)
                );
            });

        this.config.route.rules.unshift(
            { clash_mode: 'direct', outbound: 'DIRECT' },
            { clash_mode: 'global', outbound: this.t('outboundNames.Node Select') },
            { action: 'sniff' },
            { protocol: 'dns', action: 'hijack-dns' }
        );

        this.config.route.auto_detect_interface = true;
        this.config.route.final = this.t('outboundNames.Node Select');

        // Keep the subscription TUN stack when SFA can use it.
        // This SFA build does not include gVisor.
        // Convert unsupported gvisor/mixed stack to system.
        const tun = (this.config.inbounds || []).find(item => item?.type === 'tun');
        if (tun && (tun.stack === 'gvisor' || tun.stack === 'mixed')) {
            tun.stack = 'system';
        }

        // sing-box 1.14+ requires an explicit HTTP client for remote rule-set downloads.
        // Route these downloads through the same selectable proxy group as before.
        const ruleSetHttpClientTag = 'rule-set-client';
        this.config.http_clients = Array.isArray(this.config.http_clients)
            ? this.config.http_clients
            : [];
        const existingRuleSetHttpClient = this.config.http_clients.find(
            client => client?.tag === ruleSetHttpClientTag
        );
        if (existingRuleSetHttpClient) {
            existingRuleSetHttpClient.detour = this.t('outboundNames.Node Select');
        } else {
            this.config.http_clients.push({
                tag: ruleSetHttpClientTag,
                detour: this.t('outboundNames.Node Select')
            });
        }
        this.config.route.default_http_client = ruleSetHttpClientTag;

        this.validateOutbounds();
        this.sanitizeLegacySpecialOutbounds()


        // 最终强制只保留两个代理组，普通节点出站不受影响。
        const nodeSelectTag = normalizeGroupName(this.t('outboundNames.Node Select'));
        const autoSelectTag = normalizeGroupName(this.t('outboundNames.Auto Select'));
        const keptGroupTags = new Set();

        this.config.outbounds = (this.config.outbounds || []).filter(outbound => {
            if (!outbound || (outbound.type !== 'selector' && outbound.type !== 'urltest')) {
                return true;
            }

            const tag = normalizeGroupName(outbound.tag);
            const allowedType = tag === nodeSelectTag
                ? 'selector'
                : tag === autoSelectTag
                    ? 'urltest'
                    : null;

            if (!allowedType || outbound.type !== allowedType || keptGroupTags.has(tag)) {
                return false;
            }

            keptGroupTags.add(tag);
            return true;
        });

        delete this.config.outbound_providers;

        for (const outbound of this.config.outbounds || []) {
            delete outbound.providers;
        }

        if (this.enableClashUI || this.externalController || this.externalUiDownloadUrl) {
            const existing = this.config.experimental?.clash_api || {};

            this.config.experimental = this.config.experimental || {};
            this.config.experimental.clash_api = {
                ...existing,
                external_controller: this.externalController || existing.external_controller || '0.0.0.0:9090',
                external_ui: existing.external_ui || './ui',
                external_ui_download_url: this.externalUiDownloadUrl || existing.external_ui_download_url || 'https://gh-proxy.com/https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip',
                external_ui_download_detour: existing.external_ui_download_detour || 'DIRECT',
                secret: existing.secret ?? '',
                default_mode: existing.default_mode || 'rule'
            };
        }

        return this.config;
    }
}

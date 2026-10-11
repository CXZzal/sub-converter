const normalize = (value) => typeof value === 'string' ? value.trim() : value;

export function uniqueNames(names = []) {
    const seen = new Set();
    const result = [];

    names.forEach(name => {
        if (typeof name !== 'string') return;

        const normalized = normalize(name);

        if (!normalized || seen.has(normalized)) return;

        seen.add(normalized);
        result.push(normalized);
    });

    return result;
}

export function withDirectReject(options = [], { includeReject = true } = {}) {
    return uniqueNames([
        ...options,
        'DIRECT',
        ...(includeReject ? ['REJECT'] : [])
    ]);
}

export function buildNodeSelectMembers({
    proxyList = [],
    translator,
    groupByCountry = false,
    manualGroupName,
    countryGroupNames = [],
    includeAutoSelect = true,
    includeReject = true
}) {
    if (!translator) {
        throw new Error('buildNodeSelectMembers requires a translator function');
    }

    const autoName = translator('outboundNames.Auto Select');

    const base = groupByCountry
        ? [
            ...(includeAutoSelect ? [autoName] : []),
            ...(manualGroupName ? [manualGroupName] : []),
            ...countryGroupNames
        ]
        : [
            ...(includeAutoSelect ? [autoName] : []),
            ...proxyList
        ];

    return withDirectReject(base, { includeReject });
}


export function buildSelectorMembers({
    proxyList = [],
    translator,
    groupByCountry = false,
    manualGroupName,
    countryGroupNames = [],
    includeAutoSelect = true,
    includeReject = true
}) {
    if (!translator) {
        throw new Error('buildSelectorMembers requires a translator function');
    }

    /*
     * selector 作为主手动选择入口：
     *
     * 🌍代理
     * ├── ♻️自动选择
     * ├── 节点1
     * ├── 节点2
     * └── DIRECT
     *
     * 不再包含：
     * └── 节点选择(selector)
     *
     * 避免 selector 嵌套 selector。
     */

    const base = groupByCountry
        ? [
            ...(includeAutoSelect ? [translator('outboundNames.Auto Select')] : []),
            ...(manualGroupName ? [manualGroupName] : []),
            ...countryGroupNames
        ]
        : [
            ...(includeAutoSelect ? [translator('outboundNames.Auto Select')] : []),
            ...proxyList
        ];

    return withDirectReject(base, { includeReject });
}


export function buildCustomRuleMembers({
    proxyList = [],
    translator,
    manualGroupName,
    includeAutoSelect = true,
    includeReject = true
}) {
    if (!translator) {
        throw new Error('buildCustomRuleMembers requires a translator function');
    }

    return withDirectReject([
        translator('outboundNames.Node Select'),
        ...(includeAutoSelect ? [translator('outboundNames.Auto Select')] : []),
        ...(manualGroupName ? [manualGroupName] : []),
        ...proxyList
    ], { includeReject });
}
import { decodeBase64 } from '../../utils.js';
import { parseSubscriptionContent } from './subscriptionContentParser.js';

const SUBSCRIPTION_URI_PATTERN = /^(ss|vmess|vless|hysteria|hysteria2|hy2|trojan|tuic|anytls|http|https):\/\//i;

function hasSubscriptionUriLine(content) {
    return content
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .some(line => SUBSCRIPTION_URI_PATTERN.test(line));
}

function isLikelyTomlConfig(content) {
    return /^\s*\[[^\]]+\]\s*$/m.test(content) && /^\s*[A-Za-z0-9_.-]+\s*=/.test(content);
}

function isPlainSubscriptionContent(content) {
    if (!content || typeof content !== 'string') {
        return false;
    }
    return detectFormat(content) !== 'unknown' ||
        hasSubscriptionUriLine(content) ||
        isLikelyTomlConfig(content);
}

function decodeUriComponentIfNeeded(text) {
    const trimmed = text.trim();
    if (!trimmed.includes('%')) {
        return trimmed;
    }

    try {
        return decodeURIComponent(trimmed).trim();
    } catch (urlError) {
        console.warn('Failed to URL decode the text:', urlError);
        return trimmed;
    }
}

function normalizeBase64Candidate(text) {
    const compact = text.replace(/\s+/g, '');
    if (!compact || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(compact)) {
        return null;
    }
    if (/=/.test(compact.replace(/={0,2}$/, ''))) {
        return null;
    }

    const withoutPadding = compact.replace(/=+$/, '');
    if (withoutPadding.length % 4 === 1) {
        return null;
    }

    const normalized = withoutPadding.replace(/-/g, '+').replace(/_/g, '/');
    return normalized + '='.repeat((4 - normalized.length % 4) % 4);
}

/**
 * Decode content only when the payload proves it is an encoded subscription.
 * @param {string} text - Raw text content
 * @returns {string} - Decoded content
 */
function decodeContent(text) {
    const urlDecodedText = decodeUriComponentIfNeeded(text);
    if (isPlainSubscriptionContent(urlDecodedText)) {
        return urlDecodedText;
    }

    const base64Candidate = normalizeBase64Candidate(urlDecodedText);
    if (!base64Candidate) {
        return urlDecodedText;
    }

    try {
        const decodedText = decodeUriComponentIfNeeded(decodeBase64(base64Candidate));
        if (isPlainSubscriptionContent(decodedText)) {
            return decodedText;
        }
    } catch (e) {
        return urlDecodedText;
    }

    return urlDecodedText;
}

/**
 * Detect the format of subscription content
 * @param {string} content - Decoded subscription content
 * @returns {'clash'|'singbox'|'surge'|'unknown'} - Detected format
 */
function detectFormat(content) {
    const trimmed = content.trim();

    // Try JSON (Sing-Box format)
    if (trimmed.startsWith('{')) {
        try {
            const parsed = JSON.parse(trimmed);
            if (parsed.outbounds || parsed.inbounds || parsed.route) {
                return 'singbox';
            }
        } catch {
            // Not valid JSON
        }
    }

    // Try YAML (Clash format) - check for proxies: key
    if (trimmed.includes('proxies:')) {
        return 'clash';
    }

    if (/\[(General|Proxy|Rule|Proxy Group)\]/i.test(trimmed)) {
        return 'surge';
    }

    return 'unknown';
}
function safeHost(url) {
    try {
        return new URL(url).host;
    } catch {
        return '(invalid URL)';
    }
}

function safePreview(value) {
    return String(value || '')
        .replace(/https?:\/\/[^\s"'<>]+/gi, '[URL]')
        .replace(
            /([?&](?:token|key|auth|password|pass|secret|sign|signature|access_token)=)[^&\s"'<>]*/gi,
            '$1[REDACTED]'
        )
        .replace(/\b[A-Za-z0-9_-]{48,}\b/g, '[LONG_VALUE]')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 240);
}

async function logHttpFailure(label, url, response, userAgent) {
    let bodyPreview = '';

    try {
        bodyPreview = safePreview(await response.text());
    } catch {
        bodyPreview = '(could not read response body)';
    }

    console.error(label, {
        host: safeHost(url),
        status: response.status,
        statusText: response.statusText,
        contentType: response.headers.get('content-type') || '',
        server: response.headers.get('server') || '',
        cfRay: response.headers.get('cf-ray') || '',
cfCacheStatus:
response.headers.get('cf-cache-status') || '',

cfMitigated:
response.headers.get('cf-mitigated') || '',

location:
response.headers.get('location') || '',
        wwwAuthenticate: response.headers.get('www-authenticate') || '',
        userAgent: userAgent || '(not set)',
        bodyPreview: bodyPreview || '(empty response body)'
    });
}
/**
 * Fetch subscription content from a URL and parse it
 * @param {string} url - The subscription URL to fetch
 * @param {string} userAgent - Optional User-Agent header
 * @returns {Promise<object|string[]|null>} - Parsed subscription content
 */
export async function fetchSubscription(url, userAgent) {
    try {
        const headers = new Headers();

headers.set(
    'User-Agent',
    userAgent || 'ClashMetaForAndroid/2.11.12'
);

headers.set(
    'Accept',
    '*/*'
);

headers.set(
    'Accept-Encoding',
    'gzip, deflate, br'
);
        const response = await fetch(url, {
            method: 'GET',
            headers: headers
        });
        if (!response.ok) {
    await logHttpFailure(
        'Subscription fetch returned non-2xx response',
        url,
        response,
        userAgent
    );
    return null;
}
        const text = await response.text();
        const decodedText = decodeContent(text);

        return parseSubscriptionContent(decodedText);
    } catch (error) {
        console.error('Error fetching or parsing HTTP(S) content:', error);
        return null;
    }
}

/**
 * Fetch subscription content and detect its format without parsing
 * @param {string} url - The subscription URL to fetch
 * @param {string} userAgent - Optional User-Agent header
 * @returns {Promise<{content: string, format: 'clash'|'singbox'|'surge'|'unknown', url: string, subscriptionUserinfo?: string}|null>}
 */
export async function fetchSubscriptionWithFormat(url, userAgent) {
    try {
        const headers = new Headers();

headers.set(
    'User-Agent',
    userAgent || 'ClashMetaForAndroid/2.11.12'
);

headers.set(
    'Accept',
    '*/*'
);

headers.set(
    'Accept-Encoding',
    'gzip, deflate, br'
);
        const response = await fetch(url, {
            method: 'GET',
            headers: headers
        });
        if (!response.ok) {
    await logHttpFailure(
        'Subscription fetch returned non-2xx response',
        url,
        response,
        userAgent
    );

    return {
        error: true,
        status: response.status
    };
}
        const text = await response.text();
        const content = decodeContent(text);
        const format = detectFormat(content);

        const subscriptionUserinfo = response.headers.get('subscription-userinfo') || undefined;

        return { content, format, url, subscriptionUserinfo };
    } catch (error) {
        console.error('Error fetching subscription:', error);
        return null;
    }
}

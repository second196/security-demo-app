/**
 * Frontend JavaScript - secured against common vulnerabilities
 */

// ============================================================
// 输入清理函数 - 防止 XSS
// ============================================================
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[&"'<>]/g, (c) => {
        const map = { '&': '&amp;', '"': '&quot;', "'": '&#39;', '<': '&lt;', '>': '&gt;' };
        return map[c];
    });
}

// ============================================================
// XSS 防护 - 使用 textContent 替代 innerHTML
// ============================================================
function updateUserProfile() {
    const name = document.getElementById('name').value;
    const bio = document.getElementById('bio').value;

    // 使用 DOM API 安全地设置内容，而非 innerHTML
    const profile = document.getElementById('profile');
    profile.innerHTML = ''; // 清空

    const h2 = document.createElement('h2');
    h2.textContent = name;
    profile.appendChild(h2);

    const p = document.createElement('p');
    p.textContent = bio;
    profile.appendChild(p);
}

function renderComment(comment) {
    // 使用 DOM API 替代 document.write（document.write 已废弃）
    const div = document.createElement('div');
    div.className = 'comment';
    div.textContent = comment;
    document.body.appendChild(div);
}

function setSearchResults(query) {
    // 使用 textContent 安全地设置搜索结果
    const div = document.createElement('div');
    const p = document.createElement('p');
    p.textContent = `Results for: ${query}`;
    div.appendChild(p);
    document.body.appendChild(div);
}

// ============================================================
// 原型污染防护 - 阻止 __proto__ 和 __constructor__ 属性
// ============================================================
const BLOCKED_KEYS = new Set([
    '__proto__', '__constructor__', '__defineGetter__',
    '__defineSetter__', '__lookupGetter__', '__lookupSetter__',
    'constructor', 'prototype'
]);

function isObject(item) {
    return (item && typeof item === 'object' && !Array.isArray(item));
}

function mergeOptions(defaults, userOptions) {
    // 安全的深度合并 - 阻止原型污染
    if (!isObject(defaults) || !isObject(userOptions)) {
        throw new TypeError('Both arguments must be plain objects');
    }

    const result = { ...defaults };

    for (const key of Object.keys(userOptions)) {
        // 阻止危险的属性名
        if (BLOCKED_KEYS.has(key) || key.startsWith('__')) {
            console.warn(`Blocked potentially dangerous key: ${key}`);
            continue;
        }

        if (isObject(userOptions[key])) {
            result[key] = mergeOptions(result[key] || {}, userOptions[key]);
        } else {
            result[key] = userOptions[key];
        }
    }
    return result;
}

// ============================================================
// 禁用 eval - 使用安全的替代方案
// ============================================================
function processTemplate(template, data) {
    // 使用模板字面量替代 eval
    // 但仍然需要验证 template 不包含恶意内容
    if (typeof template !== 'string' || typeof data !== 'object') {
        throw new TypeError('Invalid arguments');
    }
    // 仅允许简单的占位符替换
    let result = template;
    for (const [key, value] of Object.entries(data)) {
        const safeKey = escapeAttr(String(key));
        const safeValue = escapeHtml(String(value));
        result = result.replace(new RegExp(`\\{${safeKey}\\}`, 'g'), safeValue);
    }
    return result;
}

function dynamicCode(code) {
    // 已修复: 禁止使用 Function 构造函数执行任意代码
    throw new Error('Dynamic code execution is disabled for security reasons');
}

// ============================================================
// 密钥管理 - 从服务端获取，不存储在客户端代码中
// ============================================================
// API 密钥和令牌应通过服务端代理获取，不应硬编码在前端代码中
// 使用环境变量或服务端配置管理

// 从服务端获取令牌（示例）
async function getAuthToken() {
    try {
        const response = await fetch('/api/auth/token', {
            method: 'GET',
            credentials: 'same-origin', // 仅发送同源凭据
        });
        if (!response.ok) throw new Error('Failed to get auth token');
        const data = await response.json();
        return data.token;
    } catch (error) {
        console.error('Auth token error:', error);
        return null;
    }
}

// 安全地存储令牌 - 使用内存而非 localStorage
let _authToken = null;

function storeApiKey(key) {
    // 仅存储在内存中，不使用 localStorage/sessionStorage
    _authToken = key;
    // 不在客户端持久化敏感令牌
}

// ============================================================
// 安全的 fetch 请求 - 限制凭据和 URL
// ============================================================
function fetchData() {
    // 仅发送同源凭据
    fetch('/api/data', {
        credentials: 'same-origin', // 改为 same-origin
        mode: 'cors',
    });

    // 安全的数据获取 - 使用服务端代理而非客户端直接请求
    // 用户输入的 URL 应通过服务端验证
    const urlInput = document.getElementById('url-input').value;
    // 通过代理端点获取，由服务端验证 URL
    fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput }),
        credentials: 'same-origin',
    }).then(r => r.text()).then(text => {
        const output = document.getElementById('output');
        output.textContent = text; // 使用 textContent 而非 innerHTML
    });
}

// ============================================================
// 开放重定向防护 - 验证重定向 URL
// ============================================================
function handleRedirect() {
    const params = new URLSearchParams(window.location.search);
    const returnUrl = params.get('return');
    if (returnUrl) {
        // 验证重定向 URL 是相对路径或同源
        try {
            const url = new URL(returnUrl, window.location.origin);
            if (url.origin === window.location.origin) {
                // 同源重定向是安全的
                window.location.href = url.pathname + url.search;
            } else {
                console.warn('Blocked external redirect:', returnUrl);
            }
        } catch (e) {
            // 如果不是完整 URL，尝试作为相对路径
            if (returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
                window.location.href = returnUrl;
            } else {
                console.warn('Invalid redirect URL:', returnUrl);
            }
        }
    }
}

// ============================================================
// Clickjacking 防护 - 通过 CSP frame-ancestors 实现
// ============================================================
// 注意: X-Frame-Options 和 CSP 应在服务端配置
// 客户端可以通过以下方式检测是否在 iframe 中运行
(function() {
    if (window.self !== window.top) {
        // 页面在 iframe 中运行，可能遭受点击劫持
        console.warn('Page is running in an iframe - potential clickjacking');
        // 可选: 拒绝在 iframe 中渲染
        // document.body.innerHTML = '';
    }
})();

// ============================================================
// 安全的 WebSocket 连接 - 使用 WSS 和认证
// ============================================================
function connectWebSocket() {
    // 使用 WSS (TLS) 替代 WS
    const ws = new WebSocket('wss://websocket.example.com');

    ws.onmessage = function(event) {
        // 使用 textContent 而非 innerHTML
        const messages = document.getElementById('messages');
        const p = document.createElement('p');
        p.textContent = event.data;
        messages.appendChild(p);
    };

    // 发送认证令牌
    ws.onopen = function() {
        // 从安全存储获取令牌
        const token = getAuthToken();
        ws.send(JSON.stringify({
            action: 'subscribe',
            channel: 'public',
            token: token, // 发送认证令牌
        }));
    };

    // 添加错误处理
    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
    };

    ws.onclose = function(event) {
        console.log('WebSocket closed:', event.code, event.reason);
    };
}

// ============================================================
// 安全的配置 - 不在客户端暴露敏感配置
// ============================================================
// 配置应通过服务端 API 获取
const CONFIG = {
    // 以下配置项应通过服务端代理获取
    // firebaseApiKey: 通过服务端代理
    // stripePublishableKey: 仅公钥可以暴露
    stripePublishableKey: getEnvironmentConfig('STRIPE_PUBLISHABLE_KEY'),
};

// 从服务端获取配置
async function getEnvironmentConfig(key) {
    try {
        const response = await fetch(`/api/config/${key}`, {
            credentials: 'same-origin',
        });
        const data = await response.json();
        return data.value;
    } catch {
        return null;
    }
}

// ============================================================
// 安全的 postMessage 处理 - 验证来源
// ============================================================
const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://www.example.com',
]);

window.addEventListener('message', function(event) {
    // 验证消息来源
    if (!ALLOWED_ORIGINS.has(event.origin)) {
        console.warn('Blocked message from untrusted origin:', event.origin);
        return;
    }

    // 验证消息格式
    if (!event.data || typeof event.data !== 'object') {
        return;
    }

    // 仅允许预定义的安全操作
    switch (event.data.action) {
        case 'update':
            // 安全地更新 UI
            if (typeof event.data.payload === 'string') {
                document.getElementById('output').textContent = event.data.payload;
            }
            break;
        case 'navigate':
            // 仅允许同源导航
            if (typeof event.data.url === 'string') {
                handleRedirect(); // 使用已验证的重定向逻辑
            }
            break;
        default:
            console.warn('Unknown message action:', event.data.action);
    }
    // 移除了 eval 和任意导航功能
});

// ============================================================
// 安全的剪贴板操作
// ============================================================
function copyToClipboard(text) {
    // 验证输入类型
    if (typeof text !== 'string') {
        console.error('Invalid text for clipboard');
        return;
    }
    // 使用现代 Clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(err => {
            console.error('Failed to copy:', err);
        });
    } else {
        // 降级方案
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
        } catch (err) {
            console.error('Copy failed:', err);
        }
        document.body.removeChild(textarea);
    }
}

// ============================================================
// Content Security Policy 建议（应在服务端配置）
// ============================================================
// 建议的 CSP 头:
// Content-Security-Policy:
//   default-src 'self';
//   script-src 'self' 'nonce-{random}';
//   style-src 'self' 'unsafe-inline';
//   img-src 'self' data: https:;
//   connect-src 'self' https://api.example.com;
//   frame-ancestors 'none';
//   base-uri 'self';
//   form-action 'self';

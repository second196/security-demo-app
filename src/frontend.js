/**
 * Frontend JavaScript with security vulnerabilities
 */

// ============================================================
// DOM-based XSS
// ============================================================
function updateUserProfile() {
    const name = document.getElementById('name').value;
    const bio = document.getElementById('bio').value;

    // XSS: Direct innerHTML with user input
    document.getElementById('profile').innerHTML = `
        <h2>${name}</h2>
        <p>${bio}</p>
    `;
}

function renderComment(comment) {
    // XSS: Using document.write
    document.write(`<div class="comment">${comment}</div>`);
}

function setSearchResults(query) {
    // XSS: DOM manipulation with unsanitized input
    const div = document.createElement('div');
    div.innerHTML = `<p>Results for: ${query}</p>`;
    document.body.appendChild(div);
}

// ============================================================
// Prototype pollution
// ============================================================
function mergeOptions(defaults, userOptions) {
    // Prototype pollution: deep merge without sanitization
    for (let key in userOptions) {
        if (typeof userOptions[key] === 'object') {
            defaults[key] = mergeOptions(defaults[key] || {}, userOptions[key]);
        } else {
            defaults[key] = userOptions[key];
        }
    }
    return defaults;
}

// Usage: mergeOptions({}, JSON.parse(userInput))
// If userInput = {"__proto__": {"isAdmin": true}}, it pollutes Object.prototype

// ============================================================
// Insecure eval
// ============================================================
function processTemplate(template, data) {
    // Arbitrary code execution via eval
    return eval('`' + template + '`');
}

function dynamicCode(code) {
    // Using Function constructor - similar to eval
    const func = new Function('return ' + code);
    return func();
}

// ============================================================
// Client-side secret storage
// ============================================================
const API_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

// Storing in localStorage (insecure)
function storeApiKey(key) {
    localStorage.setItem('api_key', API_KEY);
    localStorage.setItem('jwt', JWT_TOKEN);
    sessionStorage.setItem('secret', 'super_secret_value');
}

// ============================================================
// Insecure fetch requests
// ============================================================
function fetchData() {
    // Sending credentials cross-origin
    fetch('https://api.example.com/data', {
        credentials: 'include',
        mode: 'cors'
    });

    // SSRF potential: user-controlled URL
    const url = document.getElementById('url-input').value;
    fetch(url).then(r => r.text()).then(html => {
        document.getElementById('output').innerHTML = html;
    });
}

// ============================================================
// Open redirect
// ============================================================
function handleRedirect() {
    const params = new URLSearchParams(window.location.search);
    const returnUrl = params.get('return');
    // Open redirect: no validation
    if (returnUrl) {
        window.location.href = returnUrl;
    }
}

// ============================================================
// Clickjacking (no frame protection)
// ============================================================
// This page can be framed - vulnerable to clickjacking
// Missing: X-Frame-Options header
// Missing: CSP frame-ancestors directive

// ============================================================
// Insecure WebSocket
// ============================================================
function connectWebSocket() {
    // Connecting without TLS
    const ws = new WebSocket('ws://websocket.example.com');

    ws.onmessage = function(event) {
        // XSS: rendering WebSocket message directly
        document.getElementById('messages').innerHTML += event.data;
    };

    // No authentication token sent
    ws.onopen = function() {
        ws.send(JSON.stringify({
            action: 'subscribe',
            channel: 'public'
        }));
    };
}

// ============================================================
// Hardcoded secrets in JS
// ============================================================
const CONFIG = {
    firebaseApiKey: "AIzaSyD-example-key-1234567890",
    firebaseAuthDomain: "myapp-12345.firebaseapp.com",
    firebaseProjectId: "myapp-12345",
    stripePublishableKey: "pk_live_abc123def456ghi789",
    googleAnalyticsId: "UA-123456789-1",
    sentryDsn: "https://abc123@o12345.ingest.sentry.io/12345"
};

// ============================================================
// Insecure postMessage handling
// ============================================================
window.addEventListener('message', function(event) {
    // No origin validation
    // XSS: executing code from untrusted messages
    if (event.data.action === 'eval') {
        eval(event.data.code);
    }
    if (event.data.action === 'navigate') {
        window.location.href = event.data.url;
    }
});

// ============================================================
// Clipboard XSS
// ============================================================
function copyToClipboard(text) {
    // Potential XSS via clipboard
    navigator.clipboard.writeText(text);
}

// ============================================================
// Weak CSP bypass techniques
// ============================================================
// This inline script bypasses CSP if 'unsafe-inline' is used
// <script>document.cookie = "session=stolen"</script>

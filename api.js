// ================= API.JS - VMS ENTERPRISE INTEGRATION CORE =================
// Menyatukan semua sistem: Index, Command Center, Client Portal, Worker
// Support offline mode, retry, queue, deduplication, safe fetch

// ================= KONSTANTA GLOBAL =================
const API_BASE_URL = "https://vms3modev4.sapammeded.workers.dev";
let GLOBAL_TOKEN = null;
let GLOBAL_LICENSE = null;
let GLOBAL_DEVICE_ID = null;
let __request_queue = [];
let __retry_queue = [];
let __dedup_cache = new Map();
let __is_online = navigator.onLine;

// ================= 1. UNIFIED API CALL =================
// Digunakan oleh semua halaman (index, commandcenter, client-portal)
async function unifiedApiCall(endpoint, method = 'GET', body = null, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    // Inject token untuk admin endpoints
    if (endpoint.startsWith('/admin/') && GLOBAL_TOKEN) {
        headers['x-token'] = GLOBAL_TOKEN;
    }
    
    // Inject license untuk client endpoints
    if (GLOBAL_LICENSE && (endpoint.startsWith('/validate-license') || 
        endpoint.startsWith('/client/') || 
        endpoint.startsWith('/checkin') || 
        endpoint.startsWith('/save') ||
        endpoint.startsWith('/report-violation') ||
        endpoint.startsWith('/request-'))) {
        headers['x-license'] = GLOBAL_LICENSE;
    }
    
    const fetchOptions = { method, headers };
    if (body) fetchOptions.body = JSON.stringify(body);
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, fetchOptions);
        const data = await response.json();
        
        // Normalize response (handle berbagai format)
        return normalizeResponse(data, response.ok);
    } catch (error) {
        console.error(`API Call Failed: ${endpoint}`, error);
        
        // Jika offline, coba dari cache
        if (!navigator.onLine) {
            const cached = getFromCache(endpoint);
            if (cached) return { ok: true, data: cached, fromCache: true };
        }
        
        return { ok: false, message: error.message, error: true };
    }
}

// ================= 2. NORMALIZE RESPONSE (Anti Chaos) =================
function normalizeResponse(data, isOk = true) {
    // Handle berbagai format response yang mungkin muncul
    let normalizedData = null;
    
    if (data === null || data === undefined) {
        normalizedData = null;
    } else if (Array.isArray(data)) {
        normalizedData = data;
    } else if (data.data !== undefined) {
        normalizedData = data.data;
    } else if (data.devices !== undefined && !data.data) {
        normalizedData = { devices: data.devices };
    } else if (data.companies !== undefined && !data.data) {
        normalizedData = { companies: data.companies };
    } else if (data.activities !== undefined && !data.data) {
        normalizedData = { activities: data.activities };
    } else if (data.invoices !== undefined && !data.data) {
        normalizedData = { invoices: data.invoices };
    } else if (data.visitors !== undefined && !data.data) {
        normalizedData = { visitors: data.visitors };
    } else {
        normalizedData = data;
    }
    
    return {
        ok: data.ok !== undefined ? data.ok : isOk,
        data: normalizedData,
        message: data.message || null,
        timestamp: data.timestamp || Date.now(),
        status: data.status || (isOk ? 200 : 400)
    };
}

// ================= 3. CACHE MANAGEMENT =================
const CACHE_STORAGE = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 menit

function setCache(key, data, ttl = CACHE_TTL) {
    CACHE_STORAGE.set(key, {
        data: data,
        expires: Date.now() + ttl
    });
}

function getFromCache(key) {
    const cached = CACHE_STORAGE.get(key);
    if (cached && cached.expires > Date.now()) {
        return cached.data;
    }
    if (cached) CACHE_STORAGE.delete(key);
    return null;
}

function invalidateCache(pattern) {
    for (const [key] of CACHE_STORAGE) {
        if (key.includes(pattern)) {
            CACHE_STORAGE.delete(key);
        }
    }
}

// ================= 4. RETRY & QUEUE SYSTEM =================
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000;

async function retryRequest(endpoint, method, body, retryCount = 0) {
    try {
        const result = await unifiedApiCall(endpoint, method, body);
        if (result.ok) return result;
        
        if (retryCount < MAX_RETRIES) {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * (retryCount + 1)));
            return retryRequest(endpoint, method, body, retryCount + 1);
        }
        return result;
    } catch (error) {
        if (retryCount < MAX_RETRIES) {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * (retryCount + 1)));
            return retryRequest(endpoint, method, body, retryCount + 1);
        }
        return { ok: false, message: error.message };
    }
}

function addToQueue(endpoint, method, body) {
    return new Promise((resolve) => {
        __request_queue.push({
            id: Date.now() + '-' + Math.random(),
            endpoint, method, body,
            resolve,
            retries: 0
        });
        processQueue();
    });
}

async function processQueue() {
    if (__request_queue.length === 0) return;
    if (!navigator.onLine) return;
    
    const item = __request_queue.shift();
    try {
        const result = await retryRequest(item.endpoint, item.method, item.body);
        item.resolve(result);
    } catch (error) {
        item.resolve({ ok: false, message: error.message });
    }
    
    setTimeout(processQueue, 500);
}

// ================= 5. DEDUPLICATION (Hash Payload) =================
function hashPayload(payload) {
    const str = JSON.stringify(payload);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString();
}

function isDuplicate(hash, ttl = 5000) {
    if (__dedup_cache.has(hash)) {
        const entry = __dedup_cache.get(hash);
        if (entry > Date.now() - ttl) return true;
    }
    __dedup_cache.set(hash, Date.now());
    return false;
}

// ================= 6. SMART SYNC (Offline First) =================
let syncInterval = null;
let pendingSyncs = [];

async function smartSync(data, priority = 'normal') {
    const hash = hashPayload(data);
    if (isDuplicate(hash)) return { ok: true, duplicated: true };
    
    pendingSyncs.push({ data, hash, priority, timestamp: Date.now() });
    
    if (navigator.onLine) {
        return executeSync();
    }
    
    return { ok: false, queued: true, message: 'Offline, saved to queue' };
}

async function executeSync() {
    if (!navigator.onLine) return { ok: false, message: 'Offline' };
    if (pendingSyncs.length === 0) return { ok: true, synced: 0 };
    
    // Sort by priority (scan > normal)
    pendingSyncs.sort((a, b) => {
        const priorityOrder = { scan: 0, normal: 1 };
        return (priorityOrder[a.priority] || 1) - (priorityOrder[b.priority] || 1);
    });
    
    const toSync = [...pendingSyncs];
    pendingSyncs = [];
    
    let synced = 0;
    for (const item of toSync) {
        const result = await unifiedApiCall('/save', 'POST', item.data);
        if (result.ok) synced++;
    }
    
    return { ok: true, synced, total: toSync.length };
}

// ================= 7. OFFLINE DETECTION & HANDLER =================
function initOfflineHandler() {
    window.addEventListener('online', async () => {
        __is_online = true;
        console.log('Back online, syncing...');
        await executeSync();
        showStatusIndicator('Online', 'success');
    });
    
    window.addEventListener('offline', () => {
        __is_online = false;
        console.log('Offline mode active');
        showStatusIndicator('Offline', 'warning');
    });
}

function showStatusIndicator(status, type) {
    let indicator = document.getElementById('vms-status-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'vms-status-indicator';
        indicator.style.position = 'fixed';
        indicator.style.bottom = '50px';
        indicator.style.right = '10px';
        indicator.style.padding = '4px 8px';
        indicator.style.borderRadius = '12px';
        indicator.style.fontSize = '10px';
        indicator.style.zIndex = '9999';
        indicator.style.fontWeight = 'bold';
        document.body.appendChild(indicator);
    }
    
    indicator.textContent = `🌐 ${status}`;
    indicator.style.backgroundColor = type === 'success' ? '#28a745' : type === 'warning' ? '#ffc107' : '#dc3545';
    indicator.style.color = type === 'warning' ? '#333' : 'white';
    
    setTimeout(() => {
        if (indicator && indicator.textContent === `🌐 ${status}`) {
            indicator.style.opacity = '0.5';
        }
    }, 3000);
}

// ================= 8. TOKEN & LICENSE MANAGEMENT =================
function setAuthToken(token) {
    GLOBAL_TOKEN = token;
    if (token) localStorage.setItem('vms_global_token', token);
    else localStorage.removeItem('vms_global_token');
}

function getAuthToken() {
    if (GLOBAL_TOKEN) return GLOBAL_TOKEN;
    GLOBAL_TOKEN = localStorage.getItem('vms_global_token');
    return GLOBAL_TOKEN;
}

function setLicenseKey(license) {
    GLOBAL_LICENSE = license;
    if (license) localStorage.setItem('vms_global_license', license);
    else localStorage.removeItem('vms_global_license');
}

function getLicenseKey() {
    if (GLOBAL_LICENSE) return GLOBAL_LICENSE;
    GLOBAL_LICENSE = localStorage.getItem('vms_global_license');
    return GLOBAL_LICENSE;
}

function setDeviceId(deviceId) {
    GLOBAL_DEVICE_ID = deviceId;
    if (deviceId) localStorage.setItem('vms_global_device_id', deviceId);
}

function getDeviceId() {
    if (GLOBAL_DEVICE_ID) return GLOBAL_DEVICE_ID;
    GLOBAL_DEVICE_ID = localStorage.getItem('vms_global_device_id');
    if (!GLOBAL_DEVICE_ID) {
        GLOBAL_DEVICE_ID = 'dev-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('vms_global_device_id', GLOBAL_DEVICE_ID);
    }
    return GLOBAL_DEVICE_ID;
}

// ================= 9. SAFE FETCH (Global) =================
async function safeFetch(url, options = {}) {
    const maxRetries = options.retries || 2;
    let lastError = null;
    
    for (let i = 0; i <= maxRetries; i++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), options.timeout || 10000);
            
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            let data;
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                data = await response.text();
            }
            
            return {
                ok: response.ok,
                status: response.status,
                data: data,
                headers: response.headers
            };
        } catch (error) {
            lastError = error;
            if (i < maxRetries) {
                await new Promise(r => setTimeout(r, 1000 * (i + 1)));
            }
        }
    }
    
    return {
        ok: false,
        status: 0,
        data: null,
        error: lastError?.message || 'Network error'
    };
}

// ================= 10. BATCH REQUEST =================
async function batchRequest(requests) {
    const results = await Promise.all(
        requests.map(async (req) => {
            return await unifiedApiCall(req.endpoint, req.method, req.body);
        })
    );
    return results;
}

// ================= 11. WEBHOOK / EVENT SYSTEM =================
const eventListeners = new Map();

function on(event, callback) {
    if (!eventListeners.has(event)) {
        eventListeners.set(event, []);
    }
    eventListeners.get(event).push(callback);
}

function emit(event, data) {
    const listeners = eventListeners.get(event);
    if (listeners) {
        listeners.forEach(callback => {
            try {
                callback(data);
            } catch (e) {
                console.error(`Event handler error for ${event}:`, e);
            }
        });
    }
}

// ================= 12. EXPORT MODULE =================
const VMS_API = {
    // Core
    call: unifiedApiCall,
    safeFetch: safeFetch,
    normalize: normalizeResponse,
    
    // Cache
    setCache: setCache,
    getCache: getFromCache,
    invalidateCache: invalidateCache,
    
    // Queue & Retry
    retry: retryRequest,
    queue: addToQueue,
    
    // Sync
    smartSync: smartSync,
    executeSync: executeSync,
    
    // Auth
    setToken: setAuthToken,
    getToken: getAuthToken,
    setLicense: setLicenseKey,
    getLicense: getLicenseKey,
    setDevice: setDeviceId,
    getDevice: getDeviceId,
    
    // Dedup
    hashPayload: hashPayload,
    isDuplicate: isDuplicate,
    
    // Batch & Events
    batch: batchRequest,
    on: on,
    emit: emit,
    
    // Status
    isOnline: () => __is_online,
    getQueueLength: () => __request_queue.length,
    getPendingSyncs: () => pendingSyncs.length
};

// ================= 13. AUTO INITIALIZATION =================
function initVMSApi() {
    GLOBAL_TOKEN = localStorage.getItem('vms_global_token');
    GLOBAL_LICENSE = localStorage.getItem('vms_global_license');
    GLOBAL_DEVICE_ID = localStorage.getItem('vms_global_device_id');
    
    initOfflineHandler();
    
    // Periodic sync
    if (syncInterval) clearInterval(syncInterval);
    syncInterval = setInterval(() => {
        if (navigator.onLine && pendingSyncs.length > 0) {
            executeSync();
        }
    }, 30000);
    
    console.log('VMS API Core initialized');
}

// Start API
initVMSApi();

// Export untuk penggunaan global
if (typeof window !== 'undefined') {
    window.VMS_API = VMS_API;
    window.unifiedApiCall = unifiedApiCall;
    window.safeFetch = safeFetch;
    window.smartSync = smartSync;
}

// Support CommonJS / ES Modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VMS_API;
}
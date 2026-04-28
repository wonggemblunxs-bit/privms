// ==================== VMS WORKER v3.0 - WITH PASSWORD MANAGEMENT ====================
// Cloudflare Worker untuk VMS SAPAM MEDED
// FIX: Single write, memory cache, no random login fail

// ==================== SAFE KV HELPERS ====================
async function safeArray(env, key, defaultValue = []) {
    try {
        const data = await getData(env, key);
        if (Array.isArray(data)) {
            return data;
        }
        console.warn(`[SAFE_ARRAY] ${key} bukan array, fallback ke []. Tipe: ${typeof data}`);
        return defaultValue;
    } catch (e) {
        console.error(`[SAFE_ARRAY] Error fetching ${key}:`, e);
        return defaultValue;
    }
}

async function safeObject(env, key, defaultValue = {}) {
    try {
        const data = await getData(env, key);
        if (data && typeof data === 'object' && !Array.isArray(data)) {
            return data;
        }
        console.warn(`[SAFE_OBJECT] ${key} bukan object, fallback ke {}`);
        return defaultValue;
    } catch (e) {
        console.error(`[SAFE_OBJECT] Error fetching ${key}:`, e);
        return defaultValue;
    }
}

function scopedKey(base, licenseKey) {
    return licenseKey ? `${base}:${licenseKey}` : base;
}

// ==================== GLOBAL SESSION CACHE ====================
if (!globalThis.__session_cache) {
    globalThis.__session_cache = {};
}

// ==================== GLOBAL RESET LOCK ====================
if (globalThis.__reset_lock === undefined) {
    globalThis.__reset_lock = false;
}

// ==================== MAIN HANDLER ====================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, x-token, authorization, Authorization, x-reset-confirm',
            'Content-Type': 'application/json'
        };
        
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders });
        }
        
        try {
            if (!globalThis.__vms_init_done) {
                let adminsCheck = await safeArray(env, 'admins');
                if (!adminsCheck || adminsCheck.length === 0) {
                    await forceInit(env);
                }
                globalThis.__vms_init_done = true;
            }
            
            if (!globalThis.__rate) globalThis.__rate = {};
            
            function checkRateLimit(deviceId) {
                const now = Date.now();
                const windowStart = now - 10000;
                if (!globalThis.__rate[deviceId]) {
                    globalThis.__rate[deviceId] = [];
                }
                globalThis.__rate[deviceId] = globalThis.__rate[deviceId].filter(t => t > windowStart);
                if (globalThis.__rate[deviceId].length >= 20) {
                    return false;
                }
                globalThis.__rate[deviceId].push(now);
                return true;
            }
            
            if (path === '/force-init' && request.method === 'POST') {
                await forceInit(env);
                return new Response(JSON.stringify({ ok: true, message: 'System initialized' }), { headers: corsHeaders });
            }
            
            if (path === '/' && request.method === 'GET') {
                return new Response(JSON.stringify({ 
                    status: 'online', 
                    version: 'v3.0 Enterprise Login Fixed',
                    timestamp: Date.now()
                }), { headers: corsHeaders });
            }
            
            // ==================== LOGIN FIX - SINGLE WRITE + CACHE ====================
            if (path === '/login' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { username, password } = body;
                
                if (Math.random() < 0.1) console.log(`[LOGIN] Attempt for username: ${username}`);
                
                let admins = await safeArray(env, 'admins');
                if (!admins || admins.length === 0) {
                    await forceInit(env);
                    admins = await safeArray(env, 'admins');
                }
                
                const index = admins.findIndex(a => a.username === username);
                if (index === -1) {
                    if (Math.random() < 0.1) console.log(`[LOGIN] User not found: ${username}`);
                    return new Response(JSON.stringify({ ok: false, error: 'User not found' }), { 
                        headers: corsHeaders, 
                        status: 401 
                    });
                }
                
                const admin = admins[index];
                if (Math.random() < 0.1) console.log(`[LOGIN] User found: ${admin.username}, role: ${admin.role}`);
                
                const hashedInputPassword = await sha256(password);
                let isValid = (hashedInputPassword === admin.password);
                
                if (!isValid && admin.password === password) {
                    if (Math.random() < 0.1) console.log(`[LOGIN] Plain text match, upgrading to hash...`);
                    isValid = true;
                    admins[index].password = hashedInputPassword;
                    await saveData(env, 'admins', admins);
                }
                
                if (!isValid) {
                    if (Math.random() < 0.1) console.log(`[LOGIN] Password invalid for: ${username}`);
                    return new Response(JSON.stringify({ ok: false, error: 'Invalid password' }), { 
                        headers: corsHeaders, 
                        status: 401 
                    });
                }
                
                // 🔥 SINGLE WRITE ONLY - no double save, no reset token before
                const token = 'vms_token_' + Date.now() + '_' + crypto.randomUUID();
                
                admins[index].token = token;
                admins[index].lastLogin = Date.now();
                
                await saveData(env, 'admins', admins);
                
                // 🔥 CACHE TO MEMORY (ANTI KV DELAY)
                globalThis.__session_cache[token] = {
                    username: admin.username,
                    role: admin.role,
                    id: admin.id
                };
                
                // Clean old cache (optional, keep last 100)
                const cacheKeys = Object.keys(globalThis.__session_cache);
                if (cacheKeys.length > 100) {
                    for (let i = 0; i < cacheKeys.length - 100; i++) {
                        delete globalThis.__session_cache[cacheKeys[i]];
                    }
                }
                
                if (Math.random() < 0.1) console.log(`[LOGIN] Success for: ${username}, token saved to KV + cache`);
                
                return new Response(JSON.stringify({
                    ok: true,
                    token: token,
                    username: admin.username,
                    role: admin.role
                }), { headers: corsHeaders });
            }
            
            // ==================== AUTH CHECK - MEMORY FIRST ====================
            async function checkAuth(headers, env) {
                let token = headers.get('x-token');
                
                if (!token) {
                    const authHeader = headers.get('authorization') || headers.get('Authorization');
                    if (authHeader && authHeader.startsWith('Bearer ')) {
                        token = authHeader.split(' ')[1];
                    }
                }
                
                if (!token) return null;
                
                const trimmedToken = (token || '').trim();
                if (!trimmedToken) return null;
                
                // 🔥 1. MEMORY CACHE FIRST (LANGSUNG TEMBUS)
                if (globalThis.__session_cache[trimmedToken]) {
                    if (Math.random() < 0.1) console.log(`[AUTH] Cache hit for token: ${trimmedToken.substring(0, 20)}...`);
                    return globalThis.__session_cache[trimmedToken];
                }
                
                // 🔥 2. KV FALLBACK (JIKA CACHE MISS)
                const admins = await safeArray(env, 'admins');
                const admin = admins.find(a => a.token && a.token.trim() === trimmedToken);
                
                if (admin && admin.lastLogin && (Date.now() - admin.lastLogin) < 24 * 3600000) {
                    const session = {
                        username: admin.username,
                        role: admin.role,
                        id: admin.id
                    };
                    // Simpan ke cache untuk request berikutnya
                    globalThis.__session_cache[trimmedToken] = session;
                    if (Math.random() < 0.1) console.log(`[AUTH] Cache miss, loaded from KV for: ${admin.username}`);
                    return session;
                }
                
                return null;
            }
            
            const auth = await checkAuth(request.headers, env);
            
            const protectedPaths = [
                '/admin/stats', '/admin/companies', '/admin/devices', 
                '/admin/activity', '/admin/invoices', '/admin/device-requests',
                '/generate-license', '/renew-license', '/update-package',
                '/approve-device', '/delete-device', '/delete-company',
                '/mark-invoice-paid', '/admin/users', '/admin/add-user', 
                '/admin/delete-user', '/admin/settings', '/admin/company/',
                '/approve-device-request', '/admin/violations', '/admin/reset-system',
                '/admin/reset-company', '/admin/change-password', '/admin/reset-password'
            ];
            
            if (protectedPaths.some(p => path === p || path.startsWith('/admin/company/')) && !auth) {
                return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { 
                    headers: corsHeaders, 
                    status: 401 
                });
            }
            
            // ==================== CHANGE PASSWORD (SELF SERVICE) ====================
            if (path === '/admin/change-password' && request.method === 'POST') {
                if (!auth) {
                    return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { headers: corsHeaders, status: 401 });
                }

                const body = await request.json().catch(() => ({}));
                const { oldPassword, newPassword } = body;

                if (!oldPassword || !newPassword || newPassword.length < 6) {
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_INPUT' }), { headers: corsHeaders });
                }

                let admins = await safeArray(env, 'admins');
                const index = admins.findIndex(a => a.username === auth.username);

                if (index === -1) {
                    return new Response(JSON.stringify({ ok: false, error: 'USER_NOT_FOUND' }), { headers: corsHeaders });
                }

                const admin = admins[index];

                const oldHash = await sha256(oldPassword);
                if (admin.password !== oldHash) {
                    return new Response(JSON.stringify({ ok: false, error: 'OLD_PASSWORD_WRONG' }), { headers: corsHeaders });
                }

                const newHash = await sha256(newPassword);

                if (newHash === admin.password) {
                    return new Response(JSON.stringify({ ok: false, error: 'PASSWORD_SAME' }), { headers: corsHeaders });
                }

                admins[index].password = newHash;
                admins[index].token = null;

                await saveData(env, 'admins', admins);

                // clear session cache biar token lama invalid
                globalThis.__session_cache = {};

                return new Response(JSON.stringify({
                    ok: true,
                    message: 'Password updated, please login again'
                }), { headers: corsHeaders });
            }
            
            // ==================== RESET PASSWORD (SUPER ADMIN ONLY) ====================
            if (path === '/admin/reset-password' && request.method === 'POST') {
                if (!auth || auth.role !== 'SUPER_ADMIN') {
                    return new Response(JSON.stringify({ ok: false, error: 'FORBIDDEN' }), { headers: corsHeaders, status: 403 });
                }

                const body = await request.json().catch(() => ({}));
                const { username, newPassword } = body;

                if (!username || !newPassword || newPassword.length < 6) {
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_INPUT' }), { headers: corsHeaders });
                }

                let admins = await safeArray(env, 'admins');
                const index = admins.findIndex(a => a.username === username);

                if (index === -1) {
                    return new Response(JSON.stringify({ ok: false, error: 'USER_NOT_FOUND' }), { headers: corsHeaders });
                }

                const newHash = await sha256(newPassword);

                admins[index].password = newHash;
                admins[index].token = null;

                await saveData(env, 'admins', admins);

                // clear cache
                globalThis.__session_cache = {};

                return new Response(JSON.stringify({
                    ok: true,
                    message: 'Password reset success'
                }), { headers: corsHeaders });
            }
            
            // ==================== RESET SYSTEM ====================
            if (path === '/admin/reset-system' && request.method === 'POST') {
                // SUPER_ADMIN only guard
                if (!auth || auth.role !== 'SUPER_ADMIN') {
                    return new Response(JSON.stringify({
                        ok: false,
                        error: 'FORBIDDEN'
                    }), { headers: corsHeaders, status: 403 });
                }
                
                // Prevent double reset execution
                if (globalThis.__reset_lock) {
                    return new Response(JSON.stringify({
                        ok: false,
                        error: 'RESET_IN_PROGRESS'
                    }), { headers: corsHeaders });
                }
                
                globalThis.__reset_lock = true;
                
                try {
                    const body = await request.json().catch(() => ({}));

                    // flexible confirm: support body OR header
                    if (
                        !body ||
                        (body.confirm !== 'RESET_TOTAL' &&
                         request.headers.get('x-reset-confirm') !== 'RESET_TOTAL')
                    ) {
                        return new Response(JSON.stringify({
                            ok: false,
                            error: 'CONFIRMATION_REQUIRED'
                        }), { headers: corsHeaders });
                    }
                    
                    if (Math.random() < 0.1) console.log('[RESET_SYSTEM]', {
                        by: auth?.username || 'unknown',
                        time: Date.now()
                    });
                    
                    // Clear session cache
                    globalThis.__session_cache = {};
                    
                    let admins = await safeArray(env, 'admins');
                    
                    // 🔒 RESET PATCH: Only reset tokens, NEVER touch passwords
                    for (let i = 0; i < admins.length; i++) {
                        admins[i].token = null;
                    }
                    await saveData(env, 'admins', admins);
                    
                    const oldCompanies = await safeArray(env, 'companies');
                    
                    const scopedKeysList = [
                        'devices',
                        'visitors',
                        'logs',
                        'activities',
                        'violations',
                        'anti_nakal_reports'
                    ];
                    
                    for (const company of oldCompanies) {
                        if (!company.licenseKey) continue;
                        
                        for (const baseKey of scopedKeysList) {
                            const key = scopedKey(baseKey, company.licenseKey);
                            
                            if (baseKey === 'visitors') {
                                await saveData(env, key, {});
                            } else {
                                await saveData(env, key, []);
                            }
                        }
                    }
                    
                    await saveData(env, 'companies', []);
                    await saveData(env, 'invoices', []);
                    await saveData(env, 'device_requests', []);
                    await saveData(env, 'users_from_clients', []);
                    await saveData(env, 'visitors', {});
                    await saveData(env, 'activities', []);
                    await saveData(env, 'logs', []);
                    await saveData(env, 'anti_nakal_reports', []);
                    await saveData(env, 'violations', []);
                    await saveData(env, 'devices', []);
                    
                    // 🔒 RESET PATCH: Force init WITHOUT password override
                    await forceInitNoPasswordOverride(env);
                    
                    return new Response(JSON.stringify({
                        ok: true,
                        message: 'SYSTEM RESET SUCCESS. Login again.'
                    }), { headers: corsHeaders });
                    
                } finally {
                    globalThis.__reset_lock = false;
                }
            }
            
            // ==================== RESET PER COMPANY ====================
            if (path === '/admin/reset-company' && request.method === 'POST') {
                // SUPER_ADMIN only guard
                if (!auth || auth.role !== 'SUPER_ADMIN') {
                    return new Response(JSON.stringify({
                        ok: false,
                        error: 'FORBIDDEN'
                    }), { headers: corsHeaders, status: 403 });
                }
                
                const body = await request.json().catch(() => ({}));
                const { companyId } = body;

                if (!companyId) {
                    return new Response(JSON.stringify({
                        ok: false,
                        error: 'companyId required'
                    }), { headers: corsHeaders });
                }

                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.id === companyId);

                if (!company) {
                    return new Response(JSON.stringify({
                        ok: false,
                        error: 'Company not found'
                    }), { headers: corsHeaders });
                }

                const licenseKey = company.licenseKey;

                const scopedKeys = [
                    'devices',
                    'visitors',
                    'logs',
                    'activities',
                    'violations',
                    'anti_nakal_reports'
                ];

                for (const base of scopedKeys) {
                    const key = scopedKey(base, licenseKey);

                    if (base === 'visitors') {
                        await saveData(env, key, {});
                    } else {
                        await saveData(env, key, []);
                    }
                }

                // global cleanup for this company's data
                await saveData(env, 'activities', []);
                await saveData(env, 'logs', []);

                company.currentDevices = 0;
                await saveData(env, 'companies', companies);

                if (Math.random() < 0.1) console.log('[RESET_COMPANY]', {
                    companyId,
                    by: auth?.username || 'unknown',
                    time: Date.now()
                });

                return new Response(JSON.stringify({
                    ok: true,
                    message: 'Company reset success'
                }), { headers: corsHeaders });
            }
            
            const VIOLATION_SCORES = {
                LIMIT_VISITOR: 2,
                LIMIT_SCAN: 2,
                RATE_SPAM: 3,
                INVALID_DATA: 2,
                DUPLICATE_ABUSE: 1
            };
            
            async function addViolation(licenseKey, type, details, metadata = {}) {
                try {
                    const violationsKey = scopedKey('violations', licenseKey);
                    let violations = await safeArray(env, violationsKey);
                    
                    const violation = {
                        id: generateId(),
                        licenseKey: licenseKey,
                        type: type,
                        score: VIOLATION_SCORES[type] || 1,
                        details: details,
                        metadata: metadata,
                        timestamp: Date.now()
                    };
                    
                    violations.push(violation);
                    await saveData(env, violationsKey, violations.slice(-10000));
                    
                    return violation;
                } catch (e) {
                    console.error('[VIOLATION] Error adding violation:', e);
                    return null;
                }
            }
            
            async function getViolationStatus(licenseKey) {
                try {
                    const violationsKey = scopedKey('violations', licenseKey);
                    const violations = await safeArray(env, violationsKey);
                    const licenseViolations = violations.filter(v => v.licenseKey === licenseKey);
                    
                    const totalScore = licenseViolations.reduce((sum, v) => sum + (v.score || 1), 0);
                    const recentViolations = licenseViolations.filter(v => v.timestamp > Date.now() - 7 * 86400000);
                    const recentScore = recentViolations.reduce((sum, v) => sum + (v.score || 1), 0);
                    
                    let status = 'NORMAL';
                    let recommendation = null;
                    
                    if (totalScore >= 20 || recentScore >= 10) {
                        status = 'CRITICAL';
                        recommendation = 'Review required immediately';
                    } else if (totalScore >= 10 || recentScore >= 5) {
                        status = 'WARNING';
                        recommendation = 'Monitor closely';
                    } else if (totalScore >= 5 || recentScore >= 3) {
                        status = 'ATTENTION';
                        recommendation = 'Investigate patterns';
                    }
                    
                    const violationsByType = {};
                    for (const v of licenseViolations) {
                        violationsByType[v.type] = (violationsByType[v.type] || 0) + 1;
                    }
                    
                    return {
                        licenseKey: licenseKey,
                        status: status,
                        totalScore: totalScore,
                        recentScore: recentScore,
                        totalViolations: licenseViolations.length,
                        recentViolations: recentViolations.length,
                        violationsByType: violationsByType,
                        recommendation: recommendation,
                        lastViolationAt: licenseViolations.length > 0 ? Math.max(...licenseViolations.map(v => v.timestamp)) : null
                    };
                } catch (e) {
                    console.error('[VIOLATION] Error getting status:', e);
                    return { licenseKey, status: 'UNKNOWN', totalScore: 0 };
                }
            }
            
            // ==================== CLIENT ENDPOINTS ====================
            if (path === '/validate-license' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { licenseKey, deviceId, deviceName, meta } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, message: 'License key required' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Invalid license key validation attempt', { deviceId });
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license key' }), { headers: corsHeaders });
                }
                
                const isExpired = company.expiredAt < Date.now();
                if (isExpired) {
                    return new Response(JSON.stringify({ 
                        ok: false, 
                        message: 'License expired',
                        company: { ...company, status: 'EXPIRED' }
                    }), { headers: corsHeaders });
                }
                
                const devicesKey = scopedKey('devices', licenseKey);
                let devices = await safeArray(env, devicesKey);
                const companyDevices = devices.filter(d => d.licenseKey === licenseKey && d.status !== 'DELETED');
                const currentDeviceCount = companyDevices.length;
                
                let status = 'ACTIVE';
                if (currentDeviceCount >= company.maxDevices) {
                    status = 'PENDING_APPROVAL';
                }
                
                let device = devices.find(d => d.deviceId === deviceId && d.licenseKey === licenseKey);
                if (device) {
                    device.lastSeen = Date.now();
                    device.deviceName = deviceName || device.deviceName;
                    device.meta = meta;
                } else {
                    device = {
                        deviceId: deviceId,
                        deviceName: deviceName || deviceId,
                        licenseKey: licenseKey,
                        companyId: company.id,
                        companyName: company.companyName,
                        status: status,
                        firstSeen: Date.now(),
                        lastSeen: Date.now(),
                        meta: meta,
                        violations: [],
                        sessions: []
                    };
                    devices.push(device);
                }
                
                await saveData(env, devicesKey, devices);
                
                company.currentDevices = devices.filter(d => d.licenseKey === licenseKey && d.status === 'ACTIVE').length;
                await saveData(env, 'companies', companies);
                
                const violationStatus = await getViolationStatus(licenseKey);
                
                return new Response(JSON.stringify({
                    ok: true,
                    status: status,
                    company: {
                        id: company.id,
                        name: company.companyName,
                        package: company.package,
                        maxDevices: company.maxDevices,
                        currentDevices: company.currentDevices,
                        expiredAt: company.expiredAt
                    },
                    device: device,
                    violationStatus: violationStatus
                }), { headers: corsHeaders });
            }
            
            if (path === '/client/devices' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { licenseKey } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, devices: [] }), { headers: corsHeaders });
                }
                
                const devicesKey = scopedKey('devices', licenseKey);
                const devices = await safeArray(env, devicesKey);
                const companyDevices = devices.filter(d => d.licenseKey === licenseKey && d.status !== 'DELETED');
                
                return new Response(JSON.stringify({ ok: true, devices: companyDevices }), { headers: corsHeaders });
            }
            
            if (path === '/site-names' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { licenseKey, sites, customSites } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, error: 'License key required' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Invalid license' }), { headers: corsHeaders });
                }
                
                let siteNames = await safeObject(env, 'site_names');
                
                if (sites) {
                    for (const [key, value] of Object.entries(sites)) {
                        if (value && value.trim()) {
                            siteNames[key] = value.trim();
                        }
                    }
                }
                
                if (customSites) {
                    if (!siteNames.customSites) siteNames.customSites = {};
                    for (const [key, value] of Object.entries(customSites)) {
                        if (value && value.trim()) {
                            siteNames.customSites[key] = value.trim();
                        }
                    }
                }
                
                await saveData(env, 'site_names', siteNames);
                
                return new Response(JSON.stringify({
                    ok: true,
                    sites: siteNames,
                    customSites: siteNames.customSites || {}
                }), { headers: corsHeaders });
            }
            
            if (path === '/site-names' && request.method === 'GET') {
                const siteNames = await safeObject(env, 'site_names');
                return new Response(JSON.stringify({
                    ok: true,
                    sites: siteNames || {},
                    customSites: (siteNames && siteNames.customSites) || {}
                }), { headers: corsHeaders });
            }
            
            if (path === '/checkin' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { licenseKey, deviceId, action, location, qrData } = body;
                
                if (!licenseKey || !deviceId) {
                    return new Response(JSON.stringify({ ok: false, error: 'License key and device ID required' }), { headers: corsHeaders });
                }
                
                if (!checkRateLimit(deviceId)) {
                    return new Response(JSON.stringify({ ok: false, error: 'RATE_LIMIT' }), { headers: corsHeaders });
                }
                
                const devicesKey = scopedKey('devices', licenseKey);
                let devices = await safeArray(env, devicesKey);
                const device = devices.find(d => d.deviceId === deviceId && d.licenseKey === licenseKey);
                if (!device) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Device not registered for check-in', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_NOT_REGISTERED' }), { headers: corsHeaders });
                }
                
                if (device.status === 'BANNED') {
                    await addViolation(licenseKey, 'RATE_SPAM', 'Attempted check-in from banned device', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_BANNED' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                if (!company || company.expiredAt < Date.now()) {
                    return new Response(JSON.stringify({ ok: false, error: 'License invalid or expired' }), { headers: corsHeaders });
                }
                
                const activitiesKey = scopedKey('activities', licenseKey);
                let activities = await safeArray(env, activitiesKey);
                const activity = {
                    id: generateId(),
                    deviceId: deviceId,
                    deviceName: device.deviceName,
                    licenseKey: licenseKey,
                    companyId: company.id,
                    companyName: company.companyName,
                    action: action,
                    location: location || null,
                    qrData: qrData || null,
                    timestamp: Date.now(),
                    type: action === 'IN' ? 'CHECK_IN' : 'CHECK_OUT'
                };
                activities.unshift(activity);
                
                if (activities.length > 5000) {
                    activities = activities.slice(0, 5000);
                }
                await saveData(env, activitiesKey, activities);
                
                device.lastSeen = Date.now();
                await saveData(env, devicesKey, devices);
                
                const logsKey = scopedKey('logs', licenseKey);
                let logs = await safeArray(env, logsKey);
                logs.unshift({
                    id: generateId(),
                    type: action === 'IN' ? 'CHECK_IN' : 'CHECK_OUT',
                    licenseKey: licenseKey,
                    companyId: company.id,
                    companyName: company.companyName,
                    deviceId: deviceId,
                    deviceName: device.deviceName,
                    location: location,
                    timestamp: Date.now()
                });
                
                if (logs.length > 10000) {
                    logs = logs.slice(0, 10000);
                }
                await saveData(env, logsKey, logs);
                
                const violationStatus = await getViolationStatus(licenseKey);
                
                return new Response(JSON.stringify({ 
                    ok: true, 
                    activity: activity,
                    violationStatus: violationStatus
                }), { headers: corsHeaders });
            }
            
            if (path === '/save' && request.method === 'POST') {
                let body;
                try {
                    body = await request.json();
                } catch(e) {
                    body = {};
                }
                
                const { licenseKey, deviceId } = body;
                
                if (!licenseKey || !deviceId) {
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_REQUEST' }), { headers: corsHeaders });
                }
                
                if (!checkRateLimit(deviceId)) {
                    return new Response(JSON.stringify({ ok: false, error: 'RATE_LIMIT' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Invalid license key in /save', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_LICENSE' }), { headers: corsHeaders });
                }
                
                if (company.expiredAt < Date.now()) {
                    return new Response(JSON.stringify({ ok: false, error: 'LICENSE_EXPIRED' }), { headers: corsHeaders });
                }
                
                const devicesKey = scopedKey('devices', licenseKey);
                let devices = await safeArray(env, devicesKey);
                const device = devices.find(d => d.deviceId === deviceId && d.licenseKey === licenseKey);
                
                if (!device) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Device not registered in /save', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_NOT_REGISTERED' }), { headers: corsHeaders });
                }
                
                if (device.status === 'BANNED') {
                    await addViolation(licenseKey, 'RATE_SPAM', 'Banned device attempted /save', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_BANNED' }), { headers: corsHeaders });
                }
                
                const isSuspended = (device.status === 'SUSPENDED');
                
                const packageType = company.package || 'DEMO';
                let maxAllowed = Infinity;
                if (packageType === 'DEMO') maxAllowed = 5;
                else if (packageType === 'BASIC') maxAllowed = 150;
                else if (packageType === 'PRO') maxAllowed = Infinity;
                
                const visitorsKey = scopedKey('visitors', licenseKey);
                let allVisitors = await safeObject(env, visitorsKey);
                const companyVisitors = Object.values(allVisitors).filter(v => v.licenseKey === licenseKey);
                const currentVisitorCount = companyVisitors.length;
                
                if (body.visitors && Object.keys(body.visitors).length > 0 && !isSuspended) {
                    let newVisitorCount = 0;
                    
                    for (const [key, value] of Object.entries(body.visitors)) {
                        if (currentVisitorCount + newVisitorCount >= maxAllowed) {
                            await addViolation(licenseKey, 'LIMIT_VISITOR', `Visitor limit would be exceeded in /save`, {
                                currentCount: currentVisitorCount,
                                attemptedAdd: newVisitorCount,
                                maxAllowed: maxAllowed
                            });
                            break;
                        }
                        
                        const safeVisitor = {
                            nama: (value.nama || "").substring(0, 200),
                            perusahaan: (value.perusahaan || "").substring(0, 200),
                            kategori: (value.kategori || "").substring(0, 200),
                            tujuan: (value.tujuan || "").substring(0, 200),
                            pic: (value.pic || "").substring(0, 200),
                            dept: (value.dept || "").substring(0, 200),
                            expDate: value.expDate || "",
                            licenseKey: licenseKey,
                            companyId: company.id,
                            companyName: company.companyName
                        };
                        
                        allVisitors[key] = { ...allVisitors[key], ...safeVisitor, lastSync: Date.now() };
                        newVisitorCount++;
                    }
                    
                    if (newVisitorCount > 0) {
                        await saveData(env, visitorsKey, allVisitors);
                    }
                }
                
                if (body.logs && body.logs.length > 0) {
                    const allowedLogTypes = ['CHECK_IN', 'CHECK_OUT', 'REGISTER', 'WALK_IN'];
                    let validLogs = [];
                    
                    for (const log of body.logs) {
                        if (allowedLogTypes.includes(log.type) || allowedLogTypes.includes(log.action)) {
                            validLogs.push({
                                ...log,
                                licenseKey: licenseKey,
                                companyId: company.id,
                                companyName: company.companyName,
                                deviceId: deviceId,
                                validatedAt: Date.now()
                            });
                        }
                    }
                    
                    if (validLogs.length > 0) {
                        const logsKey = scopedKey('logs', licenseKey);
                        let allLogs = await safeArray(env, logsKey);
                        allLogs = [...validLogs, ...allLogs];
                        
                        if (allLogs.length > 10000) {
                            allLogs = allLogs.slice(0, 10000);
                        }
                        await saveData(env, logsKey, allLogs);
                    }
                }
                
                if (body.anti) {
                    const reportsKey = scopedKey('anti_nakal_reports', licenseKey);
                    let reports = await safeArray(env, reportsKey);
                    reports.unshift({
                        ...body.anti,
                        deviceId: deviceId,
                        deviceName: device.deviceName,
                        site: body.site,
                        licenseKey: licenseKey,
                        timestamp: Date.now()
                    });
                    
                    if (reports.length > 5000) {
                        reports = reports.slice(0, 5000);
                    }
                    await saveData(env, reportsKey, reports);
                }
                
                device.lastSeen = Date.now();
                await saveData(env, devicesKey, devices);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/violation-status' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { licenseKey } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, error: 'License key required' }), { headers: corsHeaders });
                }
                
                const status = await getViolationStatus(licenseKey);
                return new Response(JSON.stringify({ ok: true, status: status }), { headers: corsHeaders });
            }
            
            if (path === '/report-violation' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { licenseKey, deviceId, violationType, details, location } = body;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license' }), { headers: corsHeaders });
                }
                
                const devicesKey = scopedKey('devices', licenseKey);
                let devices = await safeArray(env, devicesKey);
                const device = devices.find(d => d.deviceId === deviceId);
                if (!device) {
                    return new Response(JSON.stringify({ ok: false, message: 'Device not found' }), { headers: corsHeaders });
                }
                
                const violation = await addViolation(licenseKey, violationType, details, {
                    deviceId: deviceId,
                    deviceName: device.deviceName,
                    location: location
                });
                
                if (!device.violations) device.violations = [];
                device.violations.unshift(violation);
                
                const violationCount = device.violations.length;
                let deviceStatus = device.status;
                
                if (violationCount >= 5) {
                    deviceStatus = 'BANNED';
                } else if (violationCount >= 3) {
                    deviceStatus = 'SUSPENDED';
                }
                
                device.status = deviceStatus;
                await saveData(env, devicesKey, devices);
                
                const activitiesKey = scopedKey('activities', licenseKey);
                let activities = await safeArray(env, activitiesKey);
                activities.unshift({
                    id: generateId(),
                    ...violation,
                    type: 'VIOLATION_REPORTED'
                });
                
                if (activities.length > 5000) {
                    activities = activities.slice(0, 5000);
                }
                await saveData(env, activitiesKey, activities);
                
                return new Response(JSON.stringify({
                    ok: true,
                    violation: violation,
                    deviceStatus: deviceStatus,
                    violationCount: violationCount
                }), { headers: corsHeaders });
            }
            
            if (path === '/admin/violations' && request.method === 'GET') {
                if (!auth) {
                    return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { 
                        headers: corsHeaders, 
                        status: 401 
                    });
                }
                
                const urlParams = new URL(request.url).searchParams;
                const licenseKey = urlParams.get('licenseKey');
                const limit = parseInt(urlParams.get('limit') || '100');
                
                let violations = [];
                if (licenseKey) {
                    const violationsKey = scopedKey('violations', licenseKey);
                    violations = await safeArray(env, violationsKey);
                    violations = violations.filter(v => v.licenseKey === licenseKey);
                } else {
                    const companiesList = await safeArray(env, 'companies');
                    for (const comp of companiesList) {
                        if (!comp.licenseKey) continue;
                        const vKey = scopedKey('violations', comp.licenseKey);
                        const compViolations = await safeArray(env, vKey);
                        violations.push(...compViolations);
                    }
                }
                
                violations = violations.slice(0, limit);
                
                const summary = {};
                for (const v of violations) {
                    if (!summary[v.licenseKey]) {
                        summary[v.licenseKey] = {
                            totalScore: 0,
                            counts: {}
                        };
                    }
                    summary[v.licenseKey].totalScore += v.score || 1;
                    summary[v.licenseKey].counts[v.type] = (summary[v.licenseKey].counts[v.type] || 0) + 1;
                }
                
                return new Response(JSON.stringify({
                    ok: true,
                    violations: violations,
                    summary: summary,
                    total: violations.length
                }), { headers: corsHeaders });
            }
            
            if (path === '/request-approval' && request.method === 'POST') {
                const requestBody = await request.json().catch(() => ({}));
                const { licenseKey, deviceId, deviceName, reason } = requestBody;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license' }), { headers: corsHeaders });
                }
                
                const devicesKey = scopedKey('devices', licenseKey);
                let devices = await safeArray(env, devicesKey);
                const targetDevice = devices.find(d => d.deviceId === deviceId);
                if (targetDevice) {
                    targetDevice.approvalRequest = {
                        requestedAt: Date.now(),
                        reason: reason,
                        status: 'PENDING'
                    };
                    targetDevice.status = 'PENDING_APPROVAL';
                    await saveData(env, devicesKey, devices);
                }
                
                return new Response(JSON.stringify({ ok: true, message: 'Approval request sent' }), { headers: corsHeaders });
            }
            
            if (path === '/request-device' && request.method === 'POST') {
                const requestBody = await request.json().catch(() => ({}));
                const { licenseKey, deviceName, reason } = requestBody;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license' }), { headers: corsHeaders });
                }
                
                let fee = 0;
                if (company.package === 'BASIC') {
                    const settings = await safeObject(env, 'settings');
                    fee = (settings?.pricing?.BASIC?.extraDeviceFee || 50000);
                }
                
                let deviceRequests = await safeArray(env, 'device_requests');
                
                if (!Array.isArray(deviceRequests)) {
                    deviceRequests = [];
                }
                
                const newRequest = {
                    id: generateId(),
                    licenseKey: licenseKey,
                    companyId: company.id,
                    companyName: company.companyName,
                    deviceName: deviceName,
                    reason: reason,
                    fee: fee,
                    status: 'PENDING',
                    requestedAt: Date.now()
                };
                
                deviceRequests.push(newRequest);
                await saveData(env, 'device_requests', deviceRequests);
                
                return new Response(JSON.stringify({
                    ok: true,
                    requestId: newRequest.id,
                    fee: fee,
                    message: fee > 0 ? `Fee Rp ${fee.toLocaleString()} akan ditagihkan` : 'Request sent, waiting approval'
                }), { headers: corsHeaders });
            }
            
            if (path === '/admin/stats' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                const invoices = await safeArray(env, 'invoices');
                
                let allDevices = [];
                let allViolations = [];
                
                for (const comp of companies) {
                    if (!comp.licenseKey) continue;
                    const devKey = scopedKey('devices', comp.licenseKey);
                    const devs = await safeArray(env, devKey);
                    allDevices.push(...devs);
                    
                    const violKey = scopedKey('violations', comp.licenseKey);
                    const viols = await safeArray(env, violKey);
                    allViolations.push(...viols);
                }
                
                const now = Date.now();
                const last30Days = now - 30 * 86400000;
                
                const stats = {
                    companies: {
                        total: companies.length,
                        active: companies.filter(c => c.expiredAt > now).length,
                        byPackage: {
                            DEMO: companies.filter(c => c.package === 'DEMO').length,
                            BASIC: companies.filter(c => c.package === 'BASIC').length,
                            PRO: companies.filter(c => c.package === 'PRO').length
                        }
                    },
                    devices: {
                        total: allDevices.length,
                        active: allDevices.filter(d => d.status === 'ACTIVE').length,
                        pending: allDevices.filter(d => d.status === 'PENDING_APPROVAL').length,
                        suspended: allDevices.filter(d => d.status === 'SUSPENDED').length,
                        banned: allDevices.filter(d => d.status === 'BANNED').length
                    },
                    violations: {
                        total: allViolations.length,
                        last7Days: allViolations.filter(v => v.timestamp > now - 7 * 86400000).length,
                        last30Days: allViolations.filter(v => v.timestamp > last30Days).length,
                        byType: allViolations.reduce((acc, v) => {
                            acc[v.type] = (acc[v.type] || 0) + 1;
                            return acc;
                        }, {})
                    },
                    revenue: {
                        last30Days: invoices.filter(i => i.status === 'PAID' && i.paidAt > last30Days).reduce((sum, i) => sum + i.amount, 0)
                    }
                };
                
                return new Response(JSON.stringify(stats), { headers: corsHeaders });
            }
            
            if (path === '/admin/companies' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                return new Response(JSON.stringify(companies), { headers: corsHeaders });
            }
            
            if (path.startsWith('/admin/company/') && request.method === 'GET') {
                const companyId = path.split('/').pop();
                const companies = await safeArray(env, 'companies');
                
                const company = companies.find(c => c.id === companyId);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { 
                        headers: corsHeaders, 
                        status: 404 
                    });
                }
                
                const devicesKey = scopedKey('devices', company.licenseKey);
                const companyDevices = await safeArray(env, devicesKey);
                
                const vKey = scopedKey('violations', company.licenseKey);
                const companyViolations = await safeArray(env, vKey);
                
                return new Response(JSON.stringify({
                    ...company,
                    devices: companyDevices,
                    violations: companyViolations,
                    violationStatus: await getViolationStatus(company.licenseKey),
                    stats: {
                        totalDevices: companyDevices.length,
                        activeDevices: companyDevices.filter(d => d.status === 'ACTIVE').length,
                        totalViolations: companyViolations.length
                    }
                }), { headers: corsHeaders });
            }
            
            if (path === '/admin/devices' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                let allDevices = [];
                
                for (const comp of companies) {
                    if (!comp.licenseKey) continue;
                    const devKey = scopedKey('devices', comp.licenseKey);
                    const devs = await safeArray(env, devKey);
                    allDevices.push(...devs);
                }
                
                return new Response(JSON.stringify(allDevices), { headers: corsHeaders });
            }
            
            if (path === '/admin/activity' && request.method === 'GET') {
                const urlParams = new URL(request.url).searchParams;
                const limit = parseInt(urlParams.get('limit') || '500');
                
                const companies = await safeArray(env, 'companies');
                let allActivities = [];
                
                for (const comp of companies) {
                    if (!comp.licenseKey) continue;
                    const actKey = scopedKey('activities', comp.licenseKey);
                    const acts = await safeArray(env, actKey);
                    allActivities.push(...acts);
                }
                
                return new Response(JSON.stringify(allActivities.slice(0, limit)), { headers: corsHeaders });
            }
            
            if (path === '/admin/invoices' && request.method === 'GET') {
                const invoices = await safeArray(env, 'invoices');
                return new Response(JSON.stringify(invoices), { headers: corsHeaders });
            }
            
            if (path === '/admin/device-requests' && request.method === 'GET') {
                const urlParams = new URL(request.url).searchParams;
                const status = urlParams.get('status');
                
                let deviceRequests = await safeArray(env, 'device_requests');
                if (status) {
                    deviceRequests = deviceRequests.filter(r => r.status === status);
                }
                
                return new Response(JSON.stringify(deviceRequests), { headers: corsHeaders });
            }
            
            if (path === '/approve-device-request' && request.method === 'POST') {
                const requestBody = await request.json().catch(() => ({}));
                const { requestId, approve, notes } = requestBody;
                
                let deviceRequests = await safeArray(env, 'device_requests');
                const targetRequest = deviceRequests.find(r => r.id === requestId);
                
                if (!targetRequest) {
                    return new Response(JSON.stringify({ ok: false, error: 'Request not found' }), { headers: corsHeaders });
                }
                
                if (!approve) {
                    targetRequest.status = 'REJECTED';
                    targetRequest.rejectedAt = Date.now();
                    targetRequest.rejectNotes = notes;
                    await saveData(env, 'device_requests', deviceRequests);
                    return new Response(JSON.stringify({ ok: true, request: targetRequest }), { headers: corsHeaders });
                }
                
                const invoices = await safeArray(env, 'invoices');
                const invoice = {
                    id: generateId(),
                    requestId: targetRequest.id,
                    companyId: targetRequest.companyId,
                    companyName: targetRequest.companyName,
                    type: 'DEVICE_ADDITION',
                    amount: targetRequest.fee,
                    deviceName: targetRequest.deviceName,
                    status: 'UNPAID',
                    createdAt: Date.now()
                };
                invoices.push(invoice);
                await saveData(env, 'invoices', invoices);
                
                targetRequest.status = 'WAITING_PAYMENT';
                targetRequest.invoiceId = invoice.id;
                await saveData(env, 'device_requests', deviceRequests);
                
                return new Response(JSON.stringify({
                    ok: true,
                    invoiceId: invoice.id,
                    amount: targetRequest.fee,
                    request: targetRequest
                }), { headers: corsHeaders });
            }
            
            if (path === '/generate-license' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { companyName, pic, phone, email, address, package: pkg, customMaxDevices, notes } = body;
                
                if (!companyName || !pic || !phone || !email) {
                    return new Response(JSON.stringify({ ok: false, error: 'Missing required fields' }), { headers: corsHeaders });
                }
                
                const licenseKey = 'VMS-' + generateId().toUpperCase().substring(0, 16);
                
                let maxDevices = customMaxDevices ? parseInt(customMaxDevices) : (pkg === 'PRO' ? 999 : (pkg === 'BASIC' ? 10 : 2));
                let expiredAt = Date.now();
                
                if (pkg === 'DEMO') {
                    expiredAt += 7 * 86400000;
                } else {
                    expiredAt += 30 * 86400000;
                }
                
                const newCompany = {
                    id: generateId(),
                    companyName: companyName,
                    licenseKey: licenseKey,
                    pic: pic,
                    phone: phone,
                    email: email,
                    address: address || '',
                    package: pkg,
                    maxDevices: maxDevices,
                    currentDevices: 0,
                    expiredAt: expiredAt,
                    status: 'ACTIVE',
                    createdAt: Date.now(),
                    notes: notes || ''
                };
                
                const companies = await safeArray(env, 'companies');
                companies.push(newCompany);
                await saveData(env, 'companies', companies);
                
                return new Response(JSON.stringify({
                    ok: true,
                    licenseKey: licenseKey,
                    company: newCompany
                }), { headers: corsHeaders });
            }
            
            if (path === '/renew-license' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { companyId, months, amount, paymentMethod } = body;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.id === companyId);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { headers: corsHeaders });
                }
                
                const currentExpiry = company.expiredAt;
                const newExpiry = Math.max(currentExpiry, Date.now()) + (months * 30 * 86400000);
                company.expiredAt = newExpiry;
                company.lastRenewedAt = Date.now();
                
                await saveData(env, 'companies', companies);
                
                const invoices = await safeArray(env, 'invoices');
                const invoice = {
                    id: generateId(),
                    companyId: company.id,
                    companyName: company.companyName,
                    type: 'RENEWAL',
                    amount: amount,
                    months: months,
                    status: paymentMethod === 'CASH' ? 'PAID' : 'UNPAID',
                    paymentMethod: paymentMethod,
                    createdAt: Date.now(),
                    paidAt: paymentMethod === 'CASH' ? Date.now() : null
                };
                invoices.push(invoice);
                await saveData(env, 'invoices', invoices);
                
                return new Response(JSON.stringify({ ok: true, company: company, invoice: invoice }), { headers: corsHeaders });
            }
            
            if (path === '/update-package' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { companyId, newPackage, customMaxDevices, notes } = body;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.id === companyId);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { headers: corsHeaders });
                }
                
                company.package = newPackage;
                if (customMaxDevices) {
                    company.maxDevices = parseInt(customMaxDevices);
                } else {
                    company.maxDevices = newPackage === 'PRO' ? 999 : 10;
                }
                company.packageUpdatedAt = Date.now();
                company.packageNotes = notes;
                
                await saveData(env, 'companies', companies);
                
                return new Response(JSON.stringify({ ok: true, company: company }), { headers: corsHeaders });
            }
            
            if (path === '/approve-device' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { deviceId, approve } = body;
                
                const companies = await safeArray(env, 'companies');
                let targetDevice = null;
                let targetCompany = null;
                
                for (const comp of companies) {
                    if (!comp.licenseKey) continue;
                    const devKey = scopedKey('devices', comp.licenseKey);
                    const devs = await safeArray(env, devKey);
                    const device = devs.find(d => d.deviceId === deviceId);
                    if (device) {
                        targetDevice = device;
                        targetCompany = comp;
                        break;
                    }
                }
                
                if (!targetDevice) {
                    return new Response(JSON.stringify({ ok: false, error: 'Device not found' }), { headers: corsHeaders });
                }
                
                targetDevice.status = approve ? 'ACTIVE' : 'REJECTED';
                if (!approve) {
                    targetDevice.deletedAt = Date.now();
                }
                
                if (targetCompany && targetCompany.licenseKey) {
                    const devKey = scopedKey('devices', targetCompany.licenseKey);
                    await saveData(env, devKey, await safeArray(env, devKey));
                }
                
                if (targetCompany && approve) {
                    const devKey = scopedKey('devices', targetCompany.licenseKey);
                    const freshDevices = await safeArray(env, devKey);
                    targetCompany.currentDevices = freshDevices.filter(d => d.status === 'ACTIVE').length;
                    await saveData(env, 'companies', companies);
                }
                
                return new Response(JSON.stringify({ ok: true, device: targetDevice }), { headers: corsHeaders });
            }
            
            if (path === '/delete-device' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { deviceId, reason } = body;
                
                const companies = await safeArray(env, 'companies');
                
                for (const comp of companies) {
                    if (!comp.licenseKey) continue;
                    const devKey = scopedKey('devices', comp.licenseKey);
                    let devs = await safeArray(env, devKey);
                    const index = devs.findIndex(d => d.deviceId === deviceId);
                    if (index !== -1) {
                        devs[index].status = 'DELETED';
                        devs[index].deletedAt = Date.now();
                        devs[index].deleteReason = reason;
                        await saveData(env, devKey, devs);
                        break;
                    }
                }
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/delete-company' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { companyId } = body;
                
                const companies = await safeArray(env, 'companies');
                const index = companies.findIndex(c => c.id === companyId);
                if (index === -1) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { headers: corsHeaders });
                }
                
                const deletedCompany = companies[index];
                companies.splice(index, 1);
                await saveData(env, 'companies', companies);
                
                if (deletedCompany.licenseKey) {
                    const scopedKeysList = [
                        'devices', 'visitors', 'logs', 'activities', 'violations', 'anti_nakal_reports'
                    ];
                    for (const baseKey of scopedKeysList) {
                        const key = scopedKey(baseKey, deletedCompany.licenseKey);
                        if (baseKey === 'visitors') {
                            await saveData(env, key, {});
                        } else {
                            await saveData(env, key, []);
                        }
                    }
                }
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/mark-invoice-paid' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { invoiceId, paymentMethod } = body;
                
                const invoices = await safeArray(env, 'invoices');
                const targetInvoice = invoices.find(i => i.id === invoiceId);
                if (!targetInvoice) {
                    return new Response(JSON.stringify({ ok: false, error: 'Invoice not found' }), { headers: corsHeaders });
                }
                
                targetInvoice.status = 'PAID';
                targetInvoice.paidAt = Date.now();
                targetInvoice.paymentMethod = paymentMethod;
                await saveData(env, 'invoices', invoices);
                
                if (targetInvoice.type === 'DEVICE_ADDITION' && targetInvoice.requestId) {
                    let deviceRequests = await safeArray(env, 'device_requests');
                    const deviceRequest = deviceRequests.find(r => r.id === targetInvoice.requestId);
                    if (deviceRequest && deviceRequest.status === 'WAITING_PAYMENT') {
                        deviceRequest.status = 'PAID';
                        deviceRequest.paidAt = Date.now();
                        await saveData(env, 'device_requests', deviceRequests);
                        
                        const companies = await safeArray(env, 'companies');
                        const company = companies.find(c => c.id === deviceRequest.companyId);
                        if (company && company.licenseKey) {
                            const devKey = scopedKey('devices', company.licenseKey);
                            let scopedDevices = await safeArray(env, devKey);
                            const newDevice = {
                                deviceId: 'dev_' + generateId(),
                                deviceName: deviceRequest.deviceName,
                                licenseKey: deviceRequest.licenseKey,
                                companyId: company.id,
                                companyName: company.companyName,
                                status: 'ACTIVE',
                                firstSeen: Date.now(),
                                lastSeen: Date.now(),
                                violations: [],
                                sessions: []
                            };
                            scopedDevices.push(newDevice);
                            await saveData(env, devKey, scopedDevices);
                            
                            company.currentDevices = scopedDevices.filter(d => d.status === 'ACTIVE').length;
                            await saveData(env, 'companies', companies);
                        }
                    }
                }
                
                return new Response(JSON.stringify({ ok: true, invoice: targetInvoice }), { headers: corsHeaders });
            }
            
            if (path === '/admin/users' && request.method === 'GET') {
                const admins = await safeArray(env, 'admins');
                const safeAdmins = admins.map(a => ({ username: a.username, role: a.role, lastLogin: a.lastLogin }));
                return new Response(JSON.stringify(safeAdmins), { headers: corsHeaders });
            }
            
            if (path === '/admin/add-user' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { username, password, role } = body;
                
                if (!username || !password) {
                    return new Response(JSON.stringify({ ok: false, error: 'Username and password required' }), { headers: corsHeaders });
                }
                
                const admins = await safeArray(env, 'admins');
                if (admins.find(a => a.username === username)) {
                    return new Response(JSON.stringify({ ok: false, error: 'Username already exists' }), { headers: corsHeaders });
                }
                
                const hash = await sha256(password);
                admins.push({
                    id: generateId(),
                    username: username,
                    password: hash,
                    role: role || 'ADMIN',
                    createdAt: Date.now()
                });
                await saveData(env, 'admins', admins);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            // 🔧 Proteksi SUPER_ADMIN dari delete
            if (path === '/admin/delete-user' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                const { username } = body;
                
                const admins = await safeArray(env, 'admins');
                const target = admins.find(a => a.username === username);
                
                // 🔒 PROTECT: Cannot delete SUPER_ADMIN
                if (target && target.role === 'SUPER_ADMIN') {
                    return new Response(JSON.stringify({
                        ok: false,
                        error: 'Cannot delete SUPER_ADMIN'
                    }), { headers: corsHeaders });
                }
                
                const filtered = admins.filter(a => a.username !== username);
                await saveData(env, 'admins', filtered);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/admin/settings' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                await saveData(env, 'settings', body);
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/admin/settings' && request.method === 'GET') {
                const settings = await safeObject(env, 'settings');
                return new Response(JSON.stringify(settings), { headers: corsHeaders });
            }
            
            if (path === '/sync-users' && request.method === 'POST') {
                const body = await request.json().catch(() => ({}));
                if (body.users && Array.isArray(body.users)) {
                    let serverUsers = await safeArray(env, 'users_from_clients');
                    for (const user of body.users) {
                        const existing = serverUsers.find(u => u.username === user.username);
                        if (!existing) {
                            serverUsers.push(user);
                        }
                    }
                    await saveData(env, 'users_from_clients', serverUsers);
                    return new Response(JSON.stringify({ ok: true, users: serverUsers }), { headers: corsHeaders });
                }
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/cron/check-expired' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                const now = Date.now();
                let updated = false;
                
                for (const company of companies) {
                    if (company.expiredAt < now && company.status !== 'EXPIRED') {
                        company.status = 'EXPIRED';
                        updated = true;
                    }
                }
                
                if (updated) {
                    await saveData(env, 'companies', companies);
                }
                
                return new Response(JSON.stringify({ ok: true, updated: updated }), { headers: corsHeaders });
            }
            
            return new Response(JSON.stringify({ ok: false, error: 'Endpoint not found: ' + path }), { 
                status: 404, 
                headers: corsHeaders 
            });
            
        } catch (error) {
            console.error('Worker error:', error);
            return new Response(JSON.stringify({ 
                ok: false, 
                error: error.message,
                stack: error.stack,
                timestamp: Date.now()
            }), { 
                status: 500, 
                headers: corsHeaders 
            });
        }
    }
};

// ==================== KV STORAGE LAYER ====================

async function forceInit(env) {
    console.log('[FORCE_INIT] Starting initialization...');
    
    try {
        const testKey = '__vms_test__';
        await env.VMS_STORAGE.put(testKey, 'test');
        const testVal = await env.VMS_STORAGE.get(testKey);
        console.log(`[FORCE_INIT] KV test: ${testVal === 'test' ? 'OK' : 'FAILED'}`);
        
        let admins = await safeArray(env, 'admins');
        
        if (!admins || admins.length === 0) {
            console.log('[FORCE_INIT] No admins found, creating default...');
            
            const defaultHash = await sha256('123456');
            console.log(`[FORCE_INIT] Default admin hash: ${defaultHash.substring(0, 20)}...`);
            
            admins = [{
                id: generateId(),
                username: 'admin',
                password: defaultHash,
                role: 'SUPER_ADMIN',
                createdAt: Date.now(),
                createdBy: 'system',
                token: null
            }];
            
            await saveData(env, 'admins', admins);
            console.log('[FORCE_INIT] Default admin created successfully');
        } else {
            console.log(`[FORCE_INIT] Found ${admins.length} existing admins`);
            
            let needsSave = false;
            for (let i = 0; i < admins.length; i++) {
                if (!admins[i].token) {
                    admins[i].token = null;
                    needsSave = true;
                }
            }
            if (needsSave) {
                await saveData(env, 'admins', admins);
                console.log('[FORCE_INIT] Updated admin records with missing fields');
            }
            
            // 🔒 Only ensure minimal fields exist
            for (let i = 0; i < admins.length; i++) {
                if (!admins[i].role) admins[i].role = 'ADMIN';
                if (!admins[i].username) admins[i].username = 'unknown_' + generateId();
            }
            
            // Ensure at least one SUPER_ADMIN exists
            if (!admins.some(a => a.role === 'SUPER_ADMIN')) {
                console.warn('[FORCE_INIT] No SUPER_ADMIN found, promoting first admin');
                if (admins.length > 0) {
                    admins[0].role = 'SUPER_ADMIN';
                    await saveData(env, 'admins', admins);
                }
            }
        }
        
        let settings = await safeObject(env, 'settings');
        if (!settings || Object.keys(settings).length === 0) {
            console.log('[FORCE_INIT] Creating default settings...');
            settings = {
                pricing: {
                    BASIC: { price: 500000, maxDevices: 10, extraDeviceFee: 50000 },
                    PRO: { price: 2000000, maxDevices: 999, extraDeviceFee: 0 }
                },
                general: { 
                    tax: 11,
                    company: "VMS System",
                    version: "3.0"
                }
            };
            await saveData(env, 'settings', settings);
            console.log('[FORCE_INIT] Default settings created');
        }
        
        const arrayCollections = [
            'companies', 'device_requests', 'users_from_clients', 'invoices'
        ];
        
        for (const collection of arrayCollections) {
            const data = await safeArray(env, collection);
            if (!Array.isArray(data) || data.length === undefined) {
                console.log(`[FORCE_INIT] Initializing array for: ${collection}`);
                await saveData(env, collection, []);
            }
        }
        
        const objectCollections = ['site_names'];
        for (const collection of objectCollections) {
            const data = await safeObject(env, collection);
            if (!data || typeof data !== 'object') {
                console.log(`[FORCE_INIT] Initializing object for: ${collection}`);
                await saveData(env, collection, {});
            }
        }
        
        console.log('[FORCE_INIT] Initialization complete!');
        return true;
        
    } catch (e) {
        console.error('[FORCE_INIT] Error:', e);
        return false;
    }
}

// 🔒 Special function for reset system - NO password override
async function forceInitNoPasswordOverride(env) {
    console.log('[FORCE_INIT_NO_OVERRIDE] Starting safe initialization...');
    
    try {
        const testKey = '__vms_test__';
        await env.VMS_STORAGE.put(testKey, 'test');
        const testVal = await env.VMS_STORAGE.get(testKey);
        console.log(`[FORCE_INIT_NO_OVERRIDE] KV test: ${testVal === 'test' ? 'OK' : 'FAILED'}`);
        
        let admins = await safeArray(env, 'admins');
        
        if (!admins || admins.length === 0) {
            console.log('[FORCE_INIT_NO_OVERRIDE] No admins found, creating default...');
            
            const defaultHash = await sha256('123456');
            
            admins = [{
                id: generateId(),
                username: 'admin',
                password: defaultHash,
                role: 'SUPER_ADMIN',
                createdAt: Date.now(),
                createdBy: 'system',
                token: null
            }];
            
            await saveData(env, 'admins', admins);
            console.log('[FORCE_INIT_NO_OVERRIDE] Default admin created');
        } else {
            console.log(`[FORCE_INIT_NO_OVERRIDE] Found ${admins.length} existing admins`);
            
            // 🔒 ONLY ensure minimal fields - NEVER touch passwords
            let needsSave = false;
            for (let i = 0; i < admins.length; i++) {
                if (!admins[i].role) {
                    admins[i].role = 'ADMIN';
                    needsSave = true;
                }
                if (!admins[i].username) {
                    admins[i].username = 'unknown_' + generateId();
                    needsSave = true;
                }
                if (!admins[i].password) {
                    // This should never happen, but create placeholder
                    admins[i].password = await sha256('changeme_' + generateId());
                    needsSave = true;
                }
            }
            
            if (needsSave) {
                await saveData(env, 'admins', admins);
            }
            
            // 🔒 Ensure at least one SUPER_ADMIN exists
            if (!admins.some(a => a.role === 'SUPER_ADMIN')) {
                console.warn('[FORCE_INIT_NO_OVERRIDE] No SUPER_ADMIN found, promoting first admin');
                if (admins.length > 0) {
                    admins[0].role = 'SUPER_ADMIN';
                    await saveData(env, 'admins', admins);
                }
            }
        }
        
        let settings = await safeObject(env, 'settings');
        if (!settings || Object.keys(settings).length === 0) {
            console.log('[FORCE_INIT_NO_OVERRIDE] Creating default settings...');
            settings = {
                pricing: {
                    BASIC: { price: 500000, maxDevices: 10, extraDeviceFee: 50000 },
                    PRO: { price: 2000000, maxDevices: 999, extraDeviceFee: 0 }
                },
                general: { 
                    tax: 11,
                    company: "VMS System",
                    version: "3.0"
                }
            };
            await saveData(env, 'settings', settings);
        }
        
        const arrayCollections = [
            'companies', 'device_requests', 'users_from_clients', 'invoices'
        ];
        
        for (const collection of arrayCollections) {
            const data = await safeArray(env, collection);
            if (!Array.isArray(data) || data.length === undefined) {
                await saveData(env, collection, []);
            }
        }
        
        const objectCollections = ['site_names'];
        for (const collection of objectCollections) {
            const data = await safeObject(env, collection);
            if (!data || typeof data !== 'object') {
                await saveData(env, collection, {});
            }
        }
        
        console.log('[FORCE_INIT_NO_OVERRIDE] Safe initialization complete!');
        return true;
        
    } catch (e) {
        console.error('[FORCE_INIT_NO_OVERRIDE] Error:', e);
        return false;
    }
}

async function getData(env, key) {
    try {
        if (!env || !env.VMS_STORAGE) {
            console.error(`[GET_DATA] KV Storage not available for key: ${key}`);
            return getDefaultData(key);
        }
        
        const value = await env.VMS_STORAGE.get(key);
        
        if (!value || value === 'null' || value === 'undefined') {
            console.log(`[GET_DATA] Key "${key}" not found, using default`);
            return getDefaultData(key);
        }
        
        const parsed = JSON.parse(value);
        const itemCount = Array.isArray(parsed) ? parsed.length + ' items' : Object.keys(parsed).length + ' keys';
        console.log(`[GET_DATA] Retrieved "${key}": ${itemCount}`);
        return parsed;
        
    } catch (e) {
        console.error(`[GET_DATA] Error for key "${key}":`, e);
        return getDefaultData(key);
    }
}

async function saveData(env, key, data) {
    try {
        // Safe array write (anti corrupt)
        if (data === undefined || data === null) {
            data = [];
        }
        
        if (!env || !env.VMS_STORAGE) {
            console.error(`[SAVE_DATA] KV Storage not available for key: ${key}`);
            return false;
        }
        
        const jsonString = JSON.stringify(data);
        await env.VMS_STORAGE.put(key, jsonString);
        const itemCount = Array.isArray(data) ? data.length + ' items' : Object.keys(data).length + ' keys';
        console.log(`[SAVE_DATA] Saved "${key}": ${jsonString.length} bytes, ${itemCount}`);
        return true;
        
    } catch (e) {
        console.error(`[SAVE_DATA] Error for key "${key}":`, e);
        return false;
    }
}

function getDefaultData(key) {
    const defaults = {
        companies: [],
        device_requests: [],
        admins: [],
        users_from_clients: [],
        invoices: [],
        site_names: {
            SITE_A: "SITE A",
            SITE_B: "SITE B", 
            SITE_C: "SITE C",
            customSites: {}
        },
        settings: {
            pricing: {
                BASIC: { price: 500000, maxDevices: 10, extraDeviceFee: 50000 },
                PRO: { price: 2000000, maxDevices: 999, extraDeviceFee: 0 }
            },
            general: { tax: 11 }
        }
    };
    
    if (defaults[key] !== undefined) {
        return defaults[key];
    }
    
    return [];
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 10);
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

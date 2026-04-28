// ==================== VMS API LAYER v2.0 (FINAL HARDENED) ====================
// SINGLE SOURCE OF TRUTH - JANGAN UBAH STRUKTUR

window.CLOUD_URL = "https://privms.wonggemblunxs.workers.dev";

// ==================== CONFIG ====================
window.DEBUG = location.hostname === "localhost";

// ==================== HELPER ====================
function getAdminToken() {
    return localStorage.getItem("vms_admin_token");
}

function generateDeviceId() {
    let id = localStorage.getItem("vms_device_id");

    if (!id) {
        id = (crypto.randomUUID)
            ? "dev_" + crypto.randomUUID()
            : "dev_" + Date.now() + "_" + Math.random().toString(36).substring(2, 10);

        localStorage.setItem("vms_device_id", id);
    }

    return id;
}

// ==================== CORE REQUEST (HARDENED) ====================
async function vmsRequest(endpoint, payload = {}, retry = 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
        const res = await fetch(`${window.CLOUD_URL}${endpoint}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        clearTimeout(timeout);

        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error("INVALID_JSON");
        }

        if (!data || typeof data !== "object") {
            throw new Error("INVALID_RESPONSE");
        }

        if (window.DEBUG) {
            console.log(`[API] ${endpoint}`, payload);
            console.log(`[API] RES`, data);
        }

        return data;

    } catch (err) {
        clearTimeout(timeout);

        console.error(`[API ERROR] ${endpoint}`, err.message);

        if (retry > 0) {
            console.warn(`[API RETRY] ${endpoint}`);
            return vmsRequest(endpoint, payload, retry - 1);
        }

        return { ok: false, error: err.message };
    }
}

// ==================== PUBLIC API ====================
const VMS_API = {

    // ================= LICENSE & DEVICE =================
    validate: (licenseKey, deviceId, deviceName, meta = {}) =>
        vmsRequest("/validate-license", { licenseKey, deviceId, deviceName, meta }),

    // ================= SYNC =================
    sync: (licenseKey, deviceId, lastSync = 0) =>
        vmsRequest("/sync-data", { licenseKey, deviceId, lastSync }),

    // ================= SAVE =================
    save: (licenseKey, deviceId, visitors = {}, logs = [], site = null) =>
        vmsRequest("/save", {
            licenseKey,
            deviceId,
            visitors,
            logs,
            site,
            ts: Date.now()
        }),

    // ================= CHECKIN =================
    checkin: (licenseKey, deviceId, action, location = null) =>
        vmsRequest("/checkin", { licenseKey, deviceId, action, location }),

    // ================= ADMIN =================
    adminStats: () =>
        vmsRequest("/admin/stats", { token: getAdminToken() }),

    adminCompanies: () =>
        vmsRequest("/admin/companies", { token: getAdminToken() }),

    adminDevices: () =>
        vmsRequest("/admin/devices", { token: getAdminToken() }),

    adminActivity: (limit = 500) =>
        vmsRequest("/admin/activity", { token: getAdminToken(), limit }),

    adminInvoices: () =>
        vmsRequest("/admin/invoices", { token: getAdminToken() }),

    adminDeviceRequests: (status = null) =>
        vmsRequest("/admin/device-requests", { token: getAdminToken(), status }),

    generateLicense: (data) =>
        vmsRequest("/generate-license", { token: getAdminToken(), ...data }),

    renewLicense: (companyId, months, amount, paymentMethod) =>
        vmsRequest("/renew-license", {
            token: getAdminToken(),
            companyId,
            months,
            amount,
            paymentMethod
        }),

    updatePackage: (companyId, newPackage, customMaxDevices, notes) =>
        vmsRequest("/update-package", {
            token: getAdminToken(),
            companyId,
            newPackage,
            customMaxDevices,
            notes
        }),

    approveDevice: (deviceId, approve) =>
        vmsRequest("/approve-device", {
            token: getAdminToken(),
            deviceId,
            approve
        }),

    deleteDevice: (deviceId, reason) =>
        vmsRequest("/delete-device", {
            token: getAdminToken(),
            deviceId,
            reason
        }),

    deleteCompany: (companyId) =>
        vmsRequest("/delete-company", {
            token: getAdminToken(),
            companyId
        }),

    markInvoicePaid: (invoiceId, paymentMethod) =>
        vmsRequest("/mark-invoice-paid", {
            token: getAdminToken(),
            invoiceId,
            paymentMethod
        }),

    approveDeviceRequest: (requestId, approve, notes = null) =>
        vmsRequest("/approve-device-request", {
            token: getAdminToken(),
            requestId,
            approve,
            notes
        }),

    login: (username, password) =>
        vmsRequest("/login", { username, password }),

    siteNames: (licenseKey = null, sites = null) =>
        vmsRequest("/site-names", { licenseKey, sites }),
};

// ==================== GLOBAL EXPORT ====================
window.VMS_API = VMS_API;
window.generateDeviceId = generateDeviceId;

console.log("[VMS API] v2.0 READY:", window.CLOUD_URL);
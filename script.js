/* WMS BASELINE 2026-09-25 — canonical frontend baseline. */

/* =========================================================
   AUTHENTICATION — SUPABASE
========================================================= */

const SUPABASE_URL = "https://ipmyxkhnwijpdweeztgb.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_TxMJg2izPoGmdre2BJkPMw_y_9No2sF";

if (!window.supabase) {
    throw new Error("Supabase library failed to load.");
}

const supabaseClient = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    {
        auth: {
            persistSession: true,
            autoRefreshToken: true,
            detectSessionInUrl: false
        }
    }
);

const AUDIT_KEY = "warehouse_v3_audit";

// =========================================================
// LOGIN SECURITY SETTINGS
// 5 wrong password attempts -> temporary 5-minute lock.
// The lock is stored per login in localStorage so a page refresh
// does not immediately reset the counter. Supabase Auth remains
// the real authentication authority and its own rate limits still apply.
// =========================================================
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 10 * 60 * 1000;
const LOGIN_SECURITY_KEY = "warehouse_login_security_v1";
let loginCountdownTimer = null;

function getLoginSecurityStore() {
    try {
        return JSON.parse(localStorage.getItem(LOGIN_SECURITY_KEY) || "{}");
    } catch {
        return {};
    }
}

function saveLoginSecurityStore(store) {
    try {
        localStorage.setItem(LOGIN_SECURITY_KEY, JSON.stringify(store));
    } catch (error) {
        console.warn("Could not save login security state:", error);
    }
}

function getGlobalLoginSecurityState() {
    const store = getLoginSecurityStore();
    const state = store.__global__ || { attempts: 0, lockedUntil: 0 };

    // A completed lockout starts a completely fresh 5-attempt window.
    if (state.lockedUntil && state.lockedUntil <= Date.now()) {
        delete store.__global__;
        saveLoginSecurityStore(store);
        return { attempts: 0, lockedUntil: 0 };
    }

    return {
        attempts: Number(state.attempts || 0),
        lockedUntil: Number(state.lockedUntil || 0)
    };
}

function clearLoginSecurityState() {
    const store = getLoginSecurityStore();
    delete store.__global__;
    saveLoginSecurityStore(store);
}

function registerFailedLogin() {
    const store = getLoginSecurityStore();
    const state = store.__global__ || { attempts: 0, lockedUntil: 0 };

    // If the previous lock has expired, start from zero.
    if (state.lockedUntil && state.lockedUntil <= Date.now()) {
        state.attempts = 0;
        state.lockedUntil = 0;
    }

    state.attempts = Number(state.attempts || 0) + 1;

    if (state.attempts >= LOGIN_MAX_ATTEMPTS) {
        state.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
        state.attempts = LOGIN_MAX_ATTEMPTS;
    }

    store.__global__ = state;
    saveLoginSecurityStore(store);
    return state;
}

function formatLockoutTime(milliseconds) {
    const totalSeconds = Math.max(0, Math.ceil(milliseconds / 1000));
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function stopLoginCountdown() {
    if (loginCountdownTimer) {
        clearInterval(loginCountdownTimer);
        loginCountdownTimer = null;
    }
}

function setLoginLockoutUI(_login, lockedUntil) {
    const lockout = document.getElementById("loginLockout");
    const countdown = document.getElementById("loginCountdown");
    const button = document.querySelector("#loginForm .login-button");
    const username = document.getElementById("loginUsername");
    const password = document.getElementById("loginPassword");

    stopLoginCountdown();

    const update = () => {
        const remaining = Number(lockedUntil || 0) - Date.now();
        if (remaining <= 0) {
            clearLoginSecurityState();
            if (lockout) lockout.classList.add("hidden");
            if (button) button.disabled = false;
            if (username) username.disabled = false;
            if (password) password.disabled = false;
            return;
        }

        if (lockout) lockout.classList.remove("hidden");
        if (countdown) countdown.textContent = formatLockoutTime(remaining);
        if (button) button.disabled = true;
        if (username) username.disabled = true;
        if (password) password.disabled = true;
    };

    update();
    loginCountdownTimer = setInterval(update, 1000);
}

function refreshLoginLockoutUI() {
    const state = getGlobalLoginSecurityState();

    if (state.lockedUntil && state.lockedUntil > Date.now()) {
        setLoginLockoutUI("", state.lockedUntil);
        return;
    }

    stopLoginCountdown();
    document.getElementById("loginLockout")?.classList.add("hidden");
    const button = document.querySelector("#loginForm .login-button");
    const username = document.getElementById("loginUsername");
    const password = document.getElementById("loginPassword");
    if (button) button.disabled = false;
    if (username) username.disabled = false;
    if (password) password.disabled = false;
}

let currentUser = null;
// Audit Log is stored centrally in Supabase.
async function loadAuditHistory() {
    if (!currentUser || String(currentUser.role || "").trim().toLowerCase() !== "admin") {
        return { data: [], error: null };
    }

    const pageSize = 1000;
    let from = 0;
    const allRows = [];

    while (true) {
        const { data, error } = await supabaseClient
            .from("audit_logs")
            .select("id, actor_id, actor_login, actor_name, action, employee_login, details, created_at")
            .in("action", ["Login", "Logout"])
            .order("created_at", { ascending: false })
            .range(from, from + pageSize - 1);

        if (error) {
            console.error("Audit log load error:", error);
            return { data: [], error };
        }

        const page = Array.isArray(data) ? data : [];
        allRows.push(...page);
        if (page.length < pageSize) break;
        from += pageSize;
    }

    return { data: allRows, error: null };
}

function getCurrentUser() {
    return currentUser;
}

async function loadCurrentUser(authUser) {
    if (!authUser) {
        currentUser = null;
        return null;
    }

    const fallbackLogin =
        String(authUser.email || "")
            .split("@")[0]
            .toLowerCase();

    const metadata = authUser.user_metadata || {};

    try {
        const { data: profile, error } = await supabaseClient
            .from("profiles")
            .select("id, login, full_name, role, active")
            .eq("id", authUser.id)
            .maybeSingle();

        if (error) {
            console.error("Profile lookup error:", error);
        }

        if (error) {
            console.error("Profile lookup failed. Access is blocked until the profile can be read:", error);
            currentUser = null;
            return null;
        }

        if (!profile) {
            console.error("No profile found for authenticated user:", authUser.id);
            currentUser = null;
            return null;
        }

        if (profile.active === false) {
            await supabaseClient.auth.signOut({ scope: "local" });
            currentUser = null;
            return null;
        }

        const normalizedRole = String(profile.role || "").trim().toLowerCase();
        if (!normalizedRole) {
            console.error("Profile has no role:", profile);
            currentUser = null;
            return null;
        }

        currentUser = {
            id: authUser.id,
            login: profile.login || fallbackLogin,
            name: profile.full_name || metadata.full_name || fallbackLogin,
            role: normalizedRole,
            active: true
        };

        return currentUser;
    } catch (error) {
        console.error("Profile lookup failed:", error);
        currentUser = null;
        return null;
    }
}

function loginEmail(login) {
    return `${String(login).trim().toLowerCase()}@warehouse.local`;
}

async function addAudit(action, details = "", employeeLogin = "", actorLogin = "") {
    const actorUser = getCurrentUser();
    if (!actorUser) return;

    const { error } = await supabaseClient
        .from("audit_logs")
        .insert({
            actor_id: actorUser.id,
            actor_login: actorLogin || actorUser.login || "SYSTEM",
            actor_name: actorUser.name || "System",
            action: action || "",
            employee_login: employeeLogin || "",
            details: details || ""
        });

    if (error) {
        console.error("Audit log insert error:", error);
        return false;
    }

    return true;
}

function roleLabel(role) {
    const normalized = String(role || "").trim().toLowerCase();
    if (normalized === "admin") return "Admin";
    if (normalized === "coordinator") return "Coordinator";
    if (normalized === "leader") return "Leader";
    return role || "";
}

function actorDisplay(name, login) {
    const cleanName = String(name || "").trim();
    const cleanLogin = String(login || "").trim();
    if (cleanName && cleanLogin) return `${cleanName} · ${cleanLogin}`;
    return cleanName || cleanLogin || "—";
}


// Keep long attendance notes compact in the monthly table.
// The full note remains untouched in Supabase and in exports.
function notePreview(text, maxWords = 8) {
    const full = String(text || '').trim();
    if (!full) return '—';

    const words = full.split(/\s+/);
    if (words.length <= maxWords) return full;

    return `${words.slice(0, maxWords).join(' ')}…`;
}

function currentUserRole() {
    return String(currentUser?.role || "").trim().toLowerCase();
}

// Export is an operational/reporting permission. Leaders can work with
// attendance, but they do not get Excel export controls.
// Coordinators and Admins can export.
function canExportData() {
    const role = currentUserRole();
    return role === "coordinator" || role === "admin";
}

function canDeleteExtraDays() {
    const role = currentUserRole();
    return role === "coordinator" || role === "admin";
}

function updateRoleBasedControls() {
    const canExport = canExportData();

    ["exportShiftEmployees", "exportSchedule", "exportEmployees"].forEach(id => {
        const button = $(id);
        if (button) button.hidden = !canExport;
    });

    updateHoursExportVisibility();
}

function setAuthScreen(isLoggedIn) {
    const loginScreen = document.getElementById("loginScreen");
    const userBox = document.getElementById("currentUserBox");

    if (loginScreen) {
        loginScreen.classList.toggle("hidden", isLoggedIn);
    }

    if (userBox) {
        userBox.classList.toggle("hidden", !isLoggedIn);
    }

    if (isLoggedIn && currentUser) {
        document.getElementById("currentUserName").textContent =
            currentUser.name;

        document.getElementById("currentUserLogin").textContent =
            `${roleLabel(currentUser.role)} · ${currentUser.login}`;
        syncExtraLeaderLogin();
        updateRoleBasedControls();

        // Audit Log is intentionally visible only to Admin users.
        // The database RLS patch in V22.7 enforces the same rule server-side.
        const auditTabButton = document.querySelector('[data-scheduling-tab="auditTab"]');
        const isAdmin = String(currentUser.role || "").trim().toLowerCase() === "admin";
        if (auditTabButton) {
            auditTabButton.hidden = !isAdmin;
        }

        if (!isAdmin && activeSchedulingTab === "auditTab") {
            setSchedulingTab("scheduleTab");
        }
    }
}

async function initAppOnce() {
    if (window.__warehouseAppInitialized) return;

    window.__warehouseAppInitialized = true;
    await initApp();
}

async function logout() {
    const user = getCurrentUser();

    // Audit must never block the actual logout.
    if (user) {
        try {
            await addAudit("Logout", "User signed out", "", user.login);
        } catch (auditError) {
            console.error("Logout audit error:", auditError);
        }
    }

    // clearWmsClientData() only clears browser storage and does not
    // return a Supabase response. The previous code incorrectly
    // destructured { error } from its return value, which caused
    // logout to fail with a TypeError.
    clearWmsClientData();

    const { error } =
        await supabaseClient.auth.signOut({ scope: "local" });

    if (error) {
        console.error("Logout error:", error);
        toast("Could not log out.");
        return;
    }

    if (scheduleRealtimeChannel) {
        await supabaseClient.removeChannel(scheduleRealtimeChannel);
        scheduleRealtimeChannel = null;
    }
    if (individualScheduleRealtimeChannel) {
        await supabaseClient.removeChannel(individualScheduleRealtimeChannel);
        individualScheduleRealtimeChannel = null;
    }

    if (extraDaysRealtimeChannel) {
        await supabaseClient.removeChannel(extraDaysRealtimeChannel);
        extraDaysRealtimeChannel = null;
    }
    if (attendanceRealtimeChannel) {
        await supabaseClient.removeChannel(attendanceRealtimeChannel);
        attendanceRealtimeChannel = null;
    }
    if (scheduleHistoryRealtimeChannel) {
        await supabaseClient.removeChannel(scheduleHistoryRealtimeChannel);
        scheduleHistoryRealtimeChannel = null;
    }
    if (employeesRealtimeChannel) { await supabaseClient.removeChannel(employeesRealtimeChannel); employeesRealtimeChannel=null; }
    if (auditRealtimeChannel) { await supabaseClient.removeChannel(auditRealtimeChannel); auditRealtimeChannel=null; }
    if (feedbackRealtimeChannel) { await supabaseClient.removeChannel(feedbackRealtimeChannel); feedbackRealtimeChannel=null; }

    currentUser = null;
    window.__warehouseAppInitialized = false;
    setAuthScreen(false);
}

function auditDateKey(value) {
    if (!value) return "";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value).slice(0, 10);
    return new Intl.DateTimeFormat("en-CA", {
        timeZone: "Europe/Warsaw",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    }).format(parsed);
}

async function renderAuditLog() {
    const table = document.getElementById("auditTable");
    if (!table) return;
    if (String(currentUser?.role || "").trim().toLowerCase() !== "admin") return;

    const dateFilter =
        document.getElementById("auditDate").value;

    const loginFilter =
        document.getElementById("auditLogin")
            .value
            .trim()
            .toLowerCase();

    const result = await loadAuditHistory();

    if (result.error) {
        table.innerHTML = `
            <tr>
                <td colspan="3">
                    <div class="empty">
                        Audit Log could not be loaded from Supabase.
                        <br>
                        <small>${esc(result.error.message || "Unknown error")}</small>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    const auditHistory = result.data;

    const rows = auditHistory.filter(item => {
        if (dateFilter) {
            // Supabase timestamptz is returned as an ISO string.
            // Compare directly with the date input value to avoid
            // browser locale differences (en-CA, en-GB, etc.).
            const itemDate = auditDateKey(item.created_at);

            if (itemDate !== dateFilter) return false;
        }

        if (loginFilter) {
            const searchable =
                `${item.actor_login || ""} ` +
                `${item.actor_name || ""} ` +
                `${item.employee_login || ""} ` +
                `${item.details || ""}`
                    .toLowerCase();

            if (!searchable.includes(loginFilter)) return false;
        }

        return true;
    });

    table.innerHTML =
        rows.map(item => `
            <tr>
                <td>${new Date(item.created_at).toLocaleString("en-GB")}</td>
                <td>
                    <strong>${esc(item.actor_name || "System")}</strong>
                    <br>
                    <small>${esc(item.actor_login || "SYSTEM")}</small>
                </td>
                <td><strong>${esc(item.action || "")}</strong></td>
            </tr>
        `).join("") ||
        `<tr><td colspan="3"><div class="empty">No login/logout events found.</div></td></tr>`;
}

async function initAuth() {
    const loginForm = document.getElementById("loginForm");
    const logoutButton = document.getElementById("logoutButton");

    // Password visibility toggle (eye icon).
    const passwordInput = document.getElementById("loginPassword");
    const togglePassword = document.getElementById("togglePassword");

    togglePassword?.addEventListener("click", () => {
        const showing = passwordInput.type === "text";
        passwordInput.type = showing ? "password" : "text";
        togglePassword.setAttribute("aria-label", showing ? "Show password" : "Hide password");
        togglePassword.setAttribute("title", showing ? "Show password" : "Hide password");
    });

    // If the user returns to the login screen, restore an active lockout.
    document.getElementById("loginUsername")?.addEventListener("input", refreshLoginLockoutUI);
    refreshLoginLockoutUI();

    loginForm.addEventListener("submit", async event => {
        event.preventDefault();

        const login =
            document.getElementById("loginUsername").value.trim();

        const password =
            document.getElementById("loginPassword").value;

        const error =
            document.getElementById("loginError");

        if (!login || !password) {
            error.textContent = "Enter login and password.";
            return;
        }

        // Check the 5-attempt lock BEFORE calling Supabase.
        const securityState = getGlobalLoginSecurityState();
        if (securityState.lockedUntil > Date.now()) {
            setLoginLockoutUI('', securityState.lockedUntil);
            return;
        }

        error.textContent = "";

        const button = loginForm.querySelector(".login-button");
        if (button) button.disabled = true;

        const { data, error: signInError } =
            await supabaseClient.auth.signInWithPassword({
                email: loginEmail(login),
                password
            });

        if (signInError) {
            console.error("Supabase login error:", signInError);

            const failedState = registerFailedLogin(login);
            if (failedState.lockedUntil > Date.now()) {
                error.textContent = "";
                setLoginLockoutUI('', failedState.lockedUntil);
            } else {
                const remaining = LOGIN_MAX_ATTEMPTS - failedState.attempts;
                error.textContent = remaining > 0
                    ? `Invalid login or password. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`
                    : "Invalid login or password.";
                if (button) button.disabled = false;
            }
            return;
        }

        // Successful authentication resets the failed-attempt counter.
        clearLoginSecurityState();
        stopLoginCountdown();
        document.getElementById("loginLockout")?.classList.add("hidden");

        const user = await loadCurrentUser(data.user);

        if (!user) {
            // Authentication succeeded, but the WMS profile is missing/inactive.
            // Do not leave a valid Auth session hanging in the background.
            await supabaseClient.auth.signOut({ scope: "local" });
            error.textContent = "This account is inactive or has no active WMS profile.";
            if (button) button.disabled = false;
            return;
        }

        document.getElementById("loginPassword").value = "";
        setAuthScreen(true);

        await addAudit(
            "Login",
            "User signed in",
            "",
            user.login
        );

        initAppOnce();
    });

    logoutButton.addEventListener("click", logout);

    const auditDate = document.getElementById("auditDate");
    const auditLogin = document.getElementById("auditLogin");
    const clearAudit = document.getElementById("clearAuditFilters");

    if (auditLogin) auditLogin.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); renderAuditLog(); } });
    $("applyAuditFilters")?.addEventListener("click", renderAuditLog);

    if (clearAudit) {
        clearAudit.addEventListener("click", () => {
            auditDate.value = "";
            auditLogin.value = "";
            renderAuditLog();
        });
    }

    supabaseClient.auth.onAuthStateChange(async (_event, session) => {
        if (session?.user) {
            const user = await loadCurrentUser(session.user);

            if (user) {
                setAuthScreen(true);
                initAppOnce();
            }
        } else {
            currentUser = null;
            setAuthScreen(false);
        }
    });

    const { data: sessionData, error: sessionError } =
        await supabaseClient.auth.getSession();

    if (sessionError) {
        console.error("Session restore error:", sessionError);
        setAuthScreen(false);
        return;
    }

    if (sessionData.session?.user) {
        const user =
            await loadCurrentUser(sessionData.session.user);

        if (user) {
            setAuthScreen(true);
            initAppOnce();
            return;
        }
    }

    setAuthScreen(false);
}


const BRIGADES = ["A", "B", "C", "D1", "D2", "N1", "N2"];

const PROCESSES = [
    "Leader",
    "Pick",
    "Putaway",
    "Abnormal",
    "Consolidation",
    "Buffer"
];

const EMPLOYEE_QUALIFICATIONS = [
    "Instructor",
    "Yard Coordinator",
    "Forklift operator"
];

// Secondary process skills are separate from the employee's primary process.
const EMPLOYEE_PROCESS_SKILLS = [
    "Pick",
    "Putaway",
    "Abnormal",
    "Consolidation",
    "Leader",
    "Buffer",
    "Floor Recovery",
    "Short-Pick"
];

let employeeSort = {
    key: "name",
    direction: 1
};

function normalizeProcessName(value) {
    const raw = String(value || "").trim();
    const match = PROCESSES.find(process => process.toLowerCase() === raw.toLowerCase());
    return match || raw;
}

function normalizeSecondaryProcess(value) {
    const raw = String(value || "").trim();
    const aliases = {
        "floor recovery (spady)": "Floor Recovery",
        "spady": "Floor Recovery",
        "short pick": "Short-Pick",
        "short-pick": "Short-Pick"
    };
    const alias = aliases[raw.toLowerCase()];
    if (alias) return alias;
    const match = EMPLOYEE_PROCESS_SKILLS.find(process => process.toLowerCase() === raw.toLowerCase());
    return match || raw;
}

function employeeQualifications(employee) {
    return Array.isArray(employee?.qualifications)
        ? employee.qualifications.filter(Boolean)
        : [];
}

function employeeProcessSkills(employee) {
    return Array.isArray(employee?.skills)
        ? employee.skills.filter(Boolean)
        : [];
}

function employeeHasQualification(employee, value) {
    return employeeQualifications(employee).includes(value);
}

function employeeHasProcessSkill(employee, value) {
    return employeeProcessSkills(employee).includes(value);
}

// Backward-compatible helper used by older render code.
function employeeSkills(employee) {
    return [...employeeQualifications(employee), ...employeeProcessSkills(employee)];
}

function employeeHasSkill(employee, skill) {
    return employeeSkills(employee).includes(skill);
}

function formatActionActor(name, timestamp) {
    const cleanName = String(name || "").trim() || "—";
    if (!timestamp) return esc(cleanName);

    const date = new Date(timestamp);
    const when = Number.isNaN(date.getTime())
        ? String(timestamp)
        : date.toLocaleString("en-GB", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        });

    return `
        <span class="action-actor-name">${esc(cleanName)}</span>
        <small class="action-actor-time">${esc(when)}</small>
    `;
}

function isTodayOrPast(date) {
    const today = startDay(new Date());
    return startDay(date).getTime() <= today.getTime();
}

function employeeStatusBadge(employee) {
    if (employee?.status !== "Former") return "";
    return `
        <span class="employee-status-badge former">
            FORMER
        </span>
    `;
}

// A worked day is counted only when attendance was explicitly confirmed
// and the final attendance status is not Absent. Planned/scheduled days
// are intentionally not counted. Each employee/date is counted once.
function employeeWorkedDays(employee) {
    const login = typeof employee === "string" ? employee : employee?.login;
    if (!login) return 0;

    const suffix = `_${login}`;
    const workedDates = new Set();

    Object.entries(attendance || {}).forEach(([key, data]) => {
        if (!key.endsWith(suffix)) return;

        const confirmed = Boolean(data?.confirmed);
        const status = String(data?.status || "").trim().toLowerCase();
        if (!confirmed || status === "absent") return;

        const workDate = key.slice(0, -suffix.length);
        if (workDate) workedDates.add(workDate);
    });

    return workedDates.size;
}

function employeeWorkedDaysForMonth(employee, monthDate) {
    const login = typeof employee === "string" ? employee : employee?.login;
    if (!login || !monthDate) return 0;
    const year = monthDate.getFullYear();
    const month = monthDate.getMonth();
    const suffix = `_${login}`;
    const workedDates = new Set();
    Object.entries(attendance || {}).forEach(([key, data]) => {
        if (!key.endsWith(suffix)) return;
        const datePart = key.slice(0, -suffix.length);
        const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(datePart);
        if (!match || Number(match[1]) !== year || Number(match[2]) !== month + 1) return;
        if (employee && !canConfirmEmployeeDate(employee, datePart)) return;
        const confirmed = Boolean(data?.confirmed);
        const status = String(data?.status || "").trim().toLowerCase();
        if (!confirmed || status === "absent") return;
        workedDates.add(datePart);
    });
    return workedDates.size;
}

function employeeDateKey(value) {
    if (!value) return "";
    const text = String(value).slice(0, 10);
    return /^\d{4}-\d{2}-\d{2}$/.test(text) ? text : "";
}

function canConfirmEmployeeDate(employee, date) {
    if (!employee || !date) return false;
    const startDate = employeeDateKey(employee.startDate);
    return !startDate || dateKey(date) >= startDate;
}

function attendanceMonitoringEmployees(monthDate = hoursAttendanceMonth) {
    const monthStart = dateKey(new Date(monthDate.getFullYear(), monthDate.getMonth(), 1, 12));
    const monthEnd = dateKey(new Date(monthDate.getFullYear(), monthDate.getMonth(), monthDays(monthDate), 12));
    return EMPLOYEES.filter(employee => {
        if (employee.status === "Active") return true;
        if (employee.status !== "Former" || !employee.endDate) return false;
        const end = employeeDateKey(employee.endDate);
        if (!end || end > monthEnd) return false;
        const endDate = fromKey(end);
        const keepUntil = dateKey(new Date(endDate.getFullYear(), endDate.getMonth() + 1, endDate.getDate(), 12));
        return monthStart <= keepUntil;
    });
}

function getHoursAttendanceEmployeeMetrics(employee, monthDate = hoursAttendanceMonth) {
    let planned = 0, confirmed = 0, pending = 0, absent = 0, underworked = 0, workedDays = 0, plannedDays = 0;
    const totalDays = monthDays(monthDate);
    for (let day = 1; day <= totalDays; day++) {
        const date = new Date(monthDate.getFullYear(), monthDate.getMonth(), day, 12);
        if (!canConfirmEmployeeDate(employee, date)) continue;
        const p = Number(plannedHours(employee, date) || 0);
        const data = getAttendance(employee, date);
        const actual = Number(data.actualHours || 0);
        planned += p;
        if (p > 0) plannedDays++;

        if (data.confirmed) {
            if (String(data.status || "").trim().toLowerCase() === "absent") {
                absent++;
            } else {
                confirmed += Number.isFinite(actual) ? actual : 0;
                workedDays++;
                if (p > 0 && actual < p) underworked += p - Math.max(0, actual);
            }
        } else if (p > 0) {
            pending++;
        }
    }
    const difference = confirmed - planned;
    const differenceDays = workedDays - plannedDays;
    const attendanceRate = plannedDays > 0 ? Math.round((workedDays / plannedDays) * 1000) / 10 : 0;
    return {
        planned, confirmed, difference, pending, absent, underworked, workedDays, attendanceRate,
        plannedDays, differenceDays
    };
}

function employeeSortValue(employee, key) {
    if (key === "qualifications") {
        return employeeQualifications(employee).join(", ").toLowerCase();
    }
    if (key === "processSkills") {
        return employeeProcessSkills(employee).join(", ").toLowerCase();
    }
    if (key === "workedDays") {
        return employeeWorkedDays(employee);
    }

    return String(employee?.[key] ?? "").toLowerCase();
}

const SHIFTS = {
    rest: {
        label: "R",
        start: "",
        end: "",
        presenceHours: 0,
        netHours: 0
    },
    day: {
        label: "DAY",
        start: "06:00",
        end: "16:45",
        presenceHours: 10.75,
        netHours: 10
    },
    night: {
        label: "NIGHT",
        start: "18:00",
        end: "04:45",
        presenceHours: 10.75,
        netHours: 10
    }
};

let EMPLOYEES = [];


/* =========================================================
   EMPLOYEES — SUPABASE
   The local array remains as a safe fallback if the database
   cannot be reached. When Supabase is available, it becomes
   the source of truth for the employee list.
========================================================= */

async function loadEmployeesFromSupabase() {
    const { data, error } = await supabaseClient
        .from("employees")
        .select("login, name, process, brigade, start_date, end_date, reason, status, qualifications, skills")
        .order("name", { ascending: true });

    if (error) {
        console.error("Employees load error:", error);
        return false;
    }

    // Supabase is the single source of truth. An empty table means
    // there are currently no employees; do not restore a stale JS list.
    if (!Array.isArray(data)) {
        EMPLOYEES = [];
        return false;
    }

    EMPLOYEES = data.map(employee => ({
        login: employee.login,
        name: employee.name,
        process: normalizeProcessName(employee.process),
        brigade: employee.brigade,
        startDate: employee.start_date || "",
        endDate: employee.end_date || "",
        reason: employee.reason || "",
        status: employee.status || "Active",
        qualifications: Array.isArray(employee.qualifications) ? employee.qualifications : [],
        skills: Array.isArray(employee.skills) ? employee.skills.map(normalizeSecondaryProcess).filter(Boolean) : []
    }));

    console.info(`Loaded ${EMPLOYEES.length} employees from Supabase.`);
    return true;
}

const STORAGE = {
    schedules: "warehouse_v2_schedules",
    attendance: "warehouse_v2_attendance",
    extraDays: "warehouse_v2_extra_days",
    scheduleHistory: "warehouse_v2_schedule_history"
};

let overviewDate = startDay(new Date());
let overviewShift = "day";

let schedules = readStorage(STORAGE.schedules, {});
let individualSchedules = readStorage("warehouse_v2_individual_schedules", {});
let attendance = readStorage(STORAGE.attendance, {});
let extraDays = readStorage(STORAGE.extraDays, {});
let scheduleHistory = readStorage(STORAGE.scheduleHistory, []);
let extraDaysRealtimeChannel = null;
let extraDaysRemoteLoaded = false;
let scheduleRealtimeChannel = null;
let scheduleRemoteLoaded = false;
let individualScheduleRealtimeChannel = null;
let individualScheduleRemoteLoaded = false;
let individualScheduleSaveInProgress = false;
let scheduleSaveInProgress = false;
let scheduleHistoryRealtimeChannel = null;
let employeesRealtimeChannel = null;
let auditRealtimeChannel = null;

let scheduleMonth = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    1,
    12
);

let scheduleBrigade = "A";
let activeSchedulingTab = "scheduleTab";

let hoursAttendanceMonth = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    1,
    12
);

let hoursAttendanceEmployeeLogin = "";
let hoursModalSource = "hours";
let hoursAttendanceDaySortKey = "";
let hoursAttendanceDaySortDirection = 1; // 1 = A/E/P/C/O priority, -1 = reverse
let attendanceActiveSubtab = "tracker";

// V27.1 — large-list rendering optimisation.
// Keep the first render lightweight and reveal more rows only on request.
const LARGE_LIST_PAGE_SIZE = 100;
let hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
let feedbackVisibleCount = LARGE_LIST_PAGE_SIZE;
let feedbackActiveSubtab = "tracker";

// =========================================================
// FEEDBACK TRACKER
// =========================================================
const FEEDBACK_ERROR_TYPES = [
    "False Short-Pick",
    "Full Box",
    "Duplicate",
    "Extra Pick",
    "Missing Pick",
    "Putback Error",
    "Bin Label",
    "Extra Putaway",
    "Missing Putaway",
    "BHP",
    "Machine Gunning",
    "Productivity Below Target"
];

const FEEDBACK_ERROR_ALIASES = {
    "false short-pick": "False Short-Pick",
    "false short pick": "False Short-Pick",
    "full box": "Full Box",
    "duplicat": "Duplicate",
    "duplicate": "Duplicate",
    "extra pick": "Extra Pick",
    "missing pick": "Missing Pick",
    "putback eror": "Putback Error",
    "putback error": "Putback Error",
    "bin etykieta": "Bin Label",
    "bin label": "Bin Label",
    "extra putaway": "Extra Putaway",
    "missing putaway": "Missing Putaway",
    "bhp": "BHP",
    "machine gunning": "Machine Gunning",
    "productivity below target": "Productivity Below Target"
};

function normalizeFeedbackErrorType(value) {
    const raw = String(value || "").trim();
    return FEEDBACK_ERROR_ALIASES[raw.toLowerCase()] || raw;
}
let feedbackMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1, 12);
let feedbackEntries = [];
let feedbackRealtimeChannel = null;
let feedbackLoaded = false;

function feedbackMonthKey() {
    return `${feedbackMonth.getFullYear()}-${String(feedbackMonth.getMonth()+1).padStart(2,"0")}`;
}

function feedbackDays() {
    return new Date(feedbackMonth.getFullYear(), feedbackMonth.getMonth()+1, 0).getDate();
}

function feedbackEntryEmployee(login) {
    return employeeByLogin(login) || EMPLOYEES.find(e => e.login === login);
}

async function loadFeedbackFromSupabase() {
    const first = `${feedbackMonthKey()}-01`;
    const last = `${feedbackMonthKey()}-${String(feedbackDays()).padStart(2,"0")}`;
    const { data, error } = await supabaseClient
        .from("feedback_entries")
        .select("id, work_date, employee_login, error_type, note, confirmed_by, confirmed_by_login, confirmed_by_name, confirmed_at, created_at")
        .gte("work_date", first)
        .lte("work_date", last)
        .order("work_date", { ascending: true })
        .order("created_at", { ascending: true });
    if (error) {
        console.error("Feedback load error:", error);
        feedbackEntries = [];
        feedbackLoaded = false;
        return false;
    }
    feedbackEntries = Array.isArray(data)
        ? data.map(entry => ({ ...entry, error_type: normalizeFeedbackErrorType(entry.error_type) }))
        : [];
    feedbackLoaded = true;
    return true;
}

function fillFeedbackFilters() {
    fillMultiFilter("feedbackBrigadeFilter", BRIGADES, "brigades", Object.fromEntries(BRIGADES.map(b => [b, `Brigade ${b}`])));
    fillMultiFilter("feedbackProcessFilter", PROCESSES, "processes");
    fillMultiFilter("feedbackErrorTypeFilter", FEEDBACK_ERROR_TYPES, "error-types");
    updateAllMultiFilterLabels();
}

function feedbackFilteredEmployees() {
    const search = $("feedbackSearch")?.value.trim().toLowerCase() || "";
    const brigades = selectedMultiValues("feedbackBrigadeFilter");
    const processes = selectedMultiValues("feedbackProcessFilter");
    return activeEmployees().filter(employee => {
        const text = `${employee.login} ${employee.name} ${employee.process} ${employee.brigade}`.toLowerCase();
        if (search && !text.includes(search)) return false;
        if (brigades.length && !brigades.includes(employee.brigade)) return false;
        if (processes.length && !processes.includes(employee.process)) return false;
        return true;
    }).sort((a,b) => a.name.localeCompare(b.name));
}

function feedbackTotalClass(total) {
    if (total >= 6) return "high";
    if (total >= 3) return "medium";
    return "low";
}

function feedbackActor(entry) {
    const name = String(entry.confirmed_by_name || entry.confirmed_by_login || "—").trim() || "—";
    const time = entry.confirmed_at ? new Date(entry.confirmed_at).toLocaleString("en-GB", {day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit"}) : "";
    return time ? `${name} · ${time}` : name;
}

function openFeedbackModal(login) {
    const employee = feedbackEntryEmployee(login);
    if (!employee) return;
    $("feedbackEmployeeLogin").value = login;
    $("feedbackEmployeeLabel").textContent = `${employee.name} · ${employee.login}`;
    $("feedbackDate").value = `${feedbackMonthKey()}-${String(Math.min(new Date().getDate(), feedbackDays())).padStart(2,"0")}`;
    $("feedbackErrorType").value = "";
    $("feedbackNote").value = "";
    $("feedbackConfirmedBy").textContent = currentUser?.name || currentUser?.login || "—";
    $("feedbackModal").classList.remove("hidden");
}

function closeFeedbackModal() { $("feedbackModal")?.classList.add("hidden"); }

function openFeedbackEmployeeHistoryModal(login) {
    const employee = feedbackEntryEmployee(login);
    if (!employee) return;

    const monthKey = feedbackMonthKey();
    const entries = feedbackEntries
        .filter(entry => String(entry.employee_login || "") === String(login) && String(entry.work_date || "").slice(0, 7) === monthKey)
        .sort((a, b) => {
            const dateCompare = String(b.work_date || "").localeCompare(String(a.work_date || ""));
            if (dateCompare !== 0) return dateCompare;
            return String(b.created_at || "").localeCompare(String(a.created_at || ""));
        });

    $("feedbackEmployeeHistoryLabel").textContent = `${employee.name} · ${employee.login}`;
    $("feedbackEmployeeHistoryMeta").textContent = `${entries.length} feedback entr${entries.length === 1 ? "y" : "ies"} · ${feedbackMonth.toLocaleDateString("en-GB", {month:"long", year:"numeric"})}`;
    $("feedbackEmployeeHistoryBody").innerHTML = entries.map(entry => {
        return `<tr><td>${esc(entry.work_date)}</td><td><strong>${esc(entry.error_type)}</strong></td><td>${esc(entry.note || "—")}</td><td>${formatActionActor(entry.confirmed_by_name, entry.confirmed_at)}</td></tr>`;
    }).join("") || `<tr><td colspan="4"><div class="empty">No feedback entries for this employee in the selected month.</div></td></tr>`;

    $("feedbackEmployeeHistoryModal").classList.remove("hidden");
}

function closeFeedbackEmployeeHistoryModal() {
    $("feedbackEmployeeHistoryModal")?.classList.add("hidden");
}

async function saveFeedbackEntry(event) {
    event.preventDefault();
    const login = $("feedbackEmployeeLogin").value;
    const date = $("feedbackDate").value;
    const errorType = normalizeFeedbackErrorType($("feedbackErrorType").value);
    const note = $("feedbackNote").value.trim();
    const employee = feedbackEntryEmployee(login);
    if (!employee || !date || !errorType) { toast("Select a date and error type."); return; }
    if (date.slice(0,7) !== feedbackMonthKey()) { toast("Select a date from the displayed month."); return; }
    if (date > dateKey(new Date())) { toast("Feedback cannot be recorded for a future date."); return; }
    if (!currentUser?.id) { toast("Current user is not available. Please sign in again."); return; }

    const payload = {
        work_date: date,
        employee_login: login,
        error_type: errorType,
        note: note || null,
        confirmed_by: currentUser.id,
        confirmed_by_login: currentUser.login || "",
        confirmed_by_name: currentUser.name || currentUser.login || "",
        confirmed_at: new Date().toISOString()
    };
    const { data, error } = await supabaseClient.from("feedback_entries").insert(payload).select("id, work_date, employee_login, error_type, note, confirmed_by, confirmed_by_login, confirmed_by_name, confirmed_at, created_at").single();
    if (error) { console.error("Feedback save error:", error); toast(`Could not save feedback: ${error.message}`); return; }
    feedbackEntries.push(data);
    closeFeedbackModal();
    renderFeedbackTracker();
    toast(`${employee.name}: feedback recorded.`);
}

function feedbackErrorTypesForMonth() {
    return [...new Set(feedbackEntries.map(entry => String(entry.error_type || "Other").trim()).filter(Boolean))].sort((a,b) => a.localeCompare(b));
}

function selectedFeedbackErrorTypes() {
    return selectedMultiValues("feedbackErrorTypeFilter");
}

function feedbackEntriesFilteredForView() {
    const types = selectedFeedbackErrorTypes();
    if (!types.length) return feedbackEntries;
    return feedbackEntries.filter(entry => types.includes(entry.error_type));
}

function feedbackEntriesFor(login, day) {
    const date = `${feedbackMonthKey()}-${String(day).padStart(2,"0")}`;
    return feedbackEntriesFilteredForView().filter(entry => entry.employee_login === login && entry.work_date === date);
}

function feedbackTotalFor(login) {
    return feedbackEntriesFilteredForView().filter(entry => entry.employee_login === login).length;
}

function renderFeedbackErrorStats() {
    const days = feedbackDays();
    const source = feedbackEntriesFilteredForView();
    const types = [...new Set(source.map(e => String(e.error_type || "Other").trim()).filter(Boolean))]
        .sort((a,b) => a.localeCompare(b));
    const monthTotal = source.length;
    const countFor = (type, day) => source.filter(e =>
        e.error_type === type && e.work_date === `${feedbackMonthKey()}-${String(day).padStart(2,"0")}`
    ).length;

    // Summary by error type: count and percentage of all feedback.
    const summaryRows = types.map(type => {
        const count = source.filter(e => e.error_type === type).length;
        const pct = monthTotal ? (count / monthTotal * 100) : 0;
        return `<tr><td><strong>${esc(type)}</strong></td><td>${count}</td><td>${pct.toFixed(1)}%</td></tr>`;
    });
    if (monthTotal) {
        summaryRows.push(`<tr class="feedback-stats-total-row"><td><strong>All errors</strong></td><td><strong>${monthTotal}</strong></td><td><strong>100.0%</strong></td></tr>`);
    }
    const summaryBody = $("feedbackStatsSummaryBody");
    if (summaryBody) {
        summaryBody.innerHTML = summaryRows.join("") || `<tr><td colspan="3"><div class="empty">No feedback statistics for the selected filters.</div></td></tr>`;
    }

    // Detailed matrix: every error type, every day, monthly total and share.
    const head = ["<tr><th>Error type</th>"];
    for (let day=1; day<=days; day++) head.push(`<th>${day}</th>`);
    head.push("<th>Total</th><th>%</th></tr>");
    const matrixRows = types.map(type => {
        let total = 0;
        const cells = [];
        for (let day=1; day<=days; day++) {
            const count = countFor(type, day);
            total += count;
            cells.push(`<td>${count}</td>`);
        }
        const pct = monthTotal ? (total / monthTotal * 100) : 0;
        return `<tr><td><strong>${esc(type)}</strong></td>${cells.join("")}<td><strong>${total}</strong></td><td><strong>${pct.toFixed(1)}%</strong></td></tr>`;
    });
    const dailyTotals = [];
    const dailyPcts = [];
    for (let day=1; day<=days; day++) {
        const count = source.filter(e => e.work_date === `${feedbackMonthKey()}-${String(day).padStart(2,"0")}`).length;
        dailyTotals.push(`<td><strong>${count}</strong></td>`);
        dailyPcts.push(`<td>${monthTotal ? (count / monthTotal * 100).toFixed(1) : "0.0"}%</td>`);
    }
    if (monthTotal) {
        matrixRows.push(`<tr class="feedback-stats-total-row"><td><strong>All errors</strong></td>${dailyTotals.join("")}<td><strong>${monthTotal}</strong></td><td><strong>100.0%</strong></td></tr>`);
        matrixRows.push(`<tr class="feedback-stats-percent-row"><td><strong>Daily share</strong></td>${dailyPcts.join("")}<td><strong>100.0%</strong></td><td><strong>100.0%</strong></td></tr>`);
    }
    $("feedbackStatsHead").innerHTML = head.join("");
    $("feedbackStatsBody").innerHTML = matrixRows.join("") || `<tr><td colspan="${days+6}"><div class="empty">No feedback statistics for the selected filters.</div></td></tr>`;

    // Daily overview: useful for spotting high-error days at a glance.
    const dailyRows = [];
    for (let day=1; day<=days; day++) {
        const count = source.filter(e => e.work_date === `${feedbackMonthKey()}-${String(day).padStart(2,"0")}`).length;
        const pct = monthTotal ? count / monthTotal * 100 : 0;
        dailyRows.push(`<tr><td>${day}</td><td>${feedbackMonthKey()}-${String(day).padStart(2,"0")}</td><td><strong>${count}</strong></td><td>${pct.toFixed(1)}%</td></tr>`);
    }
    const dailyBody = $("feedbackDailyStatsBody");
    if (dailyBody) dailyBody.innerHTML = dailyRows.join("");
}

function renderFeedbackAdditionalStats(source) {
    const total = source.length;
    const employeeCounts = new Map();
    const brigadeCounts = new Map();
    const processCounts = new Map();
    const typeCounts = new Map();
    source.forEach(entry => {
        const employee = feedbackEntryEmployee(entry.employee_login);
        employeeCounts.set(entry.employee_login, (employeeCounts.get(entry.employee_login) || 0) + 1);
        const brigade = employee?.brigade || "Unknown";
        const process = employee?.process || "Unknown";
        const type = entry.error_type || "Other";
        brigadeCounts.set(brigade, (brigadeCounts.get(brigade) || 0) + 1);
        processCounts.set(process, (processCounts.get(process) || 0) + 1);
        typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    });
    const topFromMap = map => [...map.entries()].sort((a,b)=>b[1]-a[1] || String(a[0]).localeCompare(String(b[0])))[0];
    const topType = topFromMap(typeCounts);
    const topBrigade = topFromMap(brigadeCounts);
    if ($("feedbackKpiTotal")) $("feedbackKpiTotal").textContent = String(total);
    if ($("feedbackKpiEmployees")) $("feedbackKpiEmployees").textContent = String(employeeCounts.size);
    if ($("feedbackKpiAverage")) $("feedbackKpiAverage").textContent = employeeCounts.size ? (total / employeeCounts.size).toFixed(1) : "0.0";
    if ($("feedbackKpiTopError")) $("feedbackKpiTopError").textContent = topType?.[0] || "—";
    if ($("feedbackKpiTopErrorCount")) $("feedbackKpiTopErrorCount").textContent = `${topType?.[1] || 0} feedback`;
    if ($("feedbackKpiTopBrigade")) $("feedbackKpiTopBrigade").textContent = topBrigade?.[0] || "—";
    if ($("feedbackKpiTopBrigadeCount")) $("feedbackKpiTopBrigadeCount").textContent = `${topBrigade?.[1] || 0} feedback`;

    const pct = count => total ? (count / total * 100).toFixed(1) : "0.0";
    const employeeMap = employeeCounts;
    const brigadeMap = brigadeCounts;
    const processMap = processCounts;
    const renderRows = (map, labelFn) => [...map.entries()]
        .sort((a,b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
        .map(([key,count]) => `<tr><td><strong>${esc(labelFn(key))}</strong></td><td>${count}</td><td>${pct(count)}%</td></tr>`)
        .join("") || `<tr><td colspan="3"><div class="empty">No data.</div></td></tr>`;

    const brigadeBody = $("feedbackStatsBrigadeBody");
    const processBody = $("feedbackStatsProcessBody");
    const employeeBody = $("feedbackStatsEmployeeBody");
    if (brigadeBody) brigadeBody.innerHTML = renderRows(brigadeMap, key => key);
    if (processBody) processBody.innerHTML = renderRows(processMap, key => key);
    if (employeeBody) {
        const rows = [...employeeMap.entries()]
            .sort((a,b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
            .map(([login,count]) => {
                const e = feedbackEntryEmployee(login);
                return `<tr><td><strong>${esc(e?.name || login)}</strong><br><small>${esc(login)}</small></td><td>${count}</td><td>${pct(count)}%</td></tr>`;
            }).join("");
        employeeBody.innerHTML = rows || `<tr><td colspan="3"><div class="empty">No employees with feedback.</div></td></tr>`;
    }
}

function activateFeedbackSubtab(name) {
    feedbackActiveSubtab = name;
    document.querySelectorAll("[data-feedback-subtab]").forEach(button => button.classList.toggle("active", button.dataset.feedbackSubtab === name));
    document.querySelectorAll(".feedback-subtab-panel").forEach(panel => panel.classList.remove("active"));
    const target = $(name === "tracker" ? "feedbackTrackerSubpage" : name === "statistics" ? "feedbackStatisticsSubpage" : "feedbackHistorySubpage");
    target?.classList.add("active");
    renderFeedbackCurrentSubtab();
}

function buildFeedbackDailyIndex(source) {
    const byDay = new Map();
    const byEmployee = new Map();
    const byEmployeeDayEntries = new Map();

    source.forEach(entry => {
        const employeeLogin = String(entry.employee_login || "");
        const dayKey = `${employeeLogin}_${entry.work_date}`;
        byDay.set(dayKey, (byDay.get(dayKey) || 0) + 1);
        byEmployee.set(employeeLogin, (byEmployee.get(employeeLogin) || 0) + 1);

        const entries = byEmployeeDayEntries.get(dayKey);
        if (entries) entries.push(entry);
        else byEmployeeDayEntries.set(dayKey, [entry]);
    });

    return { byDay, byEmployee, byEmployeeDayEntries };
}

function renderFeedbackTrackerTable(employees, filtered) {
    const days = feedbackDays();
    const index = buildFeedbackDailyIndex(filtered);
    const visibleEmployees = employees.slice(0, feedbackVisibleCount);

    const head = ["<tr><th class=\"feedback-login-col\">Login</th><th class=\"feedback-name-col\">Name</th><th class=\"feedback-brigade-col\">Brigade</th><th class=\"feedback-process-col\">Process</th><th class=\"feedback-worked-col\">Worked days</th><th class=\"feedback-start-col\">Start date</th><th class=\"feedback-total-col\"><span>Feedback</span><small>Month total</small></th>"];
    for (let day=1; day<=days; day++) head.push(`<th class="feedback-day-col">${day}</th>`);
    head.push(`<th class="feedback-add-col">Add</th></tr>`);
    $("feedbackTableHead").innerHTML = head.join("");

    $("feedbackTableBody").innerHTML = visibleEmployees.map(employee => {
        const total = index.byEmployee.get(employee.login) || 0;
        const cells = [];
        for (let day=1; day<=days; day++) {
            const date = `${feedbackMonthKey()}-${String(day).padStart(2,"0")}`;
            const key = `${employee.login}_${date}`;
            const entries = index.byEmployeeDayEntries.get(key) || [];
            const count = index.byDay.get(key) || 0;
            const title = entries.length ? entries.map(e => `${e.error_type}${e.note ? ` — ${e.note}` : ""} — ${feedbackActor(e)}`).join("\n") : "No feedback";
            cells.push(`<td class="feedback-day-cell" title="${esc(title)}"><span class="feedback-count">${count}</span></td>`);
        }
        const workedDays = employeeWorkedDaysForMonth(employee, feedbackMonth);
        return `<tr><td class="feedback-login-cell"><strong>${esc(employee.login)}</strong></td><td class="feedback-name-cell">${esc(employee.name)}</td><td class="feedback-brigade-cell">${esc(employee.brigade)}</td><td class="feedback-process-cell">${esc(employee.process)}</td><td class="feedback-worked-cell"><strong>${workedDays}</strong></td><td class="feedback-start-cell">${esc(employee.startDate || "—")}</td><td class="feedback-total-cell"><button class="feedback-total-chip feedback-total-button ${feedbackTotalClass(total)}" type="button" data-feedback-history="${esc(employee.login)}" aria-label="Open all feedback for ${esc(employee.name)}">${total}</button></td>${cells.join("")}<td class="feedback-add-cell"><button class="primary feedback-add-btn" type="button" data-feedback-add="${esc(employee.login)}" aria-label="Add feedback for ${esc(employee.name)}">+</button></td></tr>`;
    }).join("") || `<tr><td colspan="${days+8}"><div class="empty">No employees match the selected filters.</div></td></tr>`;

    const moreWrap = $("feedbackMoreWrap");
    const moreButton = $("feedbackMoreBtn");
    const hasMore = visibleEmployees.length < employees.length;
    if (moreWrap) moreWrap.hidden = !hasMore;
    if (moreButton) {
        moreButton.textContent = hasMore ? `More (${Math.min(LARGE_LIST_PAGE_SIZE, employees.length - visibleEmployees.length)})` : "More";
        moreButton.disabled = !hasMore;
    }
    const meta = $("feedbackMeta");
    if (meta) {
        meta.textContent = `${visibleEmployees.length} of ${employees.length} employee${employees.length===1?"":"s"} shown · ${filtered.length} feedback entr${filtered.length===1?"y":"ies"}`;
    }

    document.querySelectorAll("[data-feedback-add]").forEach(button => button.addEventListener("click", () => openFeedbackModal(button.dataset.feedbackAdd)));
    document.querySelectorAll("[data-feedback-history]").forEach(button => button.addEventListener("click", () => openFeedbackEmployeeHistoryModal(button.dataset.feedbackHistory)));
}

function renderFeedbackHistory(filtered) {
    const history = [...filtered].sort((a,b) => String(b.created_at||"").localeCompare(String(a.created_at||""))).slice(0,200);
    $("feedbackHistoryTable").innerHTML = history.map(entry => {
        const employee = feedbackEntryEmployee(entry.employee_login);
        return `<tr><td>${esc(entry.work_date)}</td><td><strong>${esc(employee?.login || entry.employee_login)}</strong><br>${esc(employee?.name || "")}</td><td>${esc(entry.error_type)}</td><td>${esc(entry.note || "—")}</td><td>${formatActionActor(entry.confirmed_by_name, entry.confirmed_at)}</td></tr>`;
    }).join("") || `<tr><td colspan="5"><div class="empty">No feedback entries for this month.</div></td></tr>`;
}

function renderFeedbackCurrentSubtab() {
    const filtered = feedbackEntriesFilteredForView();
    if (feedbackActiveSubtab === "statistics") {
        renderFeedbackErrorStats();
        renderFeedbackAdditionalStats(filtered);
        return;
    }
    if (feedbackActiveSubtab === "history") {
        renderFeedbackHistory(filtered);
        return;
    }

    const employees = feedbackFilteredEmployees();
    renderFeedbackTrackerTable(employees, filtered);
}

function renderFeedbackTracker() {
    const filtered = feedbackEntriesFilteredForView();
    $("feedbackMonthLabel").textContent = feedbackMonth.toLocaleDateString("en-GB", {month:"long", year:"numeric"});
    renderFeedbackCurrentSubtab();

    // Keep the main tracker fast on entry. Statistics and history are now
    // rendered only when their own subtab is opened.
    if (feedbackActiveSubtab === "tracker") {
        const employees = feedbackFilteredEmployees();
        const meta = $("feedbackMeta");
        if (meta) meta.textContent = `${Math.min(feedbackVisibleCount, employees.length)} of ${employees.length} employee${employees.length===1?"":"s"} shown · ${filtered.length} feedback entr${filtered.length===1?"y":"ies"}`;
    }
}

function showMoreFeedbackEmployees() {
    const employees = feedbackFilteredEmployees();
    if (feedbackVisibleCount >= employees.length) return;
    feedbackVisibleCount = Math.min(feedbackVisibleCount + LARGE_LIST_PAGE_SIZE, employees.length);
    renderFeedbackCurrentSubtab();
}

function subscribeToFeedbackRealtime() {
    if (feedbackRealtimeChannel || !currentUser) return;
    feedbackRealtimeChannel = supabaseClient.channel("warehouse-feedback")
        .on("postgres_changes", {event:"*", schema:"public", table:"feedback_entries"}, async payload => {
            console.info("Feedback realtime update:", payload.eventType);
            await loadFeedbackFromSupabase();
            if ($("feedbackTrackerPage")?.classList.contains("active-page")) {
                renderFeedbackTracker();
            }
        })
        .subscribe(status => console.info("Feedback realtime status:", status));
}


function $(id) {
    return document.getElementById(id);
}

function readStorage(key, fallback) {
    try {
        const value = localStorage.getItem(key);
        return value ? JSON.parse(value) : fallback;
    } catch {
        return fallback;
    }
}


function clearWmsClientData() {
    try {
        Object.values(STORAGE || {}).forEach(key => localStorage.removeItem(key));
        localStorage.removeItem("warehouse_v2_individual_schedules");
        localStorage.removeItem("warehouse_v3_audit");
    } catch (error) {
        console.warn("Could not clear local WMS data:", error);
    }
}

function saveStorage() {
    localStorage.setItem(STORAGE.schedules, JSON.stringify(schedules));
    localStorage.setItem(STORAGE.attendance, JSON.stringify(attendance));
    localStorage.setItem(STORAGE.extraDays, JSON.stringify(extraDays));
    localStorage.setItem(STORAGE.scheduleHistory, JSON.stringify(scheduleHistory));
}

function startDay(value) {
    const d = new Date(value);
    return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 12);
}

function dateKey(value) {
    const d = new Date(value);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function fromKey(value) {
    return new Date(`${value}T12:00:00`);
}

function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function subscribeToEmployeesRealtime() {
    if (employeesRealtimeChannel || !currentUser) return;
    employeesRealtimeChannel = supabaseClient
        .channel("warehouse-employees")
        .on("postgres_changes", { event: "*", schema: "public", table: "employees" }, async payload => {
            console.info("Employees realtime update:", payload.eventType);
            const loaded = await loadEmployeesFromSupabase();
            if (loaded) {
                fillOverviewFilters();
                fillEmployeeFilters();
                fillFeedbackFilters();
                renderEmployeeDatabase();
                renderFormerEmployees();
                renderStatistics();
                renderOverview();

                if ($("hoursAttendancePage")?.classList.contains("active-page")) {
                    hoursAllVisibleCount = Math.min(hoursAllVisibleCount, LARGE_LIST_PAGE_SIZE);
                    renderAllHoursAttendance();
                }
                if ($("feedbackTrackerPage")?.classList.contains("active-page")) {
                    feedbackVisibleCount = Math.min(feedbackVisibleCount, LARGE_LIST_PAGE_SIZE);
                    renderFeedbackTracker();
                }
            }
        })
        .subscribe(status => console.info("Employees realtime status:", status));
}

function activeEmployees() {
    return EMPLOYEES.filter(employee => employee.status === "Active");
}

function employeesAvailableOnDate(date) {
    return EMPLOYEES.filter(employee => {
        if (employee.status === "Active") return true;
        if (employee.status !== "Former") return false;
        return Boolean(employee.endDate) && String(date) <= String(employee.endDate);
    });
}

function employeeByLogin(login) {
    return EMPLOYEES.find(
        employee => String(employee.login) === String(login)
    );
}

async function loadExtraDaysFromSupabase() {
    if (!currentUser) return false;

    const { data, error } = await supabaseClient
        .from("schedule_exceptions")
        .select("id, work_date, employee_login, type, shift, leader_id, leader_login, leader_name, created_at")
        .order("work_date", { ascending: true });

    if (error) {
        console.error("Extra Days load error:", error);
        return false;
    }

    const rows = data || [];

    // One-time migration for existing local Extra Days when the central table is empty.
    // The current authenticated user becomes the recorded approver for migrated legacy rows.
    if (!rows.length && Object.keys(extraDays).length && currentUser?.id) {
        const legacyRows = Object.entries(extraDays).map(([key, item]) => {
            const split = key.lastIndexOf("_");
            const workDate = key.slice(0, split);
            const employeeLogin = key.slice(split + 1);
            return {
                work_date: workDate,
                employee_login: employeeLogin,
                type: item.type,
                shift: item.type === "extra-off" ? null : (item.shift || "day"),
                leader_id: currentUser.id,
                leader_login: currentUser.login,
                leader_name: currentUser.name || currentUser.login
            };
        });

        const { data: migrated, error: migrateError } = await supabaseClient
            .from("schedule_exceptions")
            .upsert(legacyRows, { onConflict: "work_date,employee_login" })
            .select("id, work_date, employee_login, type, shift, leader_id, leader_login, leader_name, created_at");

        if (!migrateError) {
            rows.push(...(migrated || []));
        } else {
            console.warn("Legacy Extra Days migration skipped:", migrateError);
        }
    }

    const next = {};
    rows.forEach(row => {
        const key = `${row.work_date}_${row.employee_login}`;
        next[key] = {
            id: row.id,
            type: row.type,
            shift: row.shift || null,
            leaderLogin: row.leader_login || "",
            leaderName: row.leader_name || "",
            leaderId: row.leader_id || "",
            createdAt: row.created_at || ""
        };
    });

    extraDays = next;
    extraDaysRemoteLoaded = true;
    saveStorage();
    return true;
}

function subscribeToExtraDaysRealtime() {
    if (extraDaysRealtimeChannel || !currentUser) return;

    extraDaysRealtimeChannel = supabaseClient
        .channel("warehouse-extra-days")
        .on(
            "postgres_changes",
            { event: "*", schema: "public", table: "schedule_exceptions" },
            async payload => {
                console.info("Extra Days realtime update:", payload.eventType);
                const loaded = await loadExtraDaysFromSupabase();
                if (loaded) {
                    renderScheduling();
                    renderOverview();
                    updateExtraScheduleHint();
                    toast("Schedule updated.");
                }
            }
        )
        .subscribe(status => {
            console.info("Extra Days realtime status:", status);
        });
}

function scheduleKey(date, login) {
    return `${dateKey(date)}_${login}`;
}

function attendanceKey(date, login) {
    return `${dateKey(date)}_${login}`;
}

function defaultShiftForBrigade(brigade) {
    return ["N1", "N2"].includes(brigade) ? "night" : "day";
}


async function loadSchedulesFromSupabase() {
    if (!currentUser) return false;

    // Supabase REST returns a maximum of 1000 rows per request by default.
    // A full month can easily contain 64 employees × 30/31 days = 1920/1984 rows.
    // Loading only the first page was the reason the UI looked like only part of
    // the month had been scheduled. Always page through the complete result set.
    const pageSize = 1000;
    const rows = [];
    let from = 0;

    while (true) {
        const { data, error } = await supabaseClient
            .from("shift_schedules")
            .select("id, work_date, employee_login, shift, updated_by, updated_by_login, created_at, updated_at")
            .order("work_date", { ascending: true })
            .order("employee_login", { ascending: true })
            .range(from, from + pageSize - 1);

        if (error) {
            console.error("Monthly Schedule load error:", error);
            return false;
        }

        const page = data || [];
        rows.push(...page);

        if (page.length < pageSize) break;
        from += pageSize;
    }

    // One-time migration of the existing local schedule into the central table.
    // Only runs when the central table is empty, so an existing central schedule is never overwritten.
    if (!rows.length && Object.keys(schedules).length && currentUser?.id) {
        const legacyRows = Object.entries(schedules).map(([key, shift]) => {
            const split = key.lastIndexOf("_");
            return {
                work_date: key.slice(0, split),
                employee_login: key.slice(split + 1),
                shift,
                updated_by: currentUser.id,
                updated_by_login: currentUser.login
            };
        });

        const migrated = [];
        for (let i = 0; i < legacyRows.length; i += 500) {
            const batch = legacyRows.slice(i, i + 500);
            const { data: batchData, error: migrateError } = await supabaseClient
                .from("shift_schedules")
                .upsert(batch, { onConflict: "work_date,employee_login" })
                .select("id, work_date, employee_login, shift, updated_by, updated_by_login, created_at, updated_at");

            if (migrateError) {
                console.warn("Legacy Monthly Schedule migration stopped:", migrateError);
                break;
            }
            migrated.push(...(batchData || []));
        }

        if (migrated.length) {
            rows.push(...migrated);
        }
    }

    const next = {};
    rows.forEach(row => {
        const key = `${row.work_date}_${row.employee_login}`;
        next[key] = row.shift;
    });

    schedules = next;
    scheduleRemoteLoaded = true;
    saveStorage();
    return true;
}

let scheduleRealtimeTimer = null;
let scheduleRealtimeReloadInProgress = false;

function scheduleRealtimeRefresh() {
    if (scheduleRealtimeTimer) clearTimeout(scheduleRealtimeTimer);

    // A monthly brigade save can generate hundreds/thousands of database events.
    // Do one authoritative reload after the burst instead of one reload per row.
    scheduleRealtimeTimer = setTimeout(async () => {
        scheduleRealtimeTimer = null;
        if (scheduleRealtimeReloadInProgress) return;

        scheduleRealtimeReloadInProgress = true;
        try {
            const loaded = await loadSchedulesFromSupabase();
            if (loaded) {
                const tabToKeep = activeSchedulingTab;
                renderScheduling();
                setSchedulingTab(tabToKeep);
                renderOverview();
                renderHoursAttendance();
            }
        } finally {
            scheduleRealtimeReloadInProgress = false;
        }
    }, 500);
}

function subscribeToScheduleRealtime() {
    if (scheduleRealtimeChannel || !currentUser) return;

    scheduleRealtimeChannel = supabaseClient
        .channel("warehouse-shift-schedules")
        .on(
            "postgres_changes",
            { event: "*", schema: "public", table: "shift_schedules" },
            payload => {
                console.info("Monthly Schedule realtime update:", payload.eventType);
                scheduleRealtimeRefresh();
            }
        )
        .subscribe(status => {
            console.info("Monthly Schedule realtime status:", status);
        });
}

async function loadIndividualSchedulesFromSupabase() {
    if (!currentUser) return false;

    const pageSize = 1000;
    const rows = [];
    let from = 0;

    while (true) {
        const { data, error } = await supabaseClient
            .from("employee_schedule_overrides")
            .select("id, work_date, employee_login, shift, updated_by, updated_by_login, created_at, updated_at")
            .order("work_date", { ascending: true })
            .order("employee_login", { ascending: true })
            .range(from, from + pageSize - 1);

        if (error) {
            console.error("Individual Schedule load error:", error);
            return false;
        }
        const page = data || [];
        rows.push(...page);
        if (page.length < pageSize) break;
        from += pageSize;
    }

    const next = {};
    rows.forEach(row => {
        next[`${row.work_date}_${row.employee_login}`] = row.shift;
    });
    individualSchedules = next;
    individualScheduleRemoteLoaded = true;
    localStorage.setItem("warehouse_v2_individual_schedules", JSON.stringify(individualSchedules));
    return true;
}

let individualScheduleRealtimeTimer = null;
let individualScheduleRealtimeReloadInProgress = false;

function individualScheduleRealtimeRefresh() {
    if (individualScheduleRealtimeTimer) clearTimeout(individualScheduleRealtimeTimer);
    individualScheduleRealtimeTimer = setTimeout(async () => {
        individualScheduleRealtimeTimer = null;
        if (individualScheduleRealtimeReloadInProgress) return;
        individualScheduleRealtimeReloadInProgress = true;
        try {
            const loaded = await loadIndividualSchedulesFromSupabase();
            if (loaded) {
                renderScheduling();
                renderOverview();
                renderHoursAttendance();
            }
        } finally {
            individualScheduleRealtimeReloadInProgress = false;
        }
    }, 350);
}

function subscribeToIndividualScheduleRealtime() {
    if (individualScheduleRealtimeChannel || !currentUser) return;
    individualScheduleRealtimeChannel = supabaseClient
        .channel("warehouse-employee-schedule-overrides")
        .on("postgres_changes", { event: "*", schema: "public", table: "employee_schedule_overrides" }, payload => {
            console.info("Individual Schedule realtime update:", payload.eventType);
            individualScheduleRealtimeRefresh();
        })
        .subscribe(status => console.info("Individual Schedule realtime status:", status));
}

function individualScheduleValue(employee, date) {
    return individualSchedules[scheduleKey(date, employee.login)] || "";
}

function getSchedule(employee, date) {
    const key = scheduleKey(date, employee.login);
    const individual = individualSchedules[key];
    const extra = extraDays[key];

    // Priority: individual override > Extra Day exception > brigade schedule > default.
    if (individual) return { shift: individual, source: "individual" };
    if (extra) return { shift: extra.type === "extra-off" ? "off" : extra.shift, source: "extra" };
    if (!schedules[key]) return { shift: defaultShiftForBrigade(employee.brigade), source: "default" };
    return { shift: schedules[key], source: "saved" };
}

const ALLOWED_ATTENDANCE_REASONS = [
    "Private leave",
    "Forced leave",
    "Feeling unwell",
    "Terminated",
    "Other"
];

function normalizeAttendanceData(data = {}) {
    const confirmed = Boolean(data.confirmed);
    const legacyStatus = String(data.status || "Pending");
    let reason = ALLOWED_ATTENDANCE_REASONS.includes(String(data.reason || ""))
        ? String(data.reason)
        : "";

    const legacyReasonMap = {
        "Private leave": "Private leave",
        "Forced leave": "Forced leave",
        "Feeling unwell": "Feeling unwell",
        "Poor health": "Feeling unwell",
        "Shein leave": "Private leave",
        "No work": "Other",
        "Terminated": "Terminated",
        "Late": "Other",
        "Left early": "Other"
    };
    if (!reason && legacyReasonMap[legacyStatus]) reason = legacyReasonMap[legacyStatus];
    // Terminated is a persistent business state. If the DB has captured the
    // terminated flag, never let a full-hours confirmation clear the reason.
    if (data.terminatedRecord === true) reason = "Terminated";

    return {
        ...data,
        confirmed,
        actualHours: Number(data.actualHours || 0),
        actualStart: data.actualStart || "",
        actualEnd: data.actualEnd || "",
        breakMinutes: Number(data.breakMinutes || 0),
        status: confirmed ? (legacyStatus === "Absent" ? "Absent" : "Confirmed") : "Pending",
        reason
    };
}

function isTerminatedOnDate(employee, date) {
    if (!employee || employee.status !== "Former" || !employee.endDate) return false;
    return String(dateKey(date)) >= String(employee.endDate);
}

function getAttendance(employee, date) {
    const existing = attendance[attendanceKey(date, employee.login)];
    return normalizeAttendanceData(existing || {
        confirmed: false,
        actualHours: 0,
        actualStart: "",
        actualEnd: "",
        breakMinutes: 0,
        status: "Pending",
        reason: isTerminatedOnDate(employee, date) ? "Terminated" : "",
        terminatedRecord: isTerminatedOnDate(employee, date),
        note: ""
    });
}

let attendanceRealtimeChannel = null;
let attendanceRemoteLoaded = false;
let attendanceRemoteReady = false;

function attendanceRowFromLocal(employee, date, data) {
    const schedule = getSchedule(employee, date);
    const shift = schedule.shift || "off";
    const planned = plannedHours(employee, date);

    return {
        work_date: dateKey(date),
        employee_login: employee.login,
        shift,
        planned_hours: Number(planned || 0),
        actual_hours: Number(data?.actualHours || 0),
        actual_start: data?.actualStart || null,
        actual_end: data?.actualEnd || null,
        break_minutes: Number(data?.breakMinutes || 0),
        status: data?.status || "Pending",
        reason: data?.reason || "",
        reason_record: data?.reason || "",
        terminated_record: data?.terminatedRecord === true || data?.reason === "Terminated",
        note: data?.note || "",
        confirmed: Boolean(data?.confirmed),
        confirmed_by: data?.confirmedById || (data?.confirmed ? (currentUser?.id || null) : null),
        confirmed_by_login: data?.confirmedByLogin || (data?.confirmed ? (currentUser?.login || "") : ""),
        confirmed_by_name: data?.confirmedByName || (data?.confirmed ? (currentUser?.name || currentUser?.login || "") : ""),
        confirmed_at: data?.confirmedAt || (data?.confirmed ? new Date().toISOString() : null),
        // Edit by is server-authoritative. A normal Confirm must NOT populate it.
        // Keep any existing edit actor only when the row was actually edited.
        last_changed_by: data?.lastChangedById || null,
        last_changed_by_login: data?.lastChangedByLogin || "",
        last_changed_by_name: data?.lastChangedByName || "",
        last_changed_at: data?.lastChangedAt || null
    };
}

function localAttendanceFromRemote(row) {
    return normalizeAttendanceData({
        confirmed: Boolean(row.confirmed),
        actualHours: Number(row.actual_hours || 0),
        actualStart: row.actual_start ? String(row.actual_start).slice(0, 5) : "",
        actualEnd: row.actual_end ? String(row.actual_end).slice(0, 5) : "",
        breakMinutes: Number(row.break_minutes || 0),
        status: row.status || "Pending",
        reason: row.reason || row.reason_record || "",
        terminatedRecord: Boolean(row.terminated_record),
        note: row.note || "",
        confirmedAt: row.confirmed_at || "",
        confirmedById: row.confirmed_by || "",
        confirmedByLogin: row.confirmed_by_login || "",
        confirmedByName: row.confirmed_by_name || "",
        lastChangedById: row.last_changed_by || "",
        lastChangedByLogin: row.last_changed_by_login || "",
        lastChangedByName: row.last_changed_by_name || "",
        lastChangedAt: row.last_changed_at || ""
    });
}

async function loadAttendanceFromSupabase() {
    if (!currentUser) return false;

    // Preserve local cache BEFORE replacing the in-memory attendance object.
    // This is needed for the one-time local → Supabase migration.
    const localBeforeLoad = readStorage(STORAGE.attendance, {});

    const pageSize = 1000;
    let from = 0;
    const allRows = [];

    while (true) {
        const { data, error } = await supabaseClient
            .from("attendance")
            .select(`
                id, work_date, employee_login, shift, planned_hours, actual_hours,
                actual_start, actual_end, break_minutes, status, reason, reason_record, note, confirmed,
                confirmed_by, confirmed_by_login, confirmed_by_name, confirmed_at, terminated_record, last_changed_by, last_changed_by_login, last_changed_by_name, last_changed_at, created_at, updated_at
            `)
            .order("work_date", { ascending: true })
            .range(from, from + pageSize - 1);

        if (error) {
            console.error("Attendance load error:", error);
            toast(`Could not load attendance: ${error.message}`);
            attendanceRemoteReady = false;
            return false;
        }

        const page = Array.isArray(data) ? data : [];
        allRows.push(...page);
        if (page.length < pageSize) break;
        from += pageSize;
    }

    const next = {};
    allRows.forEach(row => {
        next[`${row.work_date}_${row.employee_login}`] = localAttendanceFromRemote(row);
    });

    attendance = next;
    attendanceRemoteLoaded = true;
    attendanceRemoteReady = true;
    saveStorage();

    console.info(`Loaded ${allRows.length} attendance records from Supabase.`);

    if (!allRows.length && localBeforeLoad && Object.keys(localBeforeLoad).length) {
        const migrationRows = [];
        for (const [key, value] of Object.entries(localBeforeLoad)) {
            const separator = key.indexOf("_");
            if (separator < 0) continue;
            const dateString = key.slice(0, separator);
            const login = key.slice(separator + 1);
            const employee = employeeByLogin(login);
            if (!employee) continue;
            const date = fromKey(dateString);
            migrationRows.push(attendanceRowFromLocal(employee, date, value));
        }
        if (migrationRows.length) {
            const { error: migrationError } = await supabaseClient
                .from("attendance")
                .upsert(migrationRows, { onConflict: "work_date,employee_login" });
            if (migrationError) {
                console.error("Attendance migration error:", migrationError);
                toast(`Attendance migration failed: ${migrationError.message}`);
                return false;
            }
            const migrated = await loadAttendanceFromSupabase();
            if (migrated) toast(`${migrationRows.length} attendance records migrated.`);
        }
    }
    return true;
}

async function saveAttendanceToSupabase(employee, date, data) {
    if (!currentUser) return false;

    const row = attendanceRowFromLocal(employee, date, data);

    const { error } = await supabaseClient
        .from("attendance")
        .upsert(row, {
            onConflict: "work_date,employee_login"
        });

    if (error) {
        console.error("Attendance save error:", error);
        toast(`Could not save attendance: ${error.message}`);
        return false;
    }

    attendance[attendanceKey(date, employee.login)] =
        localAttendanceFromRemote(row);

    saveStorage();
    return true;
}

async function saveAttendanceRowsToSupabase(rows) {
    if (!currentUser || !rows.length) return true;

    const payload = rows.map(({ employee, date, data }) =>
        attendanceRowFromLocal(employee, date, data)
    );

    const { error } = await supabaseClient
        .from("attendance")
        .upsert(payload, {
            onConflict: "work_date,employee_login"
        });

    if (error) {
        console.error("Attendance bulk save error:", error);
        toast(`Could not save attendance: ${error.message}`);
        return false;
    }

    rows.forEach(({ employee, date, data }) => {
        attendance[attendanceKey(date, employee.login)] =
            localAttendanceFromRemote(
                attendanceRowFromLocal(employee, date, data)
            );
    });

    saveStorage();
    return true;
}

function subscribeToAttendanceRealtime() {
    if (attendanceRealtimeChannel || !currentUser) return;

    attendanceRealtimeChannel = supabaseClient
        .channel("warehouse-attendance")
        .on(
            "postgres_changes",
            {
                event: "*",
                schema: "public",
                table: "attendance"
            },
            async payload => {
                console.info(
                    "Attendance realtime update:",
                    payload.eventType
                );

                const loaded = await loadAttendanceFromSupabase();

                if (loaded) {
                    renderOverview();
                    renderHoursAttendance();
                    if (document.getElementById("employeesPage")?.classList.contains("active-page")) {
                        renderEmployeeDatabase();
                        renderFormerEmployees();
                    }
                }
            }
        )
        .subscribe(status => {
            console.info("Attendance realtime status:", status);
        });
}

function calculateHours(start, end) {
    if (!start || !end) return 0;

    const [sh, sm] = start.split(":").map(Number);
    const [eh, em] = end.split(":").map(Number);

    let startMinutes = sh * 60 + sm;
    let endMinutes = eh * 60 + em;

    if (endMinutes < startMinutes) {
        endMinutes += 1440;
    }

    return Math.max(0, endMinutes - startMinutes) / 60;
}

function plannedHours(employee, date) {
    const shift = getSchedule(employee, date).shift;
    return SHIFTS[shift] ? SHIFTS[shift].netHours : 0;
}

function toast(message) {
    const element = $("toast");
    if (!element) return;

    element.textContent = message;
    element.classList.add("show");

    clearTimeout(toast.timer);
    toast.timer = setTimeout(
        () => element.classList.remove("show"),
        2200
    );
}


function updateLiveDateTime() {
    const now = new Date();

    if ($("liveTime")) {
        $("liveTime").textContent =
            now.toLocaleTimeString("en-GB", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            });
    }

    if ($("liveDate")) {
        $("liveDate").textContent =
            now.toLocaleDateString("en-GB", {
                day: "2-digit",
                month: "2-digit",
                year: "numeric"
            });
    }
}

function fillMultiFilter(id, options, allLabel, labelMap = null) {
    const root = $(id); const menu = root?.querySelector('[data-multi-menu]');
    if (!root || !menu) return;
    menu.innerHTML = options.map(value => {
        const label = labelMap ? (labelMap[value] || value) : value;
        return `<label><input type="checkbox" value="${esc(value)}"><span>${esc(label)}</span></label>`;
    }).join('');
    const button = root.querySelector('[data-multi-toggle]');
    if (button) button.textContent = `All ${allLabel} ▾`;
}

function fillOverviewFilters() {
    fillMultiFilter('overviewBrigadeFilter', BRIGADES, 'brigades', Object.fromEntries(BRIGADES.map(b => [b, `Brigade ${b}`])));
    fillMultiFilter('overviewProcessFilter', PROCESSES, 'processes');
    fillMultiFilter('overviewSecondaryProcessFilter', EMPLOYEE_PROCESS_SKILLS, 'secondary processes');
    fillMultiFilter('overviewAttendanceFilter', ['confirmed', 'pending'], 'attendance', {confirmed:'Confirmed', pending:'Not confirmed'});
    fillMultiFilter('overviewExceptionFilter', ['private-leave','forced-leave','feeling-unwell','terminated','other','absent'], 'exceptions', {'private-leave':'Private leave','forced-leave':'Forced leave','feeling-unwell':'Feeling unwell',terminated:'Terminated',other:'Other',absent:'Absent'});
    updateAllMultiFilterLabels();
}
async function loadSystemUsers() {
    const tabButton = $("systemUsersTabButton");
    const table = $("systemUsersTable");
    const isAdmin = String(currentUser?.role || "").trim().toLowerCase() === "admin";
    if (tabButton) tabButton.hidden = !isAdmin;
    if (!table || !isAdmin) return;

    const { data, error } = await supabaseClient.rpc("admin_list_profiles");
    if (error) {
        console.error("System users load error:", error);
        table.innerHTML = `<tr><td colspan="5"><div class="empty">System users could not be loaded.<br><small>${esc(error.message)}</small></div></td></tr>`;
        return;
    }

    table.innerHTML = (data || []).map(user => `
        <tr data-system-user-row="${esc(user.login)}">
            <td><strong>${esc(user.login)}</strong></td>
            <td><input class="system-user-name-input" data-system-user-name="${esc(user.login)}" value="${esc(user.full_name || "")}" placeholder="First name Last name"></td>
            <td>
                <select data-system-user-role="${esc(user.login)}">
                    <option value="Leader" ${String(user.role || "").toLowerCase() === "leader" ? "selected" : ""}>Leader</option>
                    <option value="Coordinator" ${String(user.role || "").toLowerCase() === "coordinator" ? "selected" : ""}>Coordinator</option>
                    <option value="Admin" ${String(user.role || "").toLowerCase() === "admin" ? "selected" : ""}>Admin</option>
                </select>
            </td>
            <td><label class="system-user-active"><input type="checkbox" data-system-user-active="${esc(user.login)}" ${user.active ? "checked" : ""}> Active</label></td>
            <td><button type="button" class="mini-btn" data-system-user-save="${esc(user.login)}">Save</button></td>
        </tr>`).join("") || `<tr><td colspan="5"><div class="empty">No system users found.</div></td></tr>`;

    table.querySelectorAll("[data-system-user-save]").forEach(button => {
        button.addEventListener("click", () => saveSystemUser(button.dataset.systemUserSave));
    });
}

async function saveSystemUser(login) {
    if (String(currentUser?.role || "").trim().toLowerCase() !== "admin") return;
    const row = document.querySelector(`[data-system-user-row="${CSS.escape(login)}"]`);
    if (!row) return;
    const fullName = row.querySelector(`[data-system-user-name="${CSS.escape(login)}"]`)?.value.trim() || "";
    const role = row.querySelector(`[data-system-user-role="${CSS.escape(login)}"]`)?.value || "Leader";
    const active = Boolean(row.querySelector(`[data-system-user-active="${CSS.escape(login)}"]`)?.checked);
    if (!fullName) { toast("Full name is required."); return; }

    const { error } = await supabaseClient.rpc("admin_update_profile", {
        p_login: login, p_full_name: fullName, p_role: role, p_active: active
    });
    if (error) {
        console.error("System user update error:", error);
        toast(`Could not update user: ${error.message}`);
        return;
    }
    toast(`${fullName}: user profile updated.`);
    await loadSystemUsers();
    if (login === currentUser.login) {
        const session = await supabaseClient.auth.getSession();
        if (session?.data?.session?.user) await loadCurrentUser(session.data.session.user);
        setAuthScreen(true);
    }
}

function fillEmployeeFilters() {
    fillMultiFilter('employeeProcessFilter', PROCESSES, 'processes');
    fillMultiFilter('employeeBrigadeFilter', BRIGADES, 'brigades', Object.fromEntries(BRIGADES.map(b => [b, `Brigade ${b}`])));
    fillMultiFilter('employeeQualificationFilter', EMPLOYEE_QUALIFICATIONS, 'qualifications');
    fillMultiFilter('employeeProcessSkillFilter', EMPLOYEE_PROCESS_SKILLS, 'secondary processes');
    updateAllMultiFilterLabels();
}
function fillAdditionalMultiFilters() {
    fillMultiFilter('extraDaysTypeFilter', ['extra-off','extra-work-day','extra-work-night'], 'types', {'extra-off':'Extra OFF','extra-work-day':'Extra DAY','extra-work-night':'Extra NIGHT'});
    fillMultiFilter('scheduleHistoryType', ['extra-off','extra-work-day','extra-work-night','removed'], 'types', {'extra-off':'Extra OFF','extra-work-day':'Extra DAY','extra-work-night':'Extra NIGHT',removed:'Removed'});
    fillMultiFilter('hoursAllBrigade', BRIGADES, 'brigades', Object.fromEntries(BRIGADES.map(b => [b, `Brigade ${b}`])));
    fillMultiFilter('hoursAllProcess', PROCESSES, 'processes');
    fillMultiFilter('hoursAllStatus', ['Complete','Pending','Has difference','Absent','Left early'], 'statuses');
    updateAllMultiFilterLabels();
}
function selectedMultiValues(id) {
    return Array.from($(id)?.querySelectorAll('input[type="checkbox"]:checked') || []).map(x => x.value);
}
function setMultiFilterValues(id, values = []) {
    const set = new Set(values);
    $(id)?.querySelectorAll('input[type="checkbox"]').forEach(input => input.checked = set.has(input.value));
    updateAllMultiFilterLabels();
}
function updateMultiFilterLabel(id, allLabel) {
    const root=$(id), button=root?.querySelector('[data-multi-toggle]'); if(!root||!button) return;
    const vals=selectedMultiValues(id);
    button.textContent=vals.length ? `${vals.length} ${allLabel} selected ▾` : `All ${allLabel} ▾`;
}
function updateAllMultiFilterLabels() {
    const labels={feedbackBrigadeFilter:"brigades",feedbackProcessFilter:"processes",employeeProcessFilter:'processes',employeeBrigadeFilter:'brigades',employeeQualificationFilter:'qualifications',employeeProcessSkillFilter:'secondary processes',overviewBrigadeFilter:'brigades',overviewProcessFilter:'processes',overviewSecondaryProcessFilter:'secondary processes',overviewAttendanceFilter:'attendance',overviewExceptionFilter:'exceptions',extraDaysTypeFilter:'types',scheduleHistoryType:'types',hoursAllBrigade:'brigades',hoursAllProcess:'processes',hoursAllStatus:'statuses'};
    Object.entries(labels).forEach(([id,label])=>updateMultiFilterLabel(id,label));
}
function updateEmployeeMultiFilterLabels() {
    updateMultiFilterLabel('employeeProcessFilter','processes');
    updateMultiFilterLabel('employeeBrigadeFilter','brigades');
    updateMultiFilterLabel('employeeQualificationFilter','qualifications');
    updateMultiFilterLabel('employeeProcessSkillFilter','secondary processes');
}

function getHoursException(employee, date) {
    const data = getAttendance(employee, date);
    const planned = plannedHours(employee, date);
    const actual = Number(data.actualHours || 0);
    const confirmed = Boolean(data.confirmed);
    const status = String(data.status || "Pending");
    const reason = String(data.reason || "");
    return {
        data, planned, actual, reason,
        privateLeave: confirmed && reason === "Private leave",
        forcedLeave: confirmed && reason === "Forced leave",
        feelingUnwell: confirmed && reason === "Feeling unwell",
        terminated: confirmed && reason === "Terminated",
        other: confirmed && reason === "Other",
        absent: confirmed && status === "Absent"
    };
}

function renderOverviewExceptionStats(people) {
    const stats = {privateLeave:0,forcedLeave:0,feelingUnwell:0,terminated:0,other:0,absent:0};
    people.forEach(employee => {
        const e = getHoursException(employee, overviewDate);
        if (e.privateLeave) stats.privateLeave++;
        if (e.forcedLeave) stats.forcedLeave++;
        if (e.feelingUnwell) stats.feelingUnwell++;
        if (e.terminated) stats.terminated++;
        if (e.other) stats.other++;
        if (e.absent) stats.absent++;
    });
    const map={ovPrivateLeave:stats.privateLeave,ovForcedLeave:stats.forcedLeave,ovFeelingUnwell:stats.feelingUnwell,ovTerminated:stats.terminated,ovOther:stats.other,ovAbsent:stats.absent};
    Object.entries(map).forEach(([id,v])=>{if($(id)) $(id).textContent=String(v);});
}

function renderOverview() {
    $("overviewDate").value = dateKey(overviewDate);
    const selectedShift = SHIFTS[overviewShift];
    $("overviewShiftTime").textContent = `${selectedShift.start}–${selectedShift.end}`;
    const overviewShiftMeta = $("overviewShiftMeta");
    if (overviewShiftMeta) {
        overviewShiftMeta.textContent = overviewShift === "rest"
            ? "Rest day"
            : `${selectedShift.presenceHours.toFixed(2)} presence · ${selectedShift.netHours.toFixed(2)} net work · 45 min break`;
    }
    const people = employeesAvailableOnDate(overviewDate).filter(employee => getSchedule(employee, overviewDate).shift === overviewShift);
    let confirmed = 0;
    people.forEach(employee => { const data=getAttendance(employee,overviewDate); if(data.confirmed && data.status !== "Absent") confirmed++; });
    const pending=people.length-confirmed, rate=people.length?Math.round((confirmed/people.length)*100):0;
    const overviewWorkedDays = people.reduce((sum, employee) => sum + employeeWorkedDaysForMonth(employee, overviewDate), 0);
    $("ovPlanned").textContent=people.length; $("ovPresent").textContent=confirmed; $("ovMissing").textContent=pending; $("ovRate").textContent=`${rate}%`; $("ovRateCard").textContent=`${rate}%`;
    if ($("ovWorkedDays")) $("ovWorkedDays").textContent = String(overviewWorkedDays);
    renderOverviewExceptionStats(people);
    renderProcessSummary(people); renderBrigadeSummary(people); renderShiftEmployees(people);
}
function renderProcessSummary(people) {
    $("ovProcessTable").innerHTML =
        PROCESSES.map(process => {
            const group = people.filter(
                employee => employee.process === process
            );

            if (!group.length) return "";

            const confirmed = group.filter(employee => {
                const data = getAttendance(employee, overviewDate);
                return data.confirmed && data.status !== "Absent";
            }).length;

            const pending = group.length - confirmed;
            const share = people.length
                ? (group.length / people.length) * 100
                : 0;

            return `
                <tr>
                    <td><strong>${esc(process)}</strong></td>
                    <td>${group.length}</td>
                    <td>${confirmed}</td>
                    <td>${pending}</td>
                    <td>
                        ${share.toFixed(1)}%
                        <div class="bar">
                            <span style="width:${share}%"></span>
                        </div>
                    </td>
                </tr>
            `;
        }).join("") ||
        `<tr><td colspan="5"><div class="empty">No scheduled employees.</div></td></tr>`;
}

function renderBrigadeSummary(people) {
    $("ovBrigades").innerHTML =
        BRIGADES.map(brigade => {
            const group = people.filter(
                employee => employee.brigade === brigade
            );

            if (!group.length) return "";

            const confirmed = group.filter(employee => {
                const data = getAttendance(employee, overviewDate);
                return data.confirmed && data.status !== "Absent";
            }).length;

            const rate = Math.round(
                (confirmed / group.length) * 100
            );

            return `
                <div>
                    <div class="coverage-top">
                        <strong>Brigade ${esc(brigade)}</strong>
                        <span>${confirmed} confirmed</span>
                    </div>
                    <div class="coverage-meta">
                        <span>${group.length - confirmed} pending</span>
                        <span>${rate}%</span>
                    </div>
                    <div class="bar">
                        <span style="width:${rate}%"></span>
                    </div>
                </div>
            `;
        }).join("") ||
        `<div class="empty">No employees scheduled for this shift.</div>`;
}

function shiftStatusClass(status, confirmed) {
    if (!confirmed) return "pending";
    return status === "Absent" ? "absent" : "confirmed";
}

function renderShiftEmployees(people) {
    const search = ($("overviewSearch")?.value || "").trim().toLowerCase();
    const brigades = selectedMultiValues("overviewBrigadeFilter");
    const processes = selectedMultiValues("overviewProcessFilter");
    const secondaryProcesses = selectedMultiValues("overviewSecondaryProcessFilter");
    const attendanceFilters = selectedMultiValues("overviewAttendanceFilter");
    const exceptionFilters = selectedMultiValues("overviewExceptionFilter");

    const filtered = people.filter(employee => {
        const text = `${employee.name} ${employee.login}`.toLowerCase();
        if (search && !text.includes(search)) return false;
        if (brigades.length && !brigades.includes(employee.brigade)) return false;
        if (processes.length && !processes.includes(employee.process)) return false;
        if (secondaryProcesses.length && !secondaryProcesses.some(skill => employeeHasProcessSkill(employee, skill))) return false;

        const data = getAttendance(employee, overviewDate);
        if (attendanceFilters.includes("confirmed") && !data.confirmed) return false;
        if (attendanceFilters.includes("pending") && data.confirmed) return false;

        if (exceptionFilters.length) {
            const e = getHoursException(employee, overviewDate);
            const matches = {
                "private-leave": e.privateLeave,
                "forced-leave": e.forcedLeave,
                "feeling-unwell": e.feelingUnwell,
                "terminated": e.terminated,
                "other": e.other,
                "absent": e.absent
            };
            if (!exceptionFilters.some(key => matches[key])) return false;
        }
        return true;
    });

    $("overviewEmployeeTable").innerHTML = filtered.map(employee => {
        const schedule = getSchedule(employee, overviewDate);
        const data = getAttendance(employee, overviewDate);
        const planned = plannedHours(employee, overviewDate);
        const actual = Number(data.actualHours || 0);
        const fullConfirmed = Boolean(data.confirmed) && Math.abs(actual - planned) < 0.001;
        const visibleReason = data.reason || (data.terminatedRecord ? "Terminated" : "");
        const workedDays = employeeWorkedDaysForMonth(employee, overviewDate);
        const statusClass = shiftStatusClass(data.status, data.confirmed);

        return `
            <tr>
                <td class="check-col"><input class="employee-check" type="checkbox" data-shift-select="${esc(employee.login)}" aria-label="Select ${esc(employee.name)}"></td>
                <td><strong>${esc(employee.name)}</strong><br><small>${esc(employee.login)}</small></td>
                <td>${esc(employee.brigade)}</td>
                <td>${esc(employee.process)}</td>
                <td><div class="employee-skills compact-skills">${employeeProcessSkills(employee).map(value => `<span class="skill-badge">${esc(value)}</span>`).join("") || `<span class="muted">—</span>`}</div></td>
                <td><span class="shift-pill ${schedule.shift}">${SHIFTS[schedule.shift].label}</span></td>
                <td>${planned.toFixed(2)}h</td>
                <td>${actual.toFixed(2)}h</td>
                <td><strong>${workedDays}</strong></td>
                <td>
                    <span class="shift-status-select ${statusClass}" aria-label="Status for ${esc(employee.name)}">
                        ${data.confirmed ? "Confirmed" : "Not confirmed"}
                    </span>
                </td>
                <td class="shift-reason-display">
                    ${visibleReason ? `<span class="reason-pill">${esc(visibleReason)}</span>` : `<span class="muted">—</span>`}
                </td>
                <td>${data.confirmed ? formatActionActor(data.confirmedByName, data.confirmedAt) : "—"}</td>
                <td>${data.lastChangedAt ? formatActionActor(data.lastChangedByName, data.lastChangedAt) : "—"}</td>
                <td>
                    ${data.confirmed
                        ? `<button type="button" class="mini-btn" data-shift-edit="${esc(employee.login)}">Edit</button>`
                        : "—"}
                </td>
            </tr>`;
    }).join("") || `<tr><td colspan="14"><div class="empty">No employees match the selected filters.</div></td></tr>`;

    updateSelectionUI();

    $("overviewEmployeeTable").querySelectorAll("[data-shift-select]").forEach(checkbox => {
        checkbox.addEventListener("change", updateSelectionUI);
    });
    $("overviewEmployeeTable").querySelectorAll("[data-shift-edit]").forEach(button => {
        button.addEventListener("click", () => {
            const employee = employeeByLogin(button.dataset.shiftEdit);
            if (employee) openHoursModal(employee, overviewDate, "overview");
        });
    });
}

function getSelectedShiftLogins() {
    return Array.from(
        document.querySelectorAll(
            "#overviewEmployeeTable [data-shift-select]:checked"
        )
    ).map(
        checkbox => checkbox.dataset.shiftSelect
    );
}

function updateSelectionUI() {
    const checkboxes =
        Array.from(
            document.querySelectorAll(
                "#overviewEmployeeTable [data-shift-select]"
            )
        );

    const selected =
        checkboxes.filter(
            checkbox => checkbox.checked
        );

    $("selectedShiftCount").textContent =
        selected.length;

    const selectAll =
        $("selectAllShiftEmployees");

    if (!selectAll) return;

    selectAll.checked =
        checkboxes.length > 0 &&
        selected.length === checkboxes.length;

    selectAll.indeterminate =
        selected.length > 0 &&
        selected.length < checkboxes.length;
}

async function confirmSelectedHours() {
    if (!isTodayOrPast(overviewDate)) {
        toast("Future hours cannot be confirmed.");
        return;
    }
    const logins = getSelectedShiftLogins();

    if (!logins.length) {
        toast("Select at least one employee.");
        return;
    }

    const rowsToSave = [];

    logins.forEach(login => {
        const employee = employeeByLogin(login);
        if (!employee) return;

        const key = attendanceKey(overviewDate, employee.login);
        const current = attendance[key] || {};

        if (current.confirmed) return;
        if (!canConfirmEmployeeDate(employee, overviewDate)) return;

        const schedule = getSchedule(employee, overviewDate);
        const shift = schedule.shift;
        const planned = plannedHours(employee, overviewDate);

        const confirmedActualHours = Number(current.actualHours || planned);
        const nextData = {
            ...current,
            confirmed: true,
            actualHours: confirmedActualHours,
            actualStart: current.actualStart || (SHIFTS[shift]?.start || ""),
            actualEnd: current.actualEnd || (SHIFTS[shift]?.end || ""),
            status: "Confirmed",
            confirmedAt: new Date().toISOString(),
            confirmedById: currentUser?.id || "",
            confirmedByLogin: currentUser?.login || "",
            confirmedByName: currentUser?.name || currentUser?.login || "",
            terminatedRecord: current.terminatedRecord === true || current.reason === "Terminated" || isTerminatedOnDate(employee, overviewDate),
            // Confirm is not an edit. Edit by remains empty until a real Edit -> Save.
            lastChangedById: current.lastChangedById || "",
            lastChangedByLogin: current.lastChangedByLogin || "",
            lastChangedByName: current.lastChangedByName || "",
            lastChangedAt: current.lastChangedAt || "",
            reason: current.reason || (current.terminatedRecord === true || isTerminatedOnDate(employee, overviewDate) ? "Terminated" : "")
        };

        rowsToSave.push({
            employee,
            date: overviewDate,
            data: nextData
        });
    });

    if (!rowsToSave.length) {
        toast("Selected employees were already confirmed.");
        return;
    }

    const saved = attendanceRemoteReady
        ? await saveAttendanceRowsToSupabase(rowsToSave)
        : (() => {
            rowsToSave.forEach(({ employee, date, data }) => {
                attendance[attendanceKey(date, employee.login)] = data;
            });
            saveStorage();
            return true;
        })();

    if (!saved) return;

    renderOverview();
    renderAuditLog();

    toast(`${rowsToSave.length} employees confirmed.`);
}
async function markSelectedAbsent() {
    const logins = getSelectedShiftLogins();

    if (!logins.length) {
        toast("Select at least one employee.");
        return;
    }

    const rowsToSave = [];
    const alreadyConfirmed = [];

    logins.forEach(login => {
        const employee = employeeByLogin(login);
        if (!employee) return;

        const key = attendanceKey(overviewDate, employee.login);
        const current = attendance[key] || {};

        // Do not silently overwrite an already confirmed attendance record.
        if (current.confirmed) {
            alreadyConfirmed.push(employee.login);
            return;
        }
        if (!canConfirmEmployeeDate(employee, overviewDate)) return;

        const schedule = getSchedule(employee, overviewDate);
        const shift = schedule.shift;
        const planned = plannedHours(employee, overviewDate);

        const nextData = {
            ...current,
            confirmed: true,
            actualHours: 0,
            actualStart: "",
            actualEnd: "",
            breakMinutes: 0,
            status: "Absent",
            note: current.note || "",
            confirmedAt: new Date().toISOString(),
            confirmedById: currentUser?.id || "",
            confirmedByLogin: currentUser?.login || "",
            confirmedByName: currentUser?.name || currentUser?.login || "",
            lastChangedById: current.lastChangedById || "",
            lastChangedByLogin: current.lastChangedByLogin || "",
            lastChangedByName: current.lastChangedByName || "",
            lastChangedAt: current.lastChangedAt || ""
        };

        rowsToSave.push({
            employee,
            date: overviewDate,
            data: nextData
        });
    });

    if (!rowsToSave.length) {
        toast(alreadyConfirmed.length
            ? "Selected employees are already confirmed."
            : "No employees available to mark absent.");
        return;
    }

    const saved = attendanceRemoteReady
        ? await saveAttendanceRowsToSupabase(rowsToSave)
        : (() => {
            rowsToSave.forEach(({ employee, date, data }) => {
                attendance[attendanceKey(date, employee.login)] = data;
            });
            saveStorage();
            return true;
        })();

    if (!saved) return;

    clearSelectedHours();
    renderOverview();
    renderAuditLog();

    let message = `${rowsToSave.length} employee${rowsToSave.length === 1 ? "" : "s"} marked absent.`;
    if (alreadyConfirmed.length) {
        message += ` ${alreadyConfirmed.length} already confirmed and skipped.`;
    }
    toast(message);
}

function clearSelectedHours() {
    document
        .querySelectorAll(
            "#overviewEmployeeTable [data-shift-select]"
        )
        .forEach(
            checkbox => checkbox.checked = false
        );

    if ($("selectAllShiftEmployees")) {
        $("selectAllShiftEmployees").checked = false;
        $("selectAllShiftEmployees").indeterminate = false;
    }

    updateSelectionUI();
}


function openHoursModal(employee, date = overviewDate, source = "hours") {
    hoursModalSource = source;
    const data = getAttendance(
        employee,
        date
    );

    const schedule = getSchedule(
        employee,
        date
    );

    const shift = schedule.shift;

    $("hoursModal").classList.remove("hidden");
    $("hoursModalEmployee").textContent =
        `${employee.name} · ${employee.login}`;

    $("editLogin").value = employee.login;
    $("editDate").value = dateKey(date);
    $("editShift").value = shift;

    $("editStart").value =
        data.actualStart || SHIFTS[shift].start;

    $("editEnd").value =
        data.actualEnd || SHIFTS[shift].end;

    $("editBreak45").checked = data.confirmed
        ? Number(data.breakMinutes || 0) === 45
        : true;

    $("editStatus").value = data.confirmed
        ? (data.status === "Absent" ? "Absent" : "Confirmed")
        : "Pending";

    $("editReason").value = (data.reason === "Terminated" || data.terminatedRecord === true || isTerminatedOnDate(employee, date))
        ? "Terminated"
        : (data.reason || "");
    $("editNote").value = data.note || "";

    if ($("editActualHours")) {
        $("editActualHours").value = Number(data.actualHours || plannedHours(employee, date) || 0).toFixed(2);
    }

    const statusField = $("editStatus")?.closest("label");
    const actualHoursField = $("editActualHours")?.closest("label");

    // The Shift Overview uses the same Edit modal as the Hours tab.
    // Status is intentionally read-only here: only the Confirm action can
    // change Not confirmed -> Confirmed.
    if (statusField) statusField.style.display = "";
    if (actualHoursField) actualHoursField.style.display = "none";
    if ($("editStatus")) {
        const canChangeConfirmedStatus = Boolean(data.confirmed);
        $("editStatus").disabled = !canChangeConfirmedStatus;
        $("editStatus").title = canChangeConfirmedStatus
            ? "Use this field to correct a confirmed day between Confirmed and Absent."
            : "Pending days become confirmed only through the explicit Confirm action.";
    }

    const modalSaveButton = $("hoursForm")?.querySelector('button[type="submit"]');
    if (modalSaveButton) modalSaveButton.textContent = "Save hours";

    updateEditPreview();
}

function getEditBreakHours() {
    return $("editBreak45")?.checked ? 0.75 : 0;
}

function updateEditPreview() {
    const shift = $("editShift").value;

    const start = $("editStart").value;
    const end = $("editEnd").value;
    const gross = calculateHours(start, end);
    const breakHours = $("editStatus").value === "Absent" ? 0 : getEditBreakHours();
    const actual = $("editStatus").value === "Absent"
        ? 0
        : Math.max(0, gross - breakHours);

    const difference =
        actual - (SHIFTS[shift]?.netHours ?? 0);

    $("editActual").textContent =
        `${actual.toFixed(2)}h`;

    $("editDiff").textContent =
        `${difference >= 0 ? "+" : ""}${difference.toFixed(2)}h`;

    const breakHint = $("editBreak45Hint");
    if (breakHint) {
        breakHint.textContent = breakHours
            ? `Gross ${gross.toFixed(2)}h − 0.75h break`
            : `Gross ${gross.toFixed(2)}h · no break deducted`;
    }
}

async function saveHoursEdit(event) {
    event.preventDefault();

    const login = $("editLogin").value;
    const date = fromKey($("editDate").value);
    const employee = employeeByLogin(login);

    if (!employee) return;

    const key = attendanceKey(date, login);
    const current = attendance[key] || {};
    const planned = plannedHours(employee, date);

    const requestedStatus = $("editStatus")?.value || "Pending";
    if (requestedStatus === "Confirmed" && !isTodayOrPast(date)) {
        toast("Future hours cannot be confirmed.");
        return;
    }
    if (requestedStatus === "Confirmed" && !canConfirmEmployeeDate(employee, date)) {
        toast(`Hours cannot be confirmed before ${employee.startDate}.`);
        return;
    }

    // Shift Overview uses the same working-hours editor as the Hours tab.
    // Saving edits NEVER confirms a pending row; Confirm remains a separate action.
    if (hoursModalSource === "overview") {
        const shift = $("editShift").value;
        const status = current.confirmed
            ? ($("editStatus").value === "Absent" ? "Absent" : "Confirmed")
            : "Pending";
        const zeroHours = status === "Absent";
        const breakMinutes = zeroHours ? 0 : ($("editBreak45").checked ? 45 : 0);
        const grossHours = zeroHours ? 0 : calculateHours($("editStart").value, $("editEnd").value);
        const actual = zeroHours ? 0 : Math.max(0, grossHours - breakMinutes / 60);
        const nextData = {
            ...current,
            shift,
            actualHours: actual,
            actualStart: zeroHours ? "" : $("editStart").value,
            actualEnd: zeroHours ? "" : $("editEnd").value,
            breakMinutes,
            confirmed: Boolean(current.confirmed),
            status,
            reason: ALLOWED_ATTENDANCE_REASONS.includes($("editReason").value)
                ? $("editReason").value
                : "",
            note: $("editNote").value.trim(),
            lastChangedById: currentUser?.id || "",
            lastChangedByLogin: currentUser?.login || "",
            lastChangedByName: currentUser?.name || currentUser?.login || "",
            lastChangedAt: new Date().toISOString(),
            terminatedRecord: $("editReason").value === "Terminated"
                || isTerminatedOnDate(employee, date)
        };

        const saved = attendanceRemoteReady
            ? await saveAttendanceToSupabase(employee, date, nextData)
            : (() => { attendance[key] = nextData; saveStorage(); return true; })();

        if (!saved) return;

        $("hoursModal").classList.add("hidden");
        renderOverview();
        if ($("hoursAttendancePage")) renderHoursAttendance();
        renderAuditLog();
        toast(`${employee.name}: hours updated.`);
        return;
    }

    // Existing Hours page editing flow.
    const status = current.confirmed
        ? ($("editStatus").value === "Absent" ? "Absent" : "Confirmed")
        : "Pending";
    const zeroHours = status === "Absent";
    const breakMinutes = zeroHours ? 0 : ($("editBreak45").checked ? 45 : 0);
    const grossHours = zeroHours ? 0 : calculateHours($("editStart").value, $("editEnd").value);
    const actual = zeroHours ? 0 : Math.max(0, grossHours - breakMinutes / 60);

    const nextData = {
        ...current,
        confirmed: Boolean(current.confirmed),
        actualHours: actual,
        actualStart: zeroHours ? "" : $("editStart").value,
        actualEnd: zeroHours ? "" : $("editEnd").value,
        breakMinutes,
        status,
        reason: ALLOWED_ATTENDANCE_REASONS.includes($("editReason").value)
                ? $("editReason").value
                : "",
        note: $("editNote").value.trim(),
        terminatedRecord: $("editReason").value === "Terminated"
            || isTerminatedOnDate(employee, date),
        confirmedAt: current.confirmedAt || "",
        confirmedById: current.confirmedById || "",
        confirmedByLogin: current.confirmedByLogin || "",
        confirmedByName: current.confirmedByName || "",
        lastChangedById: currentUser?.id || "",
        lastChangedByLogin: currentUser?.login || "",
        lastChangedByName: currentUser?.name || currentUser?.login || "",
        lastChangedAt: new Date().toISOString()
    };

    const saved = attendanceRemoteReady
        ? await saveAttendanceToSupabase(employee, date, nextData)
        : (() => {
            attendance[key] = nextData;
            saveStorage();
            return true;
        })();

    if (!saved) return;

    $("hoursModal").classList.add("hidden");
    renderOverview();
    if ($("hoursAttendancePage")) renderHoursAttendance();
    renderAuditLog();

    toast("Working hours saved.");
}

function canManageEmployees() {
    const role = String(currentUser?.role || "").trim().toLowerCase();
    return role === "coordinator" || role === "admin";
}

// Leader may edit employee qualifications / secondary process skills.
// Employee status changes remain Coordinator/Admin only.
function canEditEmployeeSkills() {
    const role = String(currentUser?.role || "").trim().toLowerCase();
    return role === "leader" || role === "coordinator" || role === "admin";
}

function employeeActionButton(employee, action) {
    if (!canManageEmployees()) return "";

    if (action === "former") {
        return `
            <button
                class="secondary employee-action-btn"
                type="button"
                data-employee-action="former"
                data-employee-login="${esc(employee.login)}"
            >
                Mark as Former
            </button>
        `;
    }

    return `
        <button
            class="secondary employee-action-btn"
            type="button"
            data-employee-action="active"
            data-employee-login="${esc(employee.login)}"
        >
            Restore to Active
        </button>
    `;
}


function renderCapabilityCheckboxes(containerId, values, selected = []) {
    const root = $(containerId);
    if (!root) return;
    const selectedSet = new Set(selected);
    root.innerHTML = values.map(value => `
        <label class="capability-checkbox">
            <input type="checkbox" value="${esc(value)}" ${selectedSet.has(value) ? "checked" : ""}>
            <span>${esc(value)}</span>
        </label>
    `).join("");
}

function checkedCapabilityValues(containerId) {
    return Array.from($(containerId)?.querySelectorAll('input[type="checkbox"]:checked') || []).map(input => input.value);
}

function openEmployeeCapabilitiesModal(login) {
    const employee = employeeByLogin(login);
    if (!employee || !canEditEmployeeSkills()) return;
    $("employeeCapabilitiesLogin").value = employee.login;
    $("employeeCapabilitiesEmployee").textContent = `${employee.name} · ${employee.login}`;
    renderCapabilityCheckboxes("employeeQualifications", EMPLOYEE_QUALIFICATIONS, employeeQualifications(employee));
    renderCapabilityCheckboxes("employeeProcessSkills", EMPLOYEE_PROCESS_SKILLS, employeeProcessSkills(employee));
    $("employeeCapabilitiesModal").classList.remove("hidden");
}

function closeEmployeeCapabilitiesModal() {
    $("employeeCapabilitiesModal")?.classList.add("hidden");
}

async function saveEmployeeCapabilities() {
    if (!canEditEmployeeSkills()) return;
    const login = $("employeeCapabilitiesLogin").value;
    const employee = employeeByLogin(login);
    if (!employee) return;

    const qualifications = checkedCapabilityValues("employeeQualifications").filter(x => EMPLOYEE_QUALIFICATIONS.includes(x));
    const skills = checkedCapabilityValues("employeeProcessSkills").filter(x => EMPLOYEE_PROCESS_SKILLS.includes(x));

    const { data, error } = await supabaseClient.rpc("update_employee_capabilities", {
        p_login: login,
        p_qualifications: qualifications,
        p_skills: skills
    });
    if (error) {
        console.error("Employee capabilities update error:", error);
        toast(error.message || "Could not update employee capabilities.");
        return;
    }

    const updated = Array.isArray(data) ? data[0] : data;
    if (updated) {
        const index = EMPLOYEES.findIndex(item => item.login === login);
        if (index !== -1) {
            EMPLOYEES[index] = {
                ...EMPLOYEES[index],
                qualifications: Array.isArray(updated.qualifications) ? updated.qualifications : qualifications,
                skills: Array.isArray(updated.skills) ? updated.skills : skills
            };
        }
    }

    closeEmployeeCapabilitiesModal();
    fillEmployeeFilters();
    fillFeedbackFilters();
    updateEmployeeManagementControls();
    renderEmployeeDatabase();
    renderFormerEmployees();
    renderStatistics();
    renderFeedbackTracker();
    toast(`${employee.name}: qualifications and process skills updated.`);
}

function employeeEditButton(employee) {
    if (canManageEmployees()) {
        return `<button class="secondary employee-action-btn" type="button" data-employee-action="edit-employee" data-employee-login="${esc(employee.login)}">Edit</button>`;
    }
    if (canEditEmployeeSkills()) {
        return `<button class="secondary employee-action-btn" type="button" data-employee-action="edit-capabilities" data-employee-login="${esc(employee.login)}">Edit skills</button>`;
    }
    return "";
}

function fillEmployeeEditOptions() {
    const brigade = $("employeeEditBrigade");
    const process = $("employeeEditProcess");
    if (brigade) brigade.innerHTML = BRIGADES.map(value => `<option value="${esc(value)}">Brigade ${esc(value)}</option>`).join("");
    if (process) process.innerHTML = PROCESSES.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join("");
}

function openEmployeeEditModal(login) {
    const employee = employeeByLogin(login);
    if (!employee || !canManageEmployees()) return;
    fillEmployeeEditOptions();
    $("employeeEditLogin").value = employee.login;
    $("employeeEditEmployee").textContent = `${employee.name} · ${employee.login}`;
    $("employeeEditName").value = employee.name || "";
    $("employeeEditBrigade").value = employee.brigade || BRIGADES[0];
    $("employeeEditProcess").value = employee.process || PROCESSES[0];
    $("employeeEditStartDate").value = employee.startDate || "";
    renderCapabilityCheckboxes("employeeEditQualifications", EMPLOYEE_QUALIFICATIONS, employeeQualifications(employee));
    renderCapabilityCheckboxes("employeeEditProcessSkills", EMPLOYEE_PROCESS_SKILLS, employeeProcessSkills(employee));
    $("employeeEditModal").classList.remove("hidden");
}

function closeEmployeeEditModal() {
    $("employeeEditModal")?.classList.add("hidden");
}

async function saveEmployeeEdit() {
    if (!canManageEmployees()) return;
    const login = $("employeeEditLogin").value.trim();
    const name = $("employeeEditName").value.trim();
    const brigade = $("employeeEditBrigade").value;
    const process = $("employeeEditProcess").value;
    const startDate = $("employeeEditStartDate").value || null;
    const qualifications = checkedCapabilityValues("employeeEditQualifications").filter(x => EMPLOYEE_QUALIFICATIONS.includes(x));
    const skills = checkedCapabilityValues("employeeEditProcessSkills").filter(x => EMPLOYEE_PROCESS_SKILLS.includes(x));
    if (!login || !name || !BRIGADES.includes(brigade) || !PROCESSES.includes(process)) {
        toast("Complete the employee data correctly.");
        return;
    }
    const button = $("employeeEditForm")?.querySelector('button[type="submit"]');
    if (button) button.disabled = true;
    const { data, error } = await supabaseClient.rpc("update_employee", {
        p_login: login,
        p_name: name,
        p_brigade: brigade,
        p_process: process,
        p_start_date: startDate,
        p_qualifications: qualifications,
        p_skills: skills
    });
    if (button) button.disabled = false;
    if (error) {
        console.error("Employee update error:", error);
        toast(error.message || "Could not update employee.");
        return;
    }
    const updated = Array.isArray(data) ? data[0] : data;
    if (updated) {
        const index = EMPLOYEES.findIndex(item => item.login === login);
        if (index !== -1) {
            EMPLOYEES[index] = {
                ...EMPLOYEES[index],
                name: updated.name,
                brigade: updated.brigade,
                process: updated.process,
                startDate: updated.start_date || "",
                qualifications: Array.isArray(updated.qualifications) ? updated.qualifications : qualifications,
                skills: Array.isArray(updated.skills) ? updated.skills : skills
            };
        }
    }
    closeEmployeeEditModal();
    fillOverviewFilters();
    fillEmployeeFilters();
    fillFeedbackFilters();
    renderEmployeeDatabase();
    renderFormerEmployees();
    renderStatistics();
    renderOverview();
    if ($("hoursAttendancePage")?.classList.contains("active-page")) renderAllHoursAttendance();
    toast(`${name}: employee updated.`);
}

let employeeImportRows = [];

function normalizeImportHeader(value) {
    return String(value || "").trim().toLowerCase().replace(/[._-]+/g, " ").replace(/\\s+/g, " ");
}

function importValue(row, aliases) {
    const map = new Map(Object.entries(row).map(([key, value]) => [normalizeImportHeader(key), value]));
    for (const alias of aliases) {
        const value = map.get(normalizeImportHeader(alias));
        if (value !== undefined && value !== null && String(value).trim() !== "") return value;
    }
    return "";
}

function parseImportList(value, allowed) {
    const values = String(value || "").split(/[;,|]/).map(x => x.trim()).filter(Boolean);
    return values.filter(x => allowed.includes(x));
}

function normalizeImportDate(value) {
    if (value instanceof Date && !Number.isNaN(value.getTime())) return dateKey(value);
    if (typeof value === "number" && window.XLSX?.SSF) {
        const parsed = XLSX.SSF.parse_date_code(value);
        if (parsed) return `${parsed.y}-${String(parsed.m).padStart(2,"0")}-${String(parsed.d).padStart(2,"0")}`;
    }
    const raw = String(value || "").trim();
    if (!raw) return "";
    const m = raw.match(/^(\\d{1,2})[.\\/-](\\d{1,2})[.\\/-](\\d{4})$/);
    if (m) return `${m[3]}-${String(m[2]).padStart(2,"0")}-${String(m[1]).padStart(2,"0")}`;
    if (/^\\d{4}-\\d{2}-\\d{2}$/.test(raw)) return raw;
    return "";
}

function parseEmployeeImportRows(rawRows) {
    const existing = new Set(EMPLOYEES.map(e => String(e.login)));
    const seen = new Set();
    return rawRows.map((row, index) => {
        let login = String(importValue(row, ["Login", "Employee login", "Employee Login", "ID"]) || "").trim();
        let name = String(importValue(row, ["Name", "Employee", "Full name", "Full Name"]) || "").trim();
        const firstName = String(importValue(row, ["First name", "First Name"]) || "").trim();
        const surname = String(importValue(row, ["Surname", "Last name", "Last Name"]) || "").trim();
        if (!name && (firstName || surname)) name = `${firstName} ${surname}`.trim();
        const brigade = String(importValue(row, ["Brigade"]) || "").trim();
        const process = String(importValue(row, ["Process", "Primary process", "Primary Process"]) || "Pick").trim();
        const startDate = normalizeImportDate(importValue(row, ["Start date", "Start Date", "Date of start"]));
        const qualifications = parseImportList(importValue(row, ["Qualifications", "Qualification"]), EMPLOYEE_QUALIFICATIONS);
        const skills = parseImportList(importValue(row, ["Secondary processes", "Secondary Processes", "Skills", "Process skills"]), EMPLOYEE_PROCESS_SKILLS);
        const errors = [];
        if (!login) errors.push("Missing login");
        if (!name) errors.push("Missing name");
        if (login && seen.has(login)) errors.push("Duplicate in file");
        if (login && existing.has(login)) errors.push("Already exists");
        if (brigade && !BRIGADES.includes(brigade)) errors.push("Invalid brigade");
        if (!brigade) errors.push("Missing brigade");
        if (!PROCESSES.includes(process)) errors.push("Invalid process");
        if (startDate === "" && importValue(row, ["Start date", "Start Date", "Date of start"])) errors.push("Invalid start date");
        if (login) seen.add(login);
        return { rowNumber: index + 2, login, name, brigade, process, startDate, qualifications, skills, errors, importable: errors.length === 0 };
    });
}

function renderEmployeeImportPreview() {
    const summary = $("employeeImportSummary");
    const preview = $("employeeImportPreview");
    const confirm = $("confirmEmployeeImport");
    const valid = employeeImportRows.filter(r => r.importable);
    const errors = employeeImportRows.length - valid.length;
    if (summary) summary.innerHTML = `<strong>${employeeImportRows.length}</strong> rows · <strong>${valid.length}</strong> ready to import · <strong>${errors}</strong> with errors`;
    if (confirm) confirm.disabled = valid.length === 0;
    if (!preview) return;
    preview.innerHTML = employeeImportRows.length ? `<table><thead><tr><th>Row</th><th>Login</th><th>Name</th><th>Brigade</th><th>Process</th><th>Start date</th><th>Status</th></tr></thead><tbody>${employeeImportRows.map(r => `<tr><td>${r.rowNumber}</td><td>${esc(r.login)}</td><td>${esc(r.name)}</td><td>${esc(r.brigade)}</td><td>${esc(r.process)}</td><td>${esc(r.startDate || "—")}</td><td>${r.importable ? `<span class="import-ok">New</span>` : `<span class="import-error">${esc(r.errors.join(", "))}</span>`}</td></tr>`).join("")}</tbody></table>` : "";
}

async function handleEmployeeImportFile(file) {
    employeeImportRows = [];
    if (!file) { renderEmployeeImportPreview(); return; }
    if (typeof XLSX === "undefined") { toast("Excel import library is not available."); return; }
    try {
        const buffer = await file.arrayBuffer();
        const workbook = XLSX.read(buffer, { type: "array", cellDates: true });
        const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
        const rows = XLSX.utils.sheet_to_json(firstSheet, { defval: "" });
        employeeImportRows = parseEmployeeImportRows(rows);
        renderEmployeeImportPreview();
    } catch (error) {
        console.error("Employee import parse error:", error);
        toast("Could not read the employee file.");
    }
}

function openEmployeeImportModal() {
    if (!canManageEmployees()) return;
    employeeImportRows = [];
    if ($("employeeImportFile")) $("employeeImportFile").value = "";
    if ($("employeeImportSummary")) $("employeeImportSummary").textContent = "Choose a file to preview.";
    if ($("employeeImportPreview")) $("employeeImportPreview").innerHTML = "";
    if ($("confirmEmployeeImport")) $("confirmEmployeeImport").disabled = true;
    $("employeeImportModal")?.classList.remove("hidden");
}

function closeEmployeeImportModal() {
    $("employeeImportModal")?.classList.add("hidden");
}

async function confirmEmployeeImportRows() {
    if (!canManageEmployees()) return;
    const rows = employeeImportRows.filter(r => r.importable).map(r => ({
        login: r.login,
        name: r.name,
        brigade: r.brigade,
        process: r.process,
        start_date: r.startDate || null,
        qualifications: r.qualifications,
        skills: r.skills
    }));
    if (!rows.length) return;
    const button = $("confirmEmployeeImport");
    if (button) button.disabled = true;
    const { data, error } = await supabaseClient.rpc("import_employees", { p_rows: rows });
    if (error) {
        console.error("Employee import error:", error);
        if (button) button.disabled = false;
        toast(error.message || "Could not import employees.");
        return;
    }
    const result = Array.isArray(data) ? data[0] : data;
    closeEmployeeImportModal();
    await loadEmployeesFromSupabase();
    fillOverviewFilters();
    fillEmployeeFilters();
    fillFeedbackFilters();
    renderEmployeeDatabase();
    renderFormerEmployees();
    renderStatistics();
    renderOverview();
    toast(`Import complete: ${result?.inserted || 0} employees added.`);
}

function exportEmployeesExcel() {
    if (!canExportData()) {
        toast("Only Coordinator or Admin can export.");
        return;
    }
    const list = activeEmployees().slice().sort((a,b) => a.name.localeCompare(b.name));
    const processColumns = EMPLOYEE_PROCESS_SKILLS;
    const qualificationColumns = EMPLOYEE_QUALIFICATIONS;
    const rows = list.map(employee => {
        const skills = employeeProcessSkills(employee);
        const qualifications = employeeQualifications(employee);
        const row = {
            Login: employee.login,
            Name: employee.name,
            "Primary process": employee.process,
            Brigade: employee.brigade,
            "Start date": employee.startDate || "",
            Status: employee.status || "Active"
        };
        // One process/skill per spreadsheet cell/column.
        processColumns.forEach(process => {
            row[process] = skills.includes(process) || employee.process === process ? "✓" : "";
        });
        // One qualification per spreadsheet cell/column.
        qualificationColumns.forEach(qualification => {
            row[qualification] = qualifications.includes(qualification) ? "✓" : "";
        });
        return row;
    });
    if (window.XLSX) {
        const wb = XLSX.utils.book_new();
        const ws = XLSX.utils.json_to_sheet(rows);
        XLSX.utils.book_append_sheet(wb, ws, "Employees");
        XLSX.writeFile(wb, `Employees_${dateKey(new Date())}.xlsx`);
    } else {
        const headers = Object.keys(rows[0] || {Login:"",Name:"","Primary process":"",Brigade:"","Start date":"",Status:"",Pick:"",Putaway:"",Abnormal:"",Consolidation:"",Leader:"",Instructor:"","Yard Coordinator":"","Forklift operator":""});
        const lines = [headers.map(csvCell).join(","), ...rows.map(row => headers.map(h => csvCell(row[h])).join(","))];
        const blob = new Blob(["\uFEFF" + lines.join("\n")], {type:"text/csv;charset=utf-8;"});
        const url = URL.createObjectURL(blob); const a = document.createElement("a");
        a.href=url; a.download=`Employees_${dateKey(new Date())}.csv`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    }
    toast("Employee database exported.");
}


function updateEmployeeManagementControls() {
    const allowed = canManageEmployees();
    const importButton = $("importEmployees");
    if (importButton) importButton.hidden = !allowed;
}

function renderEmployeeDatabase() {
    updateEmployeeManagementControls();
    const search =
        $("employeeSearch").value.trim().toLowerCase();

    const brigades = selectedMultiValues("employeeBrigadeFilter");
    const processes = selectedMultiValues("employeeProcessFilter");
    const qualifications = selectedMultiValues("employeeQualificationFilter");
    const processSkills = selectedMultiValues("employeeProcessSkillFilter");

    const allActive = activeEmployees();
    const workedDaysByLogin = new Map(
        allActive.map(employee => [employee.login, employeeWorkedDays(employee)])
    );

    const list = allActive
        .filter(employee => {
            const text =
                `${employee.name} ${employee.login} ${employee.process} ${employeeQualifications(employee).join(" ")} ${employeeProcessSkills(employee).join(" ")}`
                    .toLowerCase();

            if (search && !text.includes(search)) return false;
            if (brigades.length && !brigades.includes(employee.brigade)) return false;
            if (processes.length && !processes.includes(employee.process)) return false;
            if (qualifications.length && !qualifications.some(value => employeeHasQualification(employee, value))) return false;
            if (processSkills.length && !processSkills.some(value => employeeHasProcessSkill(employee, value))) return false;

            return true;
        })
        .sort((a, b) => {
            if (employeeSort.key === "workedDays") {
                const av = workedDaysByLogin.get(a.login) || 0;
                const bv = workedDaysByLogin.get(b.login) || 0;
                return (av - bv) * employeeSort.direction;
            }
            const av = employeeSortValue(a, employeeSort.key);
            const bv = employeeSortValue(b, employeeSort.key);
            return av.localeCompare(bv) * employeeSort.direction;
        });

    $("employeeTotalCount").textContent = String(allActive.length);
    $("employeeFilteredCount").textContent = `${list.length} shown`;

    const sortIcon = key =>
        employeeSort.key === key
            ? (employeeSort.direction === 1 ? " ↑" : " ↓")
            : "";

    $("employeeTable").innerHTML =
        list.map(employee => `
            <tr>
                <td>
                    <strong>${esc(employee.name)}</strong>
                    ${employeeStatusBadge(employee)}
                </td>
                <td>${esc(employee.login)}</td>
                <td>${esc(employee.process)}</td>
                <td>${esc(employee.brigade)}</td>
                <td>
                    <div class="employee-skills">
                        ${employeeQualifications(employee).map(value => `<span class="qualification-badge">${esc(value)}</span>`).join("") || `<span class="muted">—</span>`}
                    </div>
                </td>
                <td>
                    <div class="employee-skills">
                        ${employeeProcessSkills(employee).map(value => `<span class="skill-badge">${esc(value)}</span>`).join("") || `<span class="muted">—</span>`}
                    </div>
                </td>
                <td><strong>${workedDaysByLogin.get(employee.login) || 0}</strong></td>
                <td>${esc(employee.startDate || "—")}</td>
                ${(canManageEmployees() || canEditEmployeeSkills()) ? `<td>${canEditEmployeeSkills() ? employeeEditButton(employee) : ""} ${canManageEmployees() ? employeeActionButton(employee, "former") : ""}</td>` : ""}
            </tr>
        `).join("") ||
        `<tr><td colspan="${(canManageEmployees() || canEditEmployeeSkills()) ? 9 : 8}"><div class="empty">No employees found.</div></td></tr>`;

    // Make the active sort visible on the headers.
    document.querySelectorAll("[data-employee-sort]").forEach(button => {
        const key = button.dataset.employeeSort;
        button.textContent = `${button.dataset.employeeLabel}${sortIcon(key)}`;
    });
}

function renderFormerEmployees() {
    const formerEmployees = EMPLOYEES.filter(
        employee => employee.status !== "Active"
    );
    const workedDaysByLogin = new Map(
        formerEmployees.map(employee => [employee.login, employeeWorkedDays(employee)])
    );
    const list = formerEmployees.sort((a,b) => a.name.localeCompare(b.name));

    if ($("formerEmployeeTotalCount")) $("formerEmployeeTotalCount").textContent = String(list.length);
    if ($("formerEmployeeFilteredCount")) $("formerEmployeeFilteredCount").textContent = `${list.length} shown`;

    $("formerEmployeeTable").innerHTML =
        list.map(employee => `
            <tr>
                <td><strong>${esc(employee.name)}</strong></td>
                <td>${esc(employee.login)}</td>
                <td>${esc(employee.process)}</td>
                <td>${esc(employee.brigade)}</td>
                <td><div class="employee-skills">${employeeQualifications(employee).map(value => `<span class="qualification-badge">${esc(value)}</span>`).join("") || `<span class="muted">—</span>`}</div></td><td><div class="employee-skills">${employeeProcessSkills(employee).map(value => `<span class="skill-badge">${esc(value)}</span>`).join("") || `<span class="muted">—</span>`}</div></td>
<td><strong>${workedDaysByLogin.get(employee.login) || 0}</strong></td>
                                <td>${esc(employee.startDate || "—")}</td>
                <td>${esc(employee.endDate || "—")}</td>
                <td>${esc(employee.reason || "—")}</td>
                ${(canManageEmployees() || canEditEmployeeSkills()) ? `<td>${canEditEmployeeSkills() ? employeeEditButton(employee) : ""} ${canManageEmployees() ? employeeActionButton(employee, "active") : ""}</td>` : ""}
            </tr>
        `).join("") ||
        `<tr><td colspan="${(canManageEmployees() || canEditEmployeeSkills()) ? 11 : 10}"><div class="empty">No former employees.</div></td></tr>`;
}

function openEmployeeStatusModal(login, status) {
    const employee = EMPLOYEES.find(item => item.login === login);
    if (!employee || !canManageEmployees()) return;

    $("employeeStatusLogin").value = employee.login;
    $("employeeStatusAction").value = status;
    $("employeeStatusEmployee").textContent =
        `${employee.name} · ${employee.login}`;

    const isFormer = status === "Former";
    $("employeeFormerFields").classList.toggle("hidden", !isFormer);
    $("employeeStatusTitle").textContent =
        isFormer ? "Mark employee as Former" : "Restore employee to Active";

    if (isFormer) {
        $("employeeEndDate").value = dateKey(new Date());
        $("employeeReason").value = "";
    }

    $("employeeStatusModal").classList.remove("hidden");
}

function closeEmployeeStatusModal() {
    $("employeeStatusModal").classList.add("hidden");
}

let employeeStatusSaveInProgress = false;

async function saveEmployeeStatus() {
    if (!canManageEmployees() || employeeStatusSaveInProgress) return;

    employeeStatusSaveInProgress = true;

    const login = $("employeeStatusLogin").value;
    const status = $("employeeStatusAction").value;
    const endDate = $("employeeEndDate").value || null;
    const reason = $("employeeReason").value.trim();

    if (!login) {
        employeeStatusSaveInProgress = false;
        return;
    }

    if (status === "Former") {
        if (!endDate) {
            employeeStatusSaveInProgress = false;
            toast("End date is required.");
            return;
        }

        if (!reason) {
            employeeStatusSaveInProgress = false;
            toast("Reason is required.");
            return;
        }
    }

    const button = $("saveEmployeeStatus");
    button.disabled = true;

    const { data, error } = await supabaseClient.rpc(
        "set_employee_status",
        {
            p_login: login,
            p_status: status,
            p_end_date: status === "Former" ? endDate : null,
            p_reason: status === "Former" ? reason : ""
        }
    );

    button.disabled = false;

    if (error) {
        employeeStatusSaveInProgress = false;
        console.error("Employee status update error:", error);
        toast(error.message || "Could not update employee status.");
        return;
    }

    const updated = Array.isArray(data) ? data[0] : data;

    if (updated) {
        const index = EMPLOYEES.findIndex(item => item.login === login);

        if (index !== -1) {
            EMPLOYEES[index] = {
                login: updated.login,
                name: updated.name,
                process: updated.process,
                brigade: updated.brigade,
                startDate: updated.start_date || "",
                endDate: updated.end_date || "",
                reason: updated.reason || "",
                status: updated.status || "Active",
                qualifications: Array.isArray(updated.qualifications) ? updated.qualifications : [],
                skills: Array.isArray(updated.skills) ? updated.skills : []
            };
        }
    }

    employeeStatusSaveInProgress = false;
    closeEmployeeStatusModal();
    renderEmployeeDatabase();
    renderFormerEmployees();
    renderStatistics();
    fillOverviewFilters();
    renderOverview();

    toast(
        status === "Former"
            ? "Employee marked as Former."
            : "Employee restored to Active."
    );
}

function initEmployeeStatusActions() {
    if (window.__employeeStatusActionsInitialized) return;
    window.__employeeStatusActionsInitialized = true;

    document.addEventListener("click", event => {
        const button = event.target.closest("[data-employee-action]");
        if (!button) return;

        const action = button.dataset.employeeAction;
        const login = button.dataset.employeeLogin;

        if (action === "edit-employee") {
            openEmployeeEditModal(login);
        } else if (action === "edit-capabilities") {
            openEmployeeCapabilitiesModal(login);
        } else if (action === "former") {
            openEmployeeStatusModal(login, "Former");
        } else if (action === "active") {
            openEmployeeStatusModal(login, "Active");
        }
    });

    $("closeEmployeeStatusModal").addEventListener(
        "click",
        closeEmployeeStatusModal
    );

    $("cancelEmployeeStatus").addEventListener(
        "click",
        closeEmployeeStatusModal
    );

    $("employeeStatusForm").addEventListener(
        "submit",
        async event => {
            event.preventDefault();
            await saveEmployeeStatus();
        }
    );
}

function renderStatistics() {
    $("statsTiles").innerHTML =
        BRIGADES.map(brigade => {
            const total = activeEmployees().filter(
                employee => employee.brigade === brigade
            ).length;

            return `
                <div class="stat-tile">
                    <span>Brigade ${esc(brigade)}</span>
                    <strong>${total}</strong>
                    <small>active employees</small>
                </div>
            `;
        }).join("");

    $("statsHeader").innerHTML =
        `<th>Brigade</th>` +
        PROCESSES.map(
            process => `<th>${esc(process)}</th>`
        ).join("") +
        `<th>Total</th>`;

    $("statsTable").innerHTML =
        BRIGADES.map(brigade => {
            const group = activeEmployees().filter(
                employee => employee.brigade === brigade
            );

            const total = group.length;

            const cells = PROCESSES.map(process => {
                const count = group.filter(
                    employee => employee.process === process
                ).length;

                const percentage = total
                    ? (count / total) * 100
                    : 0;

                return `
                    <td class="process-cell">
                        <strong>${count}</strong>
                        <small>${percentage.toFixed(1)}%</small>
                    </td>
                `;
            }).join("");

            return `
                <tr>
                    <td><strong>Brigade ${esc(brigade)}</strong></td>
                    ${cells}
                    <td><strong>${total}</strong></td>
                </tr>
            `;
        }).join("");

    $("processStatsHeader").innerHTML =
        `<th>Process</th>` +
        BRIGADES.map(
            brigade => `<th>Brigade ${esc(brigade)}</th>`
        ).join("") +
        `<th>Total</th>`;

    $("processStatsTable").innerHTML =
        PROCESSES.map(process => {
            const group = activeEmployees().filter(
                employee => employee.process === process
            );

            const total = group.length;

            const cells = BRIGADES.map(brigade => {
                const count = group.filter(
                    employee => employee.brigade === brigade
                ).length;

                const percentage = total
                    ? (count / total) * 100
                    : 0;

                return `
                    <td class="process-cell">
                        <strong>${count}</strong>
                        <small>${percentage.toFixed(1)}%</small>
                    </td>
                `;
            }).join("");

            return `
                <tr>
                    <td><strong>${esc(process)}</strong></td>
                    ${cells}
                    <td><strong>${total}</strong></td>
                </tr>
            `;
        }).join("");
}


function monthDays(date) {
    return new Date(
        date.getFullYear(),
        date.getMonth() + 1,
        0
    ).getDate();
}

function monthKey(date) {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
}

function getBrigadeMonthValue(brigade, date) {
    const people = activeEmployees().filter(
        employee => employee.brigade === brigade
    );

    // Brigade rows remain the normal/default schedule. Individual overrides never alter them.
    const source = people.find(employee =>
        schedules[scheduleKey(date, employee.login)]
    );

    return source
        ? schedules[scheduleKey(date, source.login)]
        : defaultShiftForBrigade(brigade);
}

function setSchedulingTab(tabId, renderContent = true) {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    const validTabs = ["scheduleTab", "extraDaysTab", "historyTab", "auditTab"];
    activeSchedulingTab = validTabs.includes(tabId) ? tabId : "scheduleTab";

    document.querySelectorAll("[data-scheduling-tab]").forEach(button => {
        button.classList.toggle("active", button.dataset.schedulingTab === activeSchedulingTab);
    });

    document.querySelectorAll("#schedulingPage .subpage").forEach(page => {
        page.classList.toggle("active-subpage", page.id === activeSchedulingTab);
    });

    if (!renderContent) return;

    if (activeSchedulingTab === "auditTab") {
        const isAdmin = String(currentUser?.role || "").trim().toLowerCase() === "admin";
        if (!isAdmin) {
            activeSchedulingTab = "scheduleTab";
            document.querySelectorAll("[data-scheduling-tab]").forEach(button => {
                button.classList.toggle("active", button.dataset.schedulingTab === activeSchedulingTab);
            });
            document.querySelectorAll("#schedulingPage .subpage").forEach(page => {
                page.classList.toggle("active-subpage", page.id === activeSchedulingTab);
            });
            return;
        }
        renderAuditLog();
    } else if (activeSchedulingTab === "extraDaysTab") {
        renderExtraDays();
        updateExtraScheduleHint();
    } else if (activeSchedulingTab === "historyTab") {
        renderScheduleHistory();
    }
}

function renderScheduling() {
    setSchedulingTab(activeSchedulingTab, false);

    $("scheduleMonthLabel").textContent =
        scheduleMonth.toLocaleDateString("en-US", {
            month: "long",
            year: "numeric"
        });

    renderScheduleTable();
    renderExtraDays();
    renderScheduleHistory();
}

function renderScheduleTable() {
    const totalDays = monthDays(scheduleMonth);

    const head = `<th>Brigade</th>` + Array.from({ length: totalDays }, (_, index) => {
        const date = new Date(scheduleMonth.getFullYear(), scheduleMonth.getMonth(), index + 1, 12);
        return `<th class="schedule-day-head"><strong>${String(index + 1).padStart(2, "0")}</strong><small>${date.toLocaleDateString("en-US", { weekday: "short" })}</small></th>`;
    }).join("");

    $("scheduleHeadRow").innerHTML = head;
    $("scheduleInfoTitle").textContent = `Monthly schedule · ${BRIGADES.length} brigades + individual overrides`;

    $("scheduleBody").innerHTML = BRIGADES.map(brigade => {
        const cells = Array.from({ length: totalDays }, (_, index) => {
            const date = new Date(scheduleMonth.getFullYear(), scheduleMonth.getMonth(), index + 1, 12);
            const value = getBrigadeMonthValue(brigade, date);
            return `<td class="schedule-cell"><select class="${value}" data-brigade-schedule="${esc(brigade)}" data-schedule-date="${dateKey(date)}">
                <option value="day" ${value === "day" ? "selected" : ""}>D</option>
                <option value="night" ${value === "night" ? "selected" : ""}>N</option>
                <option value="off" ${value === "off" ? "selected" : ""}>O</option>
            </select></td>`;
        }).join("");
        return `<tr><td class="employee-schedule-name"><strong>Brigade ${esc(brigade)}</strong><small>Default schedule</small></td>${cells}</tr>`;
    }).join("");

    $("scheduleBody").querySelectorAll("[data-brigade-schedule]").forEach(select => {
        select.addEventListener("change", () => { select.className = select.value; });
    });

    renderIndividualScheduleTable();
}

function scheduleOptionHtml(value) {
    const v = value || "";
    return `<option value="" ${!v ? "selected" : ""}>—</option>
        <option value="day" ${v === "day" ? "selected" : ""}>D</option>
        <option value="night" ${v === "night" ? "selected" : ""}>N</option>
        <option value="off" ${v === "off" ? "selected" : ""}>O</option>
        <option value="rest" ${v === "rest" ? "selected" : ""}>R</option>`;
}

function renderIndividualScheduleTable() {
    const body = $("individualScheduleBody");
    const head = $("individualScheduleHeadRow");

    if (!body || !head) return;

    const searchInput = $("individualScheduleSearch");
    const query = (searchInput?.value || "").trim().toLowerCase();

    // No search = do not render employee schedules.
    head.innerHTML = "";
    body.innerHTML = `
        <tr>
            <td>
                <div class="empty">
                    Search for an employee to view their individual schedule.
                </div>
            </td>
        </tr>
    `;

    if (!query) return;

    // Search only active employees.
    const people = activeEmployees()
        .filter(employee => {
            const login = String(employee.login || "").toLowerCase();
            const name = String(employee.name || "").toLowerCase();

            return login.includes(query) || name.includes(query);
        })
        .sort((a, b) => a.name.localeCompare(b.name));

    if (!people.length) {
        body.innerHTML = `
            <tr>
                <td>
                    <div class="empty">
                        No employees found.
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    // If several employees match, ask the user to select exactly one.
    if (people.length > 1) {
        body.innerHTML = `
            <tr>
                <td>
                    <div class="empty">
                        <strong>${people.length} employees found.</strong>
                        <br>
                        Select one employee below.
                        <select id="individualEmployeePicker"
                                class="individual-employee-picker">
                            <option value="">Select employee...</option>
                            ${people.map(employee => `
                                <option value="${esc(employee.login)}">
                                    ${esc(employee.name)} · ${esc(employee.login)}
                                </option>
                            `).join("")}
                        </select>
                    </div>
                </td>
            </tr>
        `;

        const picker = $("individualEmployeePicker");

        if (picker) {
            picker.addEventListener("change", () => {
                if (picker.value) {
                    renderSelectedIndividualSchedule(picker.value);
                }
            });
        }

        return;
    }

    // Exactly one employee matched.
    renderSelectedIndividualSchedule(people[0].login);
}


function renderSelectedIndividualSchedule(login) {
    const body = $("individualScheduleBody");
    const head = $("individualScheduleHeadRow");

    if (!body || !head) return;

    const employee = employeeByLogin(login);

    if (!employee) {
        head.innerHTML = "";
        body.innerHTML = `
            <tr>
                <td>
                    <div class="empty">
                        Employee not found.
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    const totalDays = monthDays(scheduleMonth);

    // Render the month header only for the selected employee.
    head.innerHTML =
        `<th>Employee</th>` +
        Array.from({ length: totalDays }, (_, index) => {
            const date = new Date(
                scheduleMonth.getFullYear(),
                scheduleMonth.getMonth(),
                index + 1,
                12
            );

            return `
                <th class="schedule-day-head">
                    <strong>${String(index + 1).padStart(2, "0")}</strong>
                    <small>
                        ${date.toLocaleDateString("en-US", {
                            weekday: "short"
                        })}
                    </small>
                </th>
            `;
        }).join("");

    const cells = Array.from({ length: totalDays }, (_, index) => {
        const date = new Date(
            scheduleMonth.getFullYear(),
            scheduleMonth.getMonth(),
            index + 1,
            12
        );

        const override = individualScheduleValue(employee, date);
        const effective = getSchedule(employee, date).shift;

        const displayClass = override || effective || "off";

        return `
            <td class="schedule-cell individual-schedule-cell ${override ? "has-override" : ""}">
                <select
                    class="${displayClass}"
                    data-individual-schedule="${esc(employee.login)}"
                    data-schedule-date="${dateKey(date)}"
                    data-effective-shift="${effective || ""}"
                    title="${override ? `Override: ${override}` : `Brigade: ${effective || "off"}`}">
                    ${scheduleOptionHtml(override || "")}
                </select>
            </td>
        `;
    }).join("");

    body.innerHTML = `
        <tr>
            <td class="employee-schedule-name">
                <strong>${esc(employee.name)}</strong>
                <small>
                    ${esc(employee.login)}
                    · ${esc(employee.process)}
                    · Brigade ${esc(employee.brigade)}
                </small>
            </td>
            ${cells}
        </tr>
    `;

    // Only the selected employee's controls are attached.
    body.querySelectorAll("[data-individual-schedule]").forEach(select => {
        select.addEventListener("change", () => {
            const employeeLogin = select.dataset.individualSchedule;
            const date = select.dataset.scheduleDate;
            const key = `${date}_${employeeLogin}`;

            if (select.value) {
                individualSchedules[key] = select.value;
            } else {
                // Empty option removes the individual override.
                delete individualSchedules[key];
            }

            const selectedEmployee = employeeByLogin(employeeLogin);

            if (selectedEmployee) {
                const effectiveShift = getSchedule(
                    selectedEmployee,
                    new Date(`${date}T12:00:00`)
                ).shift;

                select.className =
                    select.value ||
                    effectiveShift ||
                    "off";

                select.classList.toggle(
                    "override-selected",
                    Boolean(select.value)
                );

                select.title = select.value
                    ? `Override: ${select.value}`
                    : `Brigade: ${effectiveShift || "off"}`;
            }
        });
    });
}


async function saveIndividualSchedules() {
    if (individualScheduleSaveInProgress) return;
    const role = String(currentUser?.role || "").trim().toLowerCase();
    if (!['coordinator', 'admin'].includes(role)) {
        toast("Only Coordinator or Admin can save individual schedules.");
        return;
    }
    if (!currentUser?.id || !currentUser?.login) {
        toast("Current user is not available. Please sign in again.");
        return;
    }

    individualScheduleSaveInProgress = true;
    const button = $("saveIndividualSchedule");
    if (button) { button.disabled = true; button.textContent = "Saving…"; }

    try {
        const monthPrefix = monthKey(scheduleMonth);
        const payload = [];
        Object.entries(individualSchedules).forEach(([key, shift]) => {
            const [date, ...loginParts] = key.split("_");
            const login = loginParts.join("_");
            if (date.startsWith(monthPrefix + "-") && ["day", "night", "off", "rest"].includes(shift)) {
                payload.push({ work_date: date, employee_login: login, shift });
            }
        });

        const { data: savedCount, error } = await supabaseClient.rpc(
            "save_employee_schedule_overrides",
            {
                p_month: `${monthPrefix}-01`,
                p_rows: payload
            }
        );
        if (error) throw error;

        await loadIndividualSchedulesFromSupabase();
        renderScheduling();
        renderOverview();
        renderHoursAttendance();
        toast(`Individual schedule saved: ${Number(savedCount ?? payload.length)} overrides.`);
    } catch (error) {
        console.error("Individual Schedule save error:", error);
        toast(`Could not save individual schedule: ${error.message || error}`);
    } finally {
        individualScheduleSaveInProgress = false;
        if (button) { button.disabled = false; button.textContent = "Save individual changes"; }
    }
}

async function saveSchedule() {
    if (scheduleSaveInProgress) return;

    const role = String(currentUser?.role || "").trim().toLowerCase();
    if (!['coordinator', 'admin'].includes(role)) {
        toast("Only Coordinator or Admin can save the monthly schedule.");
        return;
    }
    if (!currentUser?.id || !currentUser?.login) {
        toast("Current user is not available. Please sign in again.");
        return;
    }

    scheduleSaveInProgress = true;
    const saveButton = $("saveSchedule");
    if (saveButton) {
        saveButton.disabled = true;
        saveButton.textContent = "Saving…";
    }

    try {
        // Send only the 7 brigade rows to Supabase. The database expands them
        // to all active employees in one atomic transaction. This avoids the
        // previous 1,000+ row JSON payload and prevents partial-month saves.
        const brigadeSchedule = {};

        BRIGADES.forEach(brigade => {
            const row = {};
            document
                .querySelectorAll(`[data-brigade-schedule="${CSS.escape(brigade)}"]`)
                .forEach(select => {
                    row[select.dataset.scheduleDate] = select.value;
                });
            brigadeSchedule[brigade] = row;
        });

        const { data: savedCount, error } = await supabaseClient.rpc(
            "save_monthly_schedule_by_brigade",
            {
                p_month: `${scheduleMonth.getFullYear()}-${String(scheduleMonth.getMonth() + 1).padStart(2, "0")}-01`,
                p_brigade_schedule: brigadeSchedule
            }
        );

        if (error) {
            console.error("Atomic Monthly Schedule save error:", error);
            toast(`Could not save schedule: ${error.message}`);
            return;
        }

        // Reload the authoritative database state after the transaction.
        const loaded = await loadSchedulesFromSupabase();
        if (!loaded) {
            toast("Schedule was saved, but the updated data could not be reloaded.");
            return;
        }

        // Keep whichever scheduling subtab the user currently has open.
        const tabToKeep = activeSchedulingTab;
        renderScheduling();
        setSchedulingTab(tabToKeep);
        renderOverview();
        renderHoursAttendance();

        toast(`Monthly schedule saved for ${savedCount ?? 0} employee-days.`);
    } catch (error) {
        console.error("Monthly Schedule unexpected error:", error);
        toast(`Could not save schedule: ${error.message || error}`);
    } finally {
        scheduleSaveInProgress = false;
        if (saveButton) {
            saveButton.disabled = false;
            saveButton.textContent = "Save & apply";
        }
    }
}

function updateExtraScheduleHint() {
    const login = $("extraEmployeeLogin").value.trim();
    const dateValue = $("extraDate").value;

    if (!login || !dateValue) {
        $("extraScheduleHint").textContent =
            "Select a login and date to see the current schedule.";
        return;
    }

    const employee = employeeByLogin(login);
    if (!employee) {
        $("extraScheduleHint").textContent = "Employee not found.";
        return;
    }

    const date = fromKey(dateValue);
    const current = getSchedule(employee, date);
    const currentLabel =
        current.shift === "day"
            ? "DAY"
            : current.shift === "night"
                ? "NIGHT"
                : "OFF";

    const existing = extraDays[scheduleKey(date, employee.login)];
    const exceptionLabel = existing
        ? existing.type === "extra-off"
            ? " · current exception: EXTRA OFF"
            : ` · current exception: EXTRA ${existing.shift.toUpperCase()}`
        : "";

    $("extraScheduleHint").textContent =
        `Current schedule: ${currentLabel}${exceptionLabel}`;
}

function syncExtraLeaderLogin() {
    const field = $("extraLeaderLogin");
    if (!field) return;
    field.value = currentUser ? actorDisplay(currentUser.name, currentUser.login) : "";
    field.readOnly = true;
    field.title = "Automatically taken from the currently logged-in user.";
}

async function saveExtraDay() {
    const login = $("extraEmployeeLogin").value.trim();
    const dateValue = $("extraDate").value;
    const type = $("extraType").value;
    const leaderLogin = currentUser?.login || "";
    const leaderId = currentUser?.id || "";

    const employee = employeeByLogin(login);

    if (!employee) {
        toast("Employee login not found.");
        return;
    }

    if (!dateValue) {
        toast("Select a date.");
        return;
    }

    if (!leaderLogin || !leaderId) {
        toast("Current user is not available. Please sign in again.");
        return;
    }

    const date = fromKey(dateValue);
    const key = scheduleKey(date, employee.login);
    const normal = getSchedule(employee, date).shift;
    const existing = extraDays[key];

    if (!existing) {
        if (type === "extra-off" && normal === "off") {
            toast("This employee is already OFF on this date.");
            return;
        }

        if (type !== "extra-off" && normal !== "off") {
            toast("This employee is already scheduled to work on this date.");
            return;
        }
    }

    const payload = {
        work_date: dateKey(date),
        employee_login: employee.login,
        type,
        shift: type === "extra-off" ? null : (type === "extra-work-night" ? "night" : "day"),
        leader_id: leaderId,
        leader_login: leaderLogin,
        leader_name: currentUser?.name || leaderLogin
    };

    const { data, error } = await supabaseClient
        .from("schedule_exceptions")
        .upsert(payload, { onConflict: "work_date,employee_login" })
        .select("id, work_date, employee_login, type, shift, leader_id, leader_login, leader_name, created_at")
        .single();

    if (error) {
        console.error("Extra Days save error:", error);
        toast(`Could not save exception: ${error.message}`);
        return;
    }

    extraDays[key] = {
        id: data.id,
        type: data.type,
        shift: data.shift || null,
        leaderLogin: data.leader_login || leaderLogin,
        leaderName: data.leader_name || currentUser?.name || leaderLogin,
        leaderId: data.leader_id || leaderId,
        createdAt: data.created_at || new Date().toISOString()
    };
    saveStorage();

    $("extraEmployeeLogin").value = "";
    $("extraLeaderLogin").value = currentUser?.login || "";
    $("extraEmployeeHint").textContent = "Enter the exact employee login.";
    $("extraScheduleHint").textContent =
        "The current schedule for this date will appear here.";

    renderScheduling();
    renderOverview();

    toast("Schedule exception saved and synchronized.");
}

function renderExtraDays() {
    const dateFilter = $("extraDaysDateFilter")?.value || "";
    const loginFilter = $("extraDaysLoginFilter")?.value.trim().toLowerCase() || "";
    const typeFilters = selectedMultiValues("extraDaysTypeFilter");
    const entries = Object.entries(extraDays).map(([key, item]) => {
        const split = key.lastIndexOf("_");
        return { key, date: key.slice(0, split), login: key.slice(split + 1), item };
    }).filter(e => {
        if (dateFilter && e.date !== dateFilter) return false;
        if (loginFilter && !e.login.toLowerCase().includes(loginFilter)) return false;
        if (typeFilters.length && !typeFilters.includes(e.item.type)) return false;
        return true;
    }).sort((a, b) => {
        const ca = a.item.createdAt || `${a.date}T00:00:00`;
        const cb = b.item.createdAt || `${b.date}T00:00:00`;
        return String(cb).localeCompare(String(ca)) || String(b.date).localeCompare(String(a.date)) || a.login.localeCompare(b.login);
    });

    let off = 0, day = 0, night = 0;
    entries.forEach(e => {
        if (e.item.type === "extra-off") off++;
        else if (e.item.type === "extra-work-day") day++;
        else if (e.item.type === "extra-work-night") night++;
    });
    if ($("extraStatOff")) $("extraStatOff").textContent = String(off);
    if ($("extraStatDay")) $("extraStatDay").textContent = String(day);
    if ($("extraStatNight")) $("extraStatNight").textContent = String(night);
    if ($("extraStatTotal")) $("extraStatTotal").textContent = String(entries.length);

    $("extraDaysTable").innerHTML = entries.map(({key, date, login, item}) => {
        const employee = employeeByLogin(login);
        if (!employee) return "";
        const isOff = item.type === "extra-off";
        const label = isOff ? "Extra day off" : `Extra work — ${String(item.shift || "day").toUpperCase()}`;
        const created = item.createdAt ? new Date(item.createdAt).toLocaleString("en-GB") : "—";
        const actionCell = canDeleteExtraDays()
            ? `<button class="icon-btn" type="button" data-remove-extra="${esc(key)}" title="Remove Extra Day">×</button>`
            : `—`;
        return `<tr><td>${esc(date)}</td><td><strong>${esc(employee.name)}</strong><br><small>${esc(employee.login)}</small></td><td>${esc(employee.brigade)}</td><td>${esc(employee.process)}</td><td><span class="extra-change ${isOff ? "off" : "work"}">${esc(label)}</span></td><td>${esc(actorDisplay(item.leaderName, item.leaderLogin))}</td><td>${esc(created)}</td><td>${actionCell}</td></tr>`;
    }).join("") || `<tr><td colspan="8"><div class="empty">No active Extra Days match the selected filters.</div></td></tr>`;

    $("extraDaysTable").querySelectorAll("[data-remove-extra]").forEach(button => button.addEventListener("click", () => removeExtraDay(button.dataset.removeExtra)));
}
async function removeExtraDay(key) {
    if (!canDeleteExtraDays()) {
        toast("Only Coordinator or Admin can delete Extra Days.");
        return;
    }

    const split = key.lastIndexOf("_");
    const date = key.slice(0, split);
    const login = key.slice(split + 1);
    const employee = employeeByLogin(login);
    const item = extraDays[key];

    if (!confirm(`Remove extra day for ${employee ? employee.name : login} on ${date}?`)) {
        return;
    }

    if (item?.id) {
        const { error } = await supabaseClient
            .from("schedule_exceptions")
            .delete()
            .eq("id", item.id);

        if (error) {
            console.error("Extra Days remove error:", error);
            toast(`Could not remove exception: ${error.message}`);
            return;
        }
    } else {
        const { error } = await supabaseClient
            .from("schedule_exceptions")
            .delete()
            .eq("work_date", date)
            .eq("employee_login", login);

        if (error) {
            console.error("Extra Days remove error:", error);
            toast(`Could not remove exception: ${error.message}`);
            return;
        }
    }

    delete extraDays[key];
    saveStorage();

    renderScheduling();
    renderOverview();
    toast("Extra day removed and synchronized.");
}

async function renderScheduleHistory() {
    const table = $("scheduleHistoryTable");
    if (!table || !currentUser) return;
    const dateFrom = $("scheduleHistoryDateFrom")?.value || "";
    const dateTo = $("scheduleHistoryDateTo")?.value || "";
    const loginSearch = $("scheduleHistoryLogin")?.value.trim().toLowerCase() || "";
    const typeFilters = selectedMultiValues("scheduleHistoryType");
    if (dateFrom && dateTo && dateFrom > dateTo) {
        table.innerHTML = `<tr><td colspan="7"><div class="empty">From date cannot be later than To date.</div></td></tr>`;
        return;
    }

    const pageSize = 1000;
    let allRows = [];
    for (let from = 0; ; from += pageSize) {
        let query = supabaseClient.from("schedule_exception_history")
            .select("id, action, work_date, employee_login, type, shift, leader_login, leader_name, changed_by_login, changed_by_name, created_at")
            .order("created_at", { ascending: false })
            .range(from, from + pageSize - 1);
        if (dateFrom) query = query.gte("work_date", dateFrom);
        if (dateTo) query = query.lte("work_date", dateTo);
        const { data, error } = await query;
        if (error) {
            console.error("Extra Day history load error:", error);
            table.innerHTML = `<tr><td colspan="7"><div class="empty">History could not be loaded.<br><small>${esc(error.message)}</small></div></td></tr>`;
            return;
        }
        const page = Array.isArray(data) ? data : [];
        allRows.push(...page);
        if (page.length < pageSize) break;
    }

    const rows = allRows.filter(item => {
        if (loginSearch) {
            const q = `${item.employee_login || ""} ${item.leader_login || ""} ${item.leader_name || ""} ${item.changed_by_login || ""} ${item.changed_by_name || ""}`.toLowerCase();
            if (!q.includes(loginSearch)) return false;
        }
        if (typeFilters.length) {
            const matches = typeFilters.some(type => type === "removed" ? item.action === "Extra day removed" : item.type === type);
            if (!matches) return false;
        }
        return true;
    });

    const stats = { work: 0, day: 0, night: 0, off: 0, removed: 0 };
    rows.forEach(item => {
        if (item.action === "Extra day removed") { stats.removed++; return; }
        if (item.type === "extra-off") stats.off++;
        else if (item.shift === "day") { stats.day++; stats.work++; }
        else if (item.shift === "night") { stats.night++; stats.work++; }
    });
    if ($("historyStatWork")) $("historyStatWork").textContent = String(stats.work);
    if ($("historyStatDay")) $("historyStatDay").textContent = String(stats.day);
    if ($("historyStatNight")) $("historyStatNight").textContent = String(stats.night);
    if ($("historyStatOff")) $("historyStatOff").textContent = String(stats.off);
    if ($("historyStatTotal")) $("historyStatTotal").textContent = String(rows.length);

    table.innerHTML = rows.map(item => {
        const employee = employeeByLogin(item.employee_login);
        const change = item.action === "Extra day removed" ? "Removed" : item.type === "extra-off" ? "Extra day off" : `Extra work — ${String(item.shift || "day").toUpperCase()}`;
        return `<tr><td>${new Date(item.created_at).toLocaleString("en-GB")}</td><td><strong>${esc(item.action)}</strong></td><td>${esc(employee?.name || item.employee_login)}<br><small>${esc(item.employee_login)}</small></td><td>${esc(item.work_date)}</td><td>${esc(actorDisplay(item.leader_name, item.leader_login))}</td><td>${esc(change)}</td><td>${formatActionActor(item.changed_by_name, item.created_at)}</td></tr>`;
    }).join("") || `<tr><td colspan="7"><div class="empty">No Extra Day history matches the selected filters.</div></td></tr>`;
}
function csvCell(value) {
    return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function exportSchedule() {
    if (!canExportData()) {
        toast("Only Coordinator or Admin can export.");
        return;
    }

    const totalDays = monthDays(scheduleMonth);
    const headers = Array.from(
        { length: totalDays },
        (_, index) => String(index + 1).padStart(2, "0")
    );

    const rows = [["Brigade", ...headers]];

    BRIGADES.forEach(brigade => {
        const row = [brigade];
        for (let day = 1; day <= totalDays; day++) {
            const date = new Date(
                scheduleMonth.getFullYear(),
                scheduleMonth.getMonth(),
                day,
                12
            );
            const value = getBrigadeMonthValue(brigade, date);
            row.push(
                value === "day" ? "DAY" :
                value === "night" ? "NIGHT" : "OFF"
            );
        }
        rows.push(row);
    });

    rows.push([]);
    rows.push(["Employee schedule"]);
    rows.push(["Login", "Name", "Process", "Brigade", ...headers]);

    activeEmployees()
        .sort((a, b) => a.name.localeCompare(b.name))
        .forEach(employee => {
            const row = [
                employee.login,
                employee.name,
                employee.process,
                employee.brigade
            ];

            for (let day = 1; day <= totalDays; day++) {
                const date = new Date(
                    scheduleMonth.getFullYear(),
                    scheduleMonth.getMonth(),
                    day,
                    12
                );
                const schedule = getSchedule(employee, date);
                const extra = extraDays[scheduleKey(date, employee.login)];

                if (extra?.type === "extra-off") {
                    row.push("EXTRA OFF");
                } else if (extra?.type === "extra-work-day" || extra?.type === "extra-work-night") {
                    row.push(`EXTRA ${String(extra.shift || "day").toUpperCase()}`);
                } else {
                    row.push(
                        schedule.shift === "day" ? "DAY" :
                        schedule.shift === "night" ? "NIGHT" :
                        schedule.shift === "rest" ? "R" : "OFF"
                    );
                }
            }
            rows.push(row);
        });

    // Semicolon is intentional for Polish Excel locale: every day opens in a separate cell.
    const csv = rows
        .map(row => row.map(csvCell).join(";"))
        .join("\r\n");

    const blob = new Blob(
        ["\uFEFF" + csv],
        { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `Warehouse_Schedule_${monthKey(scheduleMonth)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    toast("Schedule exported with separate day columns.");
}

async function confirmHoursDay(employee, date) {
    if (!employee || !currentUser) return;

    if (!isTodayOrPast(date)) {
        toast("Future hours cannot be confirmed.");
        return;
    }

    if (!canConfirmEmployeeDate(employee, date)) {
        toast(`Hours cannot be confirmed before ${employee.startDate}.`);
        return;
    }

    const key = attendanceKey(date, employee.login);
    const current = getAttendance(employee, date);
    if (current.confirmed) {
        toast("This day is already confirmed.");
        return;
    }

    const schedule = getSchedule(employee, date);
    const planned = plannedHours(employee, date);
    const actual = Number(current.actualHours || planned);
    const nextData = {
        ...current,
        shift: schedule.shift,
        confirmed: true,
        actualHours: actual,
        actualStart: current.actualStart || (SHIFTS[schedule.shift]?.start || ""),
        actualEnd: current.actualEnd || (SHIFTS[schedule.shift]?.end || ""),
        breakMinutes: current.breakMinutes ?? (planned > 0 ? 45 : 0),
        status: "Confirmed",
        // Preserve the reason selected/stored for this day. A reason is an explicit
        // business decision and must not disappear just because actual = planned.
        reason: current.reason || ((employee.status === "Former" && employee.endDate && String(date) >= String(employee.endDate)) ? "Terminated" : ""),
        confirmedAt: new Date().toISOString(),
        confirmedById: currentUser.id || "",
        confirmedByLogin: currentUser.login || "",
        confirmedByName: currentUser.name || currentUser.login || "",
        // Confirm is not an edit. Edit by stays blank until Save is used in Edit.
        lastChangedById: current.lastChangedById || "",
        lastChangedByLogin: current.lastChangedByLogin || "",
        lastChangedByName: current.lastChangedByName || "",
        lastChangedAt: current.lastChangedAt || ""
    };

    const saved = attendanceRemoteReady
        ? await saveAttendanceToSupabase(employee, date, nextData)
        : (() => { attendance[key] = nextData; saveStorage(); return true; })();

    if (!saved) return;

    renderOverview();
    renderHoursAttendance();
    renderAuditLog();
    toast(`${employee.name}: hours confirmed.`);
}

function renderHoursAttendance() {
    renderAllHoursAttendance();
    const employee = employeeByLogin(hoursAttendanceEmployeeLogin);
    const summary = $("hoursEmployeeSummary");

    $("hoursMonthLabel").textContent =
        hoursAttendanceMonth.toLocaleDateString("en-US", {
            month: "long",
            year: "numeric"
        });

    if (!employee) {
        summary.classList.remove("show");
        $("hoursAttendanceTable").innerHTML = "";
        return;
    }

    summary.classList.add("show");

    $("hoursEmployeeName").innerHTML =
        `${esc(employee.name)} ${employeeStatusBadge(employee)}`;

    $("hoursEmployeeMeta").innerHTML =
        `${esc(employee.login)} · ${esc(employee.process)} · Brigade ${esc(employee.brigade)}`
        + (employee.status === "Former"
            ? ` · <strong class="former-inline">Former since ${esc(employee.endDate || "—")}</strong>`
            : "");

    let planned = 0;
    let plannedDays = 0;
    let confirmed = 0;
    let pending = 0;
    let absent = 0;
    let underworked = 0;
    let workedDays = 0;

    const rows = [];
    const totalDays = monthDays(hoursAttendanceMonth);

    for (let day = 1; day <= totalDays; day++) {
        const date = new Date(
            hoursAttendanceMonth.getFullYear(),
            hoursAttendanceMonth.getMonth(),
            day,
            12
        );

        const schedule = getSchedule(employee, date);
        const data = getAttendance(employee, date);
        const p = canConfirmEmployeeDate(employee, date) ? plannedHours(employee, date) : 0;
        const a = canConfirmEmployeeDate(employee, date) ? Number(data.actualHours || 0) : 0;

        if (!canConfirmEmployeeDate(employee, date)) {
            rows.push(`
                <tr>
                    <td><strong>${date.toLocaleDateString("en-GB")}</strong></td>
                    <td>${date.toLocaleDateString("en-US", { weekday: "short" })}</td>
                    <td><span class="shift-pill off">O</span></td>
                    <td>0.00h</td><td>0.00h</td><td>—</td><td>—</td>
                    <td><span class="hours-status-pending">Before start</span></td>
                    <td>Not employed yet</td><td>—</td><td>—</td><td>—</td><td>—</td>
                </tr>
            `);
            continue;
        }

        planned += p;
        if (p > 0) plannedDays++;

        // Count every confirmed actual hour, even when the employee was
        // originally scheduled OFF (for example, a manually entered 8h day).
        // Previously this was nested inside `if (p > 0)`, which incorrectly
        // showed 0.00h in the Confirmed tile for confirmed hours on OFF days.
        if (data.confirmed) {
            const isAbsent = String(data.status || "").trim().toLowerCase() === "absent";
            if (isAbsent) {
                absent++;
            } else {
                confirmed += a;
                workedDays++;
                if (p > 0 && a < p) underworked += p - Math.max(0, a);
            }
        }

        // Pending means a scheduled working day that still has not been confirmed.
        if (p > 0 && !data.confirmed) {
            pending++;
        }

        const isAbsent = String(data.status || "").trim().toLowerCase() === "absent";
        const leftEarly = Boolean(data.confirmed) && !isAbsent && p > 0 && a + 0.001 < p;
        const statusClass =
            isAbsent ? "hours-status-absent" :
            data.confirmed ? "hours-status-confirmed" :
            "hours-status-pending";
        const actualTime = data.confirmed && (data.actualStart || data.actualEnd)
            ? `${esc(data.actualStart || "—")}–${esc(data.actualEnd || "—")}`
            : "—";
        const detailStatus = isAbsent ? "Absent" : leftEarly ? "Left early" : data.confirmed ? "Confirmed" : (p ? "Not confirmed" : "OFF");
        const detailReason = data.reason || (isAbsent ? "Absent" : leftEarly ? "Left early" : "—");

        rows.push(`
            <tr>
                <td><strong>${date.toLocaleDateString("en-GB")}</strong></td>
                <td>${date.toLocaleDateString("en-US", { weekday: "short" })}</td>
                <td>
                    <span class="shift-pill ${schedule.shift}">
                        ${schedule.shift === "day" ? "DAY" : schedule.shift === "night" ? "NIGHT" : schedule.shift === "rest" ? "R" : "OFF"}
                    </span>
                </td>
                <td>${p.toFixed(2)}h</td>
                <td><strong>${a.toFixed(2)}h</strong></td>
                <td>${actualTime}</td>
                <td>${data.confirmed && Number(data.breakMinutes || 0) ? "45 min" : "—"}</td>
                <td><span class="${statusClass}">${esc(detailStatus)}</span></td>
                <td>${esc(detailReason)}</td>
                <td>${formatActionActor(data.confirmedByName, data.confirmedAt)}</td>
                <td>${formatActionActor(data.lastChangedByName, data.lastChangedAt)}</td>
                <td class="hours-note" title="${esc(data.note || "")}">${esc(notePreview(data.note, 8))}</td>
                <td>
                    ${(p > 0 || a > 0 || data.confirmed || data.status === "Absent" || data.reason)
                        ? data.confirmed
                            ? `<button class="mini-btn" data-ha-edit="${dateKey(date)}">Edit</button>`
                            : p > 0
                                ? `<div class="hours-action-group">
                                    ${isTodayOrPast(date)
                                        ? `<button class="mini-btn confirm" data-ha-confirm="${dateKey(date)}">Confirm</button>`
                                        : `<span class="future-confirm-note">Future</span>`}
                                    <button class="mini-btn" data-ha-edit="${dateKey(date)}">Edit</button>
                                  </div>`
                                : `<button class="mini-btn" data-ha-edit="${dateKey(date)}">Edit</button>`
                        : "—"}
                </td>
            </tr>
        `);
    }

    const differenceDays = workedDays - plannedDays;
    $("haPlanned").textContent = String(plannedDays);
    $("haConfirmed").textContent = `${differenceDays > 0 ? "+" : ""}${differenceDays}`;
    if ($("haWorkedDays")) $("haWorkedDays").textContent = String(workedDays);
    if ($("haAbsent")) $("haAbsent").textContent = String(absent);
    if ($("haUnderworked")) $("haUnderworked").textContent = `${underworked.toFixed(2)}h`;
    $("haPending").textContent = String(pending);
    $("hoursAttendanceTable").innerHTML = rows.join("") ||
        `<tr><td colspan="13"><div class="empty">No days in this month.</div></td></tr>`;

    $("hoursAttendanceTable")
        .querySelectorAll("[data-ha-confirm]")
        .forEach(button => {
            button.addEventListener("click", () => {
                const date = fromKey(button.dataset.haConfirm);
                confirmHoursDay(employee, date);
            });
        });

    $("hoursAttendanceTable")
        .querySelectorAll("[data-ha-edit]")
        .forEach(button => {
            button.addEventListener("click", () => {
                const date = fromKey(button.dataset.haEdit);
                openHoursModal(employee, date);
            });
        });
}

function subscribeToHistoryRealtime() {
    if (!currentUser) return;

    if (!scheduleHistoryRealtimeChannel) {
        scheduleHistoryRealtimeChannel = supabaseClient
            .channel("warehouse-extra-day-history")
            .on("postgres_changes", { event: "*", schema: "public", table: "schedule_exception_history" }, () => {
                renderScheduleHistory();
                if (activeSchedulingTab === "extraDaysTab") renderExtraDays();
            })
            .subscribe();
    }

    if (!auditRealtimeChannel) {
        auditRealtimeChannel = supabaseClient
            .channel("warehouse-audit-log")
            .on("postgres_changes", { event: "*", schema: "public", table: "audit_logs" }, () => {
                if (String(currentUser?.role || "").trim().toLowerCase() === "admin" && activeSchedulingTab === "auditTab") renderAuditLog();
            })
            .subscribe(status => console.info("Audit realtime status:", status));
    }

}

function switchPage(pageId) {
    // Every top-level tab opens at the top instead of preserving the previous page's scroll position.
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    document
        .querySelectorAll(".page")
        .forEach(page => {
            page.classList.toggle(
                "active-page",
                page.id === pageId
            );
        });

    document
        .querySelectorAll(".nav-btn")
        .forEach(button => {
            button.classList.toggle(
                "active",
                button.dataset.page === pageId
            );
        });

    if (pageId === "overviewPage") {
        renderOverview();
    }

    if (pageId === "employeesPage") {
        renderEmployeeDatabase();
        renderFormerEmployees();
        renderStatistics();
    }

    if (pageId === "schedulingPage") {
        renderScheduling();
    }

    if (pageId === "hoursAttendancePage") {
        // V27.1 — first render is limited to 100 employees.
        hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
        hoursAttendanceEmployeeLogin = "";
        hoursAttendanceDaySortKey = "";
        hoursAttendanceDaySortDirection = 1;
        attendanceActiveSubtab = "tracker";
        activateAttendanceSubtab("tracker");
        if ($("hoursAllSearch")) $("hoursAllSearch").value = "";
        setMultiFilterValues("hoursAllBrigade", []);
        setMultiFilterValues("hoursAllProcess", []);
        setMultiFilterValues("hoursAllStatus", []);
        if ($("hoursAdvancedFilters")) $("hoursAdvancedFilters").hidden = true;
        if ($("hoursFiltersToggle")) $("hoursFiltersToggle").setAttribute("aria-expanded", "false");
        renderHoursAttendance();
    }

    if (pageId === "feedbackTrackerPage") {
        // V27.1 — first render is limited to 100 employees.
        feedbackVisibleCount = LARGE_LIST_PAGE_SIZE;
        feedbackActiveSubtab = "tracker";
        activateFeedbackSubtab("tracker");
        renderFeedbackTracker();
    }
}

function initEvents() {
    document
        .querySelectorAll(".nav-btn")
        .forEach(button => {
            button.addEventListener(
                "click",
                () => switchPage(button.dataset.page)
            );
        });

    $("selectAllShiftEmployees").addEventListener(
        "change",
        event => {
            document
                .querySelectorAll(
                    "#overviewEmployeeTable [data-shift-select]"
                )
                .forEach(
                    checkbox =>
                        checkbox.checked = event.target.checked
                );

            updateSelectionUI();
        }
    );

    $("confirmSelectedHours").addEventListener(
        "click",
        confirmSelectedHours
    );

    $("exportShiftEmployees")?.addEventListener("click", exportShiftEmployees);
    $("exportEmployees")?.addEventListener("click", exportEmployeesExcel);
    $("importEmployees")?.addEventListener("click", openEmployeeImportModal);
    $("employeeImportFile")?.addEventListener("change", event => handleEmployeeImportFile(event.target.files?.[0] || null));
    $("confirmEmployeeImport")?.addEventListener("click", confirmEmployeeImportRows);
    $("closeEmployeeImportModal")?.addEventListener("click", closeEmployeeImportModal);
    $("cancelEmployeeImport")?.addEventListener("click", closeEmployeeImportModal);
    $("closeEmployeeEditModal")?.addEventListener("click", closeEmployeeEditModal);
    $("cancelEmployeeEdit")?.addEventListener("click", closeEmployeeEditModal);
    $("employeeEditForm")?.addEventListener("submit", event => { event.preventDefault(); saveEmployeeEdit(); });

    $("markSelectedAbsent").addEventListener(
        "click",
        markSelectedAbsent
    );

    $("clearSelectedHours").addEventListener(
        "click",
        clearSelectedHours
    );

    $("overviewToday").addEventListener(
        "click",
        () => {
            overviewDate = startDay(new Date());
            renderOverview();
        }
    );

    $("overviewDate").addEventListener(
        "change",
        event => {
            overviewDate = fromKey(event.target.value);
            renderOverview();
        }
    );

    $("overviewShiftButtons").addEventListener(
        "click",
        event => {
            const button =
                event.target.closest("[data-shift]");

            if (!button) return;

            overviewShift =
                button.dataset.shift;

            document
                .querySelectorAll(
                    "#overviewShiftButtons [data-shift]"
                )
                .forEach(item => {
                    item.classList.toggle(
                        "selected",
                        item === button
                    );
                });

            renderOverview();
        }
    );

    $("overviewSearch")?.addEventListener("keydown", event => {
        if (event.key === "Enter") { event.preventDefault(); renderOverview(); }
    });
    $("applyOverviewFilters")?.addEventListener("click", renderOverview);

    document
        .querySelectorAll("[data-employees-tab]")
        .forEach(button => {
            button.addEventListener(
                "click",
                () => {
                    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
                    document
                        .querySelectorAll("[data-employees-tab]")
                        .forEach(item => {
                            item.classList.toggle(
                                "active",
                                item === button
                            );
                        });

                    document
                        .querySelectorAll(
                            "#employeesPage .subpage"
                        )
                        .forEach(page => {
                            page.classList.toggle(
                                "active-subpage",
                                page.id ===
                                button.dataset.employeesTab
                            );
                        });

                    if (button.dataset.employeesTab === "systemUsersTab") {
                        loadSystemUsers();
                    }
                }
            );
        });

    $("employeeSearch").addEventListener("keydown", event => {
        if (event.key === "Enter") { event.preventDefault(); renderEmployeeDatabase(); }
    });
    $("applyEmployeeFilters")?.addEventListener("click", renderEmployeeDatabase);

    document.querySelectorAll("[data-employee-sort]").forEach(button => {
        button.addEventListener("click", () => {
            const key = button.dataset.employeeSort;
            if (employeeSort.key === key) {
                employeeSort.direction *= -1;
            } else {
                employeeSort.key = key;
                employeeSort.direction = 1;
            }
            renderEmployeeDatabase();
        });
    });

    document.querySelectorAll("[data-multi-toggle]").forEach(button => {
        button.addEventListener("click", event => {
            event.stopPropagation();
            const root=$(button.dataset.multiToggle);
            document.querySelectorAll(".multi-filter.open").forEach(x=>{if(x!==root)x.classList.remove("open")});
            root?.classList.toggle("open");
        });
    });
    document.addEventListener("click", event => {
        if (!event.target.closest(".multi-filter")) document.querySelectorAll(".multi-filter.open").forEach(x=>x.classList.remove("open"));
    });
    document.querySelectorAll(".multi-filter input[type=\"checkbox\"]").forEach(input => input.addEventListener("change", updateAllMultiFilterLabels));
    $("clearEmployeeFilters")?.addEventListener("click", () => {
        $("employeeSearch").value="";
        setMultiFilterValues("employeeProcessFilter", []);
        setMultiFilterValues("employeeBrigadeFilter", []);
        setMultiFilterValues("employeeQualificationFilter", []);
        setMultiFilterValues("employeeProcessSkillFilter", []);
        renderEmployeeDatabase();
    });

    $("employeeCapabilitiesForm")?.addEventListener("submit", async event => {
        event.preventDefault();
        await saveEmployeeCapabilities();
    });
    $("closeEmployeeCapabilitiesModal")?.addEventListener("click", closeEmployeeCapabilitiesModal);
    $("cancelEmployeeCapabilities")?.addEventListener("click", closeEmployeeCapabilitiesModal);

    document.querySelectorAll("[data-feedback-subtab]").forEach(button => {
        button.addEventListener("click", () => activateFeedbackSubtab(button.dataset.feedbackSubtab));
    });

    document.querySelectorAll("[data-attendance-subtab]").forEach(button => {
        button.addEventListener("click", () => activateAttendanceSubtab(button.dataset.attendanceSubtab));
    });

    // Feedback Tracker
    $("feedbackMonthPrev")?.addEventListener("click", async () => {
        feedbackMonth = new Date(feedbackMonth.getFullYear(), feedbackMonth.getMonth()-1, 1, 12);
        feedbackVisibleCount = LARGE_LIST_PAGE_SIZE;
        await loadFeedbackFromSupabase();
        renderFeedbackTracker();
    });
    $("feedbackMonthNext")?.addEventListener("click", async () => {
        feedbackMonth = new Date(feedbackMonth.getFullYear(), feedbackMonth.getMonth()+1, 1, 12);
        feedbackVisibleCount = LARGE_LIST_PAGE_SIZE;
        await loadFeedbackFromSupabase();
        renderFeedbackTracker();
    });
    $("applyFeedbackFilters")?.addEventListener("click", () => {
        feedbackVisibleCount = LARGE_LIST_PAGE_SIZE;
        renderFeedbackTracker();
    });
    $("clearFeedbackFilters")?.addEventListener("click", () => {
        $("feedbackSearch").value = "";
        setMultiFilterValues("feedbackBrigadeFilter", []);
        setMultiFilterValues("feedbackProcessFilter", []);
        setMultiFilterValues("feedbackErrorTypeFilter", []);
        feedbackVisibleCount = LARGE_LIST_PAGE_SIZE;
        renderFeedbackTracker();
    });
    $("feedbackSearch")?.addEventListener("keydown", event => {
        if (event.key === "Enter") { event.preventDefault(); feedbackVisibleCount = LARGE_LIST_PAGE_SIZE; renderFeedbackTracker(); }
    });
    $("feedbackMoreBtn")?.addEventListener("click", showMoreFeedbackEmployees);
    $("feedbackForm")?.addEventListener("submit", saveFeedbackEntry);
    $("closeFeedbackModal")?.addEventListener("click", closeFeedbackModal);
    $("cancelFeedback")?.addEventListener("click", closeFeedbackModal);
    $("feedbackModal")?.addEventListener("click", event => { if (event.target.id === "feedbackModal") closeFeedbackModal(); });
    $("closeFeedbackEmployeeHistoryModal")?.addEventListener("click", closeFeedbackEmployeeHistoryModal);
    $("closeFeedbackEmployeeHistory")?.addEventListener("click", closeFeedbackEmployeeHistoryModal);
    $("feedbackEmployeeHistoryModal")?.addEventListener("click", event => { if (event.target.id === "feedbackEmployeeHistoryModal") closeFeedbackEmployeeHistoryModal(); });



    document
        .querySelectorAll("[data-scheduling-tab]")
        .forEach(button => {
            button.addEventListener(
                "click",
                () => {
                    setSchedulingTab(button.dataset.schedulingTab);
                }
            );
        });

    $("schedulePrev").addEventListener(
        "click",
        () => {
            scheduleMonth = new Date(
                scheduleMonth.getFullYear(),
                scheduleMonth.getMonth() - 1,
                1,
                12
            );
            renderScheduling();
        }
    );

    $("scheduleNext").addEventListener(
        "click",
        () => {
            scheduleMonth = new Date(
                scheduleMonth.getFullYear(),
                scheduleMonth.getMonth() + 1,
                1,
                12
            );
            renderScheduling();
        }
    );
$("saveSchedule").addEventListener(
        "click",
        saveSchedule
    );

    // Individual employee schedule has its own Save button.
    // V24.2 was missing this listener, so clicking Save did nothing.
    $("saveIndividualSchedule")?.addEventListener(
        "click",
        saveIndividualSchedules
    );

    $("exportSchedule").addEventListener(
        "click",
        exportSchedule
    );

    const individualSearch = $("individualScheduleSearch");
    const runIndividualSearch = () => renderIndividualScheduleTable();
    individualSearch?.addEventListener("input", runIndividualSearch);
    individualSearch?.addEventListener("search", runIndividualSearch);
    individualSearch?.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            event.preventDefault();
            runIndividualSearch();
        }
    });
    $("individualScheduleSearchBtn")?.addEventListener("click", runIndividualSearch);
    $("clearIndividualScheduleSearch")?.addEventListener("click", () => {
        if (individualSearch) individualSearch.value = "";
        runIndividualSearch();
        individualSearch?.focus();
    });

    $("extraEmployeeLogin").addEventListener(
        "input",
        () => {
            const login =
                $("extraEmployeeLogin").value.trim();

            const employee =
                employeeByLogin(login);

            $("extraEmployeeHint").textContent =
                !login
                    ? "Enter an employee login."
                    : employee
                        ? `${employee.name} · ${employee.process} · Brigade ${employee.brigade}`
                        : "Employee not found.";

            updateExtraScheduleHint();
        }
    );

    $("saveExtraDay").addEventListener(
        "click",
        saveExtraDay
    );

    $("extraDaysLoginFilter")?.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); renderExtraDays(); } });
    $("applyExtraDaysFilters")?.addEventListener("click", renderExtraDays);
    $("clearExtraDaysFilters")?.addEventListener("click",()=>{ $("extraDaysDateFilter").value=""; $("extraDaysLoginFilter").value=""; setMultiFilterValues("extraDaysTypeFilter", []); renderExtraDays(); });

    $("scheduleHistoryLogin")?.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); renderScheduleHistory(); } });
    $("applyScheduleHistoryFilters")?.addEventListener("click", renderScheduleHistory);

    $("clearScheduleHistoryFilters")?.addEventListener("click", () => {
        if($("scheduleHistoryDateFrom")) $("scheduleHistoryDateFrom").value="";
        if($("scheduleHistoryDateTo")) $("scheduleHistoryDateTo").value="";
        if($("scheduleHistoryLogin")) $("scheduleHistoryLogin").value="";
        setMultiFilterValues("scheduleHistoryType", []);
        renderScheduleHistory();
    });

    $("hoursMonthPrev").addEventListener(
        "click",
        () => {
            hoursAttendanceMonth = new Date(
                hoursAttendanceMonth.getFullYear(),
                hoursAttendanceMonth.getMonth() - 1,
                1,
                12
            );
            hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
            hoursAttendanceDaySortKey = "";
            hoursAttendanceDaySortDirection = 1;
            renderHoursAttendance();
        }
    );

    $("hoursMonthNext").addEventListener(
        "click",
        () => {
            hoursAttendanceMonth = new Date(
                hoursAttendanceMonth.getFullYear(),
                hoursAttendanceMonth.getMonth() + 1,
                1,
                12
            );
            hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
            hoursAttendanceDaySortKey = "";
            hoursAttendanceDaySortDirection = 1;
            renderHoursAttendance();
        }
    );

    $("hoursClearEmployee").addEventListener(
        "click",
        () => {
            hoursAttendanceEmployeeLogin = "";
            renderHoursAttendance();
        }
    );

    $("closeHoursModal").addEventListener(
        "click",
        () => $("hoursModal").classList.add("hidden")
    );

    $("cancelHoursModal").addEventListener(
        "click",
        () => $("hoursModal").classList.add("hidden")
    );

    $("hoursForm").addEventListener(
        "submit",
        saveHoursEdit
    );

    $("editActualHours")?.addEventListener(
        "input",
        updateEditPreview
    );

    $("editStart").addEventListener(
        "input",
        updateEditPreview
    );

    $("editEnd").addEventListener(
        "input",
        updateEditPreview
    );

    $("editBreak45").addEventListener(
        "change",
        updateEditPreview
    );

    $("editShift").addEventListener(
        "change",
        updateEditPreview
    );

    $("hoursAllSearch")?.addEventListener("input", () => {
        hoursAttendanceEmployeeLogin = "";
        hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
        renderHoursAttendance();
    });
    $("hoursAllSearch")?.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            event.preventDefault();
            hoursAttendanceEmployeeLogin = "";
            hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
            renderHoursAttendance();
        }
    });
    $("hoursFiltersToggle")?.addEventListener("click", () => {
        const filters = $("hoursAdvancedFilters");
        const button = $("hoursFiltersToggle");
        if (!filters || !button) return;
        const show = filters.hidden;
        filters.hidden = !show;
        button.setAttribute("aria-expanded", String(show));
    });
    $("hoursClearAllFilters")?.addEventListener("click", () => {
        if ($("hoursAllSearch")) $("hoursAllSearch").value = "";
        setMultiFilterValues("hoursAllBrigade", []);
        setMultiFilterValues("hoursAllProcess", []);
        setMultiFilterValues("hoursAllStatus", []);
        hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
        hoursAttendanceEmployeeLogin = "";
        renderHoursAttendance();
    });
    $("hoursAdvancedFilters")?.querySelectorAll('input[type="checkbox"]').forEach(input => {
        input.addEventListener("change", () => {
            hoursAttendanceEmployeeLogin = "";
            hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
            renderHoursAttendance();
        });
    });
    $("hoursAllMoreBtn")?.addEventListener("click", showMoreHoursEmployees);
    $("hoursExportAllBtn")?.addEventListener("click", () => exportHoursAttendanceCSV(true));
    $("hoursExportFilteredBtn")?.addEventListener("click", () => exportHoursAttendanceCSV(false));

    $("editStatus").addEventListener(
        "change",
        () => {
            if ($("editStatus").value === "Absent") {
                $("editStart").value = "";
                $("editEnd").value = "";
                $("editBreak45").checked = false;
            }

            updateEditPreview();
        }
    );
}



async function initApp() {
    await loadEmployeesFromSupabase();
    await loadSchedulesFromSupabase();
    await loadIndividualSchedulesFromSupabase();
    await loadExtraDaysFromSupabase();
    await loadAttendanceFromSupabase();
    await loadFeedbackFromSupabase();

    subscribeToScheduleRealtime();
    subscribeToIndividualScheduleRealtime();
    subscribeToExtraDaysRealtime();
    subscribeToAttendanceRealtime();
    subscribeToHistoryRealtime();
    subscribeToEmployeesRealtime();
    subscribeToFeedbackRealtime();

    updateLiveDateTime();
    setInterval(updateLiveDateTime, 1000);
    fillOverviewFilters();
    fillEmployeeFilters();
    fillAdditionalMultiFilters();
    fillFeedbackFilters();

    // Heavy Hours Attendance / Feedback tables are rendered lazily when
    // the user actually opens those pages.

    $("overviewDate").value =
        dateKey(overviewDate);

    initEvents();
    initEmployeeStatusActions();
    $("reloadSystemUsers")?.addEventListener("click", loadSystemUsers);
    await loadSystemUsers();

    switchPage("overviewPage");
}

document.addEventListener("DOMContentLoaded", async () => {
    try {
        await initAuth();
    } catch (error) {
        console.error("Authentication initialization failed:", error);

        const loginError = document.getElementById("loginError");
        if (loginError) {
            loginError.textContent =
                "Authentication could not be initialized. Check Supabase setup.";
        }

        setAuthScreen(false);
    }
});



/* Attendance Monitoring subtabs */
function activateAttendanceSubtab(name) {
    attendanceActiveSubtab = name === "statistics" ? "statistics" : "tracker";
    document.querySelectorAll("[data-attendance-subtab]").forEach(button => {
        button.classList.toggle("active", button.dataset.attendanceSubtab === attendanceActiveSubtab);
    });
    document.querySelectorAll(".attendance-subtab-panel").forEach(panel => {
        panel.classList.toggle("active", panel.id === (attendanceActiveSubtab === "tracker" ? "attendanceTrackerSubpage" : "attendanceStatisticsSubpage"));
    });
    if (attendanceActiveSubtab === "statistics") {
        renderAttendanceMonthlyStats();
    } else {
        renderAllHoursAttendance();
    }
}

/* Attendance Monitoring: all employees + filters + export */
function hoursExportAllowed() {
    return canExportData();
}
function updateHoursExportVisibility() {
    const toolbar = $("hoursExportToolbar");
    if (toolbar) toolbar.hidden = !hoursExportAllowed();
}
function renderAttendanceMonthlyStats() {
    const monthDate = hoursAttendanceMonth;
    const year = monthDate.getFullYear();
    const month = monthDate.getMonth();
    const employees = attendanceMonitoringEmployees(monthDate);
    const monthStart = new Date(year, month, 1, 12);
    const monthEnd = new Date(year, month + 1, 0, 12);
    const inMonth = (dateValue) => {
        const d = dateValue instanceof Date ? dateValue : new Date(`${dateValue}T12:00:00`);
        return d >= monthStart && d <= monthEnd;
    };

    let extraDays = 0, extraNights = 0, extraOff = 0, absentTotal = 0;
    const dailyAbsent = new Map();
    const dailyPlanned = new Map();
    const extraByDate = new Map();

    for (let day = 1; day <= monthEnd.getDate(); day++) {
        const date = new Date(year, month, day, 12);
        dailyAbsent.set(day, 0);
        dailyPlanned.set(day, 0);
    }

    employees.forEach(employee => {
        for (let day = 1; day <= monthEnd.getDate(); day++) {
            const date = new Date(year, month, day, 12);
            if (!canConfirmEmployeeDate(employee, date)) continue;
            const planned = Number(plannedHours(employee, date) || 0);
            if (planned <= 0) continue;
            dailyPlanned.set(day, dailyPlanned.get(day) + 1);
            const data = getAttendance(employee, date);
            if (String(data.status || '').trim().toLowerCase() === 'absent') {
                absentTotal++;
                dailyAbsent.set(day, dailyAbsent.get(day) + 1);
            }
        }
    });

    Object.values(extraDays || {}).forEach(item => {
        if (!item?.date || !inMonth(item.date)) return;
        const key = String(item.date).slice(0, 10);
        if (!extraByDate.has(key)) extraByDate.set(key, { day: 0, night: 0, off: 0 });
        const bucket = extraByDate.get(key);
        if (item.type === 'extra-off') { extraOff++; bucket.off++; }
        else if (item.type === 'extra-work-night') { extraNights++; bucket.night++; }
        else if (item.type === 'extra-work-day') { extraDays++; bucket.day++; }
    });

    $("attendanceStatsExtraDays") && ($("attendanceStatsExtraDays").textContent = String(extraDays));
    $("attendanceStatsExtraNights") && ($("attendanceStatsExtraNights").textContent = String(extraNights));
    $("attendanceStatsExtraOff") && ($("attendanceStatsExtraOff").textContent = String(extraOff));
    $("attendanceStatsAbsent") && ($("attendanceStatsAbsent").textContent = String(absentTotal));
    $("attendanceStatsAbsentDays") && ($("attendanceStatsAbsentDays").textContent = String([...dailyAbsent.values()].filter(v => v > 0).length));

    const absentBody = $("attendanceStatsDailyAbsent");
    if (absentBody) {
        absentBody.innerHTML = Array.from(dailyAbsent.entries()).map(([day, count]) => {
            const planned = dailyPlanned.get(day) || 0;
            const pct = planned ? ((count / planned) * 100).toFixed(1) : '0.0';
            const date = new Date(year, month, day, 12);
            return `<tr><td>${String(day).padStart(2,'0')}</td><td>${date.toLocaleDateString('en-GB')}</td><td>${count}</td><td>${pct}%</td></tr>`;
        }).join('');
    }

    const extraBody = $("attendanceStatsExtraByDate");
    if (extraBody) {
        const rows = [...extraByDate.entries()].sort((a,b) => a[0].localeCompare(b[0]));
        extraBody.innerHTML = rows.map(([key, bucket]) => {
            const date = new Date(`${key}T12:00:00`);
            return `<tr><td>${date.toLocaleDateString('en-GB')}</td><td>${bucket.day}</td><td>${bucket.night}</td><td>${bucket.off}</td></tr>`;
        }).join('') || `<tr><td colspan="4"><div class="empty">No Extra Days records for this month.</div></td></tr>`;
    }
}

function getHoursEmployeeSummary(employee) {
    return getHoursAttendanceEmployeeMetrics(employee, hoursAttendanceMonth);
}
function getHoursAttendanceDaySortRank(employee, dayKey) {
    const [year, month, day] = String(dayKey).split("-").map(Number);
    const date = new Date(year, month - 1, day, 12);
    const cell = getHoursAttendanceDayCell(employee, date);
    const rank = { absent: 0, early: 1, pending: 2, confirmed: 3, off: 4 };
    return Object.prototype.hasOwnProperty.call(rank, cell.className) ? rank[cell.className] : 9;
}

function sortHoursAttendanceEmployees(employees) {
    if (!hoursAttendanceDaySortKey) return employees;
    const direction = hoursAttendanceDaySortDirection;
    return [...employees].sort((a, b) => {
        const rankA = getHoursAttendanceDaySortRank(a, hoursAttendanceDaySortKey);
        const rankB = getHoursAttendanceDaySortRank(b, hoursAttendanceDaySortKey);
        if (rankA !== rankB) return (rankA - rankB) * direction;
        return String(a.name || a.login || "").localeCompare(String(b.name || b.login || ""), undefined, { sensitivity: "base" });
    });
}

function toggleHoursAttendanceDaySort(dayKey) {
    if (hoursAttendanceDaySortKey === dayKey) {
        hoursAttendanceDaySortDirection *= -1;
    } else {
        hoursAttendanceDaySortKey = dayKey;
        hoursAttendanceDaySortDirection = 1;
    }
    hoursAllVisibleCount = LARGE_LIST_PAGE_SIZE;
    renderAllHoursAttendance();
}

function hoursAllFilterEmployees(ignoreFilters = false) {
    let list = attendanceMonitoringEmployees(hoursAttendanceMonth);
    if (ignoreFilters) return list;
    const search = $("hoursAllSearch")?.value.trim().toLowerCase() || "";
    const brigades = selectedMultiValues("hoursAllBrigade");
    const processes = selectedMultiValues("hoursAllProcess");
    const statuses = selectedMultiValues("hoursAllStatus");
    if (search) list = list.filter(e => String(e.login).toLowerCase().includes(search) || String(e.name).toLowerCase().includes(search));
    if (brigades.length) list = list.filter(e => brigades.includes(e.brigade));
    if (processes.length) list = list.filter(e => processes.includes(e.process));
    if (statuses.length) list = list.filter(e => statuses.some(status => {
        const s = getHoursEmployeeSummary(e);
        return status === "Complete" ? s.pending === 0 :
            status === "Pending" ? s.pending > 0 :
            status === "Has difference" ? Math.abs(Number(s.differenceDays || 0)) > 0 :
            status === "Absent" ? s.absent > 0 :
            status === "Left early" ? s.underworked > 0.001 : false;
    }));
    return list;
}
function getHoursAttendanceDayCell(employee, date) {
    const schedule = getSchedule(employee, date);
    if (!canConfirmEmployeeDate(employee, date)) {
        const dateLabel = date.toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit", year: "numeric" });
        const weekdayLabel = date.toLocaleDateString("en-US", { weekday: "long" });
        return {
            code: "O",
            className: "off",
            title: `${weekdayLabel}, ${dateLabel} · Before start date ${employee.startDate} · No attendance confirmation allowed`
        };
    }
    const planned = Number(plannedHours(employee, date) || 0);
    const data = getAttendance(employee, date);
    const actual = Number(data.actualHours || 0);
    const safeActual = Number.isFinite(actual) ? actual : 0;
    const dateLabel = date.toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit", year: "numeric" });
    const weekdayLabel = date.toLocaleDateString("en-US", { weekday: "long" });
    const shiftLabel = SHIFTS[schedule.shift]?.label || String(schedule.shift || "OFF").toUpperCase();

    // Keep Attendance Monitoring synchronized with the exact schedule source used by Shift Overview.
    if (planned <= 0) {
        return {
            code: "O",
            className: "off",
            title: `${weekdayLabel}, ${dateLabel} · ${shiftLabel} · Day off / no planned shift`
        };
    }

    if (!data.confirmed) {
        return {
            code: "P",
            className: "pending",
            title: `${weekdayLabel}, ${dateLabel} · ${shiftLabel} · Pending confirmation · Planned ${planned.toFixed(2)}h`
        };
    }

    const isAbsent = String(data.status || "").trim().toLowerCase() === "absent";
    if (isAbsent) {
        return {
            code: "A",
            className: "absent",
            title: `${weekdayLabel}, ${dateLabel} · ${shiftLabel} · Absent${data.reason ? ` · ${data.reason}` : ""}`
        };
    }

    const leftEarly = planned > 0 && safeActual + 0.001 < planned;
    if (leftEarly) {
        const missing = Math.max(0, planned - safeActual);
        return {
            code: "E",
            className: "early",
            title: `${weekdayLabel}, ${dateLabel} · ${shiftLabel} · Left early · Planned ${planned.toFixed(2)}h · Actual ${safeActual.toFixed(2)}h · Underworked ${missing.toFixed(2)}h${data.reason ? ` · ${data.reason}` : ""}`
        };
    }

    return {
        code: "C",
        className: "confirmed",
        title: `${weekdayLabel}, ${dateLabel} · ${shiftLabel} · Confirmed · ${safeActual.toFixed(2)}h${data.reason ? ` · ${data.reason}` : ""}`
    };
}

function getHoursAttendanceDayHeaders(monthDate = hoursAttendanceMonth) {
    const year = monthDate.getFullYear();
    const month = monthDate.getMonth();
    const headers = [];
    for (let day = 1; day <= monthDays(monthDate); day++) {
        const date = new Date(year, month, day, 12);
        headers.push({
            date,
            key: dateKey(date),
            label: String(day).padStart(2, "0"),
            fullLabel: date.toLocaleDateString("en-GB", { weekday: "long", day: "2-digit", month: "2-digit", year: "numeric" })
        });
    }
    return headers;
}

function renderAllHoursAttendance() {
    if (attendanceActiveSubtab === "statistics") {
        renderAttendanceMonthlyStats();
        return;
    }
    const body = $("hoursAllTableBody"), meta = $("hoursAllMeta"), head = $("hoursAllTableHead");
    if (!body) return;
    updateHoursExportVisibility();

    const filteredEmployees = hoursAllFilterEmployees(false);
    const employees = sortHoursAttendanceEmployees(filteredEmployees);
    const visibleEmployees = employees.slice(0, hoursAllVisibleCount);
    const dayHeaders = getHoursAttendanceDayHeaders(hoursAttendanceMonth);

    let plannedDays = 0, confirmedDays = 0, pending = 0;
    filteredEmployees.forEach(employee => {
        const s = getHoursEmployeeSummary(employee);
        plannedDays += Number(s.plannedDays || 0);
        confirmedDays += Number(s.workedDays || 0);
        pending += Number(s.pending || 0);
    });
    const differenceDays = confirmedDays - plannedDays;

    if ($("hoursAllTotal")) $("hoursAllTotal").textContent = String(employees.length);
    if ($("hoursAllPlanned")) $("hoursAllPlanned").textContent = String(plannedDays);
    if ($("hoursAllConfirmed")) $("hoursAllConfirmed").textContent = String(confirmedDays);
    if ($("hoursAllPending")) $("hoursAllPending").textContent = String(pending);
    if ($("hoursAllDifference")) $("hoursAllDifference").textContent = `${differenceDays > 0 ? "+" : ""}${differenceDays}`;

    if (meta) {
        meta.textContent = `${visibleEmployees.length} of ${employees.length} employee${employees.length === 1 ? "" : "s"} shown · click a row to open the full attendance record`;
    }

    if (head) {
        head.innerHTML = `<tr>
            <th class="hours-matrix-employee-col">Employee</th>
            <th class="hours-matrix-brigade-col">Brigade</th>
            <th class="hours-matrix-process-col">Process</th>
            ${dayHeaders.map(({label, fullLabel, key}) => {
                const active = hoursAttendanceDaySortKey === key;
                const arrow = active ? (hoursAttendanceDaySortDirection === 1 ? "↑" : "↓") : "↕";
                const title = active
                    ? `Sorted by ${fullLabel} · click to reverse order`
                    : `Sort employees by ${fullLabel} · Absent first`;
                return `<th class="hours-matrix-day-col${active ? " is-sorted" : ""}" title="${esc(title)}"><button type="button" class="attendance-day-sort-button" data-hours-sort-day="${esc(key)}" aria-label="${esc(title)}"><span>${esc(label)}</span><small>${arrow}</small></button></th>`;
            }).join("")}
            <th>Planned days</th>
            <th>Worked days</th>
            <th>Difference</th>
            <th>Absent</th>
            <th>Pending</th>
            <th>Underworked</th>
            <th>Attendance</th>
        </tr>`;
    }

    body.innerHTML = visibleEmployees.map(employee => {
        const summary = getHoursEmployeeSummary(employee);
        const difference = Number(summary.differenceDays || 0);
        const dayCells = dayHeaders.map(({date, key}) => {
            const cell = getHoursAttendanceDayCell(employee, date);
            const selectedClass = hoursAttendanceDaySortKey === key ? " is-sorted-column" : "";
            return `<td class="hours-matrix-day-cell${selectedClass}" title="${esc(cell.title)}"><span class="attendance-day-badge ${cell.className}">${esc(cell.code)}</span></td>`;
        }).join("");

        return `<tr class="hours-employee-row" data-hours-employee="${esc(employee.login)}" tabindex="0" title="Open attendance record">
            <td class="hours-matrix-employee"><strong>${esc(employee.name)}</strong><br><small>${esc(employee.login)}</small></td>
            <td class="hours-matrix-brigade">${esc(employee.brigade)}</td>
            <td class="hours-matrix-process">${esc(employee.process)}</td>
            ${dayCells}
            <td>${summary.plannedDays}</td>
            <td>${summary.workedDays}</td>
            <td>${difference > 0 ? "+" : ""}${difference}</td>
            <td>${summary.absent}</td>
            <td>${summary.pending}</td>
            <td>${summary.underworked.toFixed(2)}h</td>
            <td>${summary.attendanceRate.toFixed(1)}%</td>
        </tr>`;
    }).join("") || `<tr><td colspan="${3 + dayHeaders.length + 7}"><div class="empty">No employees match the selected filters.</div></td></tr>`;

    head?.querySelectorAll("[data-hours-sort-day]").forEach(button => {
        button.addEventListener("click", event => {
            event.stopPropagation();
            toggleHoursAttendanceDaySort(button.dataset.hoursSortDay);
        });
    });

    body.querySelectorAll("[data-hours-employee]").forEach(row => {
        const open = () => {
            hoursAttendanceEmployeeLogin = row.dataset.hoursEmployee;
            renderHoursAttendance();
            document.getElementById("hoursEmployeeSummary")?.scrollIntoView({ behavior: "smooth", block: "start" });
        };
        row.addEventListener("click", open);
        row.addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                open();
            }
        });
    });

    const moreWrap = $("hoursAllMoreWrap");
    const moreButton = $("hoursAllMoreBtn");
    const hasMore = visibleEmployees.length < employees.length;
    if (moreWrap) moreWrap.hidden = !hasMore;
    if (moreButton) {
        moreButton.textContent = hasMore ? `More (${Math.min(LARGE_LIST_PAGE_SIZE, employees.length - visibleEmployees.length)})` : "More";
        moreButton.disabled = !hasMore;
    }
}

function showMoreHoursEmployees() {
    const employees = hoursAllFilterEmployees(false);
    if (hoursAllVisibleCount >= employees.length) return;
    hoursAllVisibleCount = Math.min(hoursAllVisibleCount + LARGE_LIST_PAGE_SIZE, employees.length);
    renderAllHoursAttendance();
}

function hoursExportRows(ignoreFilters) {
    const employees = hoursAllFilterEmployees(ignoreFilters), rows=[];
    for (const employee of employees) for (let day=1; day<=monthDays(hoursAttendanceMonth); day++) {
        const date=new Date(hoursAttendanceMonth.getFullYear(),hoursAttendanceMonth.getMonth(),day,12), schedule=getSchedule(employee,date), data=getAttendance(employee,date), planned=plannedHours(employee,date);
        const actual=data.confirmed ? Number(data.actualHours||0) : "", difference=actual === "" ? "" : actual-planned;
        rows.push([employee.login,employee.name,employee.brigade,employee.process,date.toLocaleDateString("en-GB"),date.toLocaleDateString("en-US",{weekday:"long"}),schedule.shift === "day" ? "DAY" : schedule.shift === "night" ? "NIGHT" : schedule.shift === "rest" ? "R" : "OFF",planned.toFixed(2),actual === "" ? "" : actual.toFixed(2),difference === "" ? "" : difference.toFixed(2),data.confirmed ? (data.status || "Confirmed") : (planned>0 ? "Pending" : "OFF"),data.reason||"",data.note||""]);
    }
    return rows;
}
// csvCell is declared once above and reused by all CSV exports.

/* Attendance Monitoring XLSX export
   Matrix layout:
   A = Login
   B = Name
   C+ = every calendar day of selected month
   Unconfirmed = 0 (confirmed-hours matrix; detailed sheet keeps status/reason)
*/
function xlsxEscape(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function xlsxColName(n) {
    let result = "";
    while (n > 0) {
        const r = (n - 1) % 26;
        result = String.fromCharCode(65 + r) + result;
        n = Math.floor((n - 1) / 26);
    }
    return result;
}

function crc32(bytes) {
    let crc = 0 ^ -1;
    for (let i = 0; i < bytes.length; i++) {
        crc ^= bytes[i];
        for (let j = 0; j < 8; j++) {
            crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return (crc ^ -1) >>> 0;
}

function u16(n) {
    return new Uint8Array([n & 255, (n >>> 8) & 255]);
}

function u32(n) {
    return new Uint8Array([
        n & 255,
        (n >>> 8) & 255,
        (n >>> 16) & 255,
        (n >>> 24) & 255
    ]);
}

function bytes(text) {
    return new TextEncoder().encode(text);
}

function joinBytes(parts) {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

function zipStore(files) {
    const local = [];
    const central = [];
    let offset = 0;

    for (const file of files) {
        const name = bytes(file.name);
        const data = bytes(file.data);
        const crc = crc32(data);

        local.push(
            u32(0x04034b50), u16(20), u16(0x0800), u16(0),
            u16(0), u16(0), u32(crc), u32(data.length),
            u32(data.length), u16(name.length), u16(0),
            name, data
        );

        central.push(
            u32(0x02014b50), u16(20), u16(20), u16(0x0800),
            u16(0), u16(0), u16(0), u32(crc), u32(data.length),
            u32(data.length), u16(name.length), u16(0), u16(0),
            u16(0), u16(0), u32(0), u32(offset), name
        );

        offset += 30 + name.length + data.length;
    }

    const localBytes = joinBytes(local);
    const centralBytes = joinBytes(central);

    const end = joinBytes([
        u32(0x06054b50),
        u16(0), u16(0),
        u16(files.length), u16(files.length),
        u32(centralBytes.length),
        u32(localBytes.length),
        u16(0)
    ]);

    return joinBytes([localBytes, centralBytes, end]);
}

function buildHoursAttendanceXlsx(employees) {
    const year = hoursAttendanceMonth.getFullYear();
    const month = hoursAttendanceMonth.getMonth();
    const totalDays = monthDays(hoursAttendanceMonth);

    const header = ["Login", "Name"];
    for (let day = 1; day <= totalDays; day++) {
        header.push(
            `${String(day).padStart(2, "0")}.${String(month + 1).padStart(2, "0")}.${year}`
        );
    }

    const matrix = [header];

    for (const employee of employees) {
        const row = [employee.login, employee.name];

        for (let day = 1; day <= totalDays; day++) {
            const date = new Date(year, month, day, 12);
            const attendance = getAttendance(employee, date);

            // Only confirmed hours are exported.
            // Pending/unconfirmed and OFF days are 0.
            const value = attendance.confirmed
                ? Number(attendance.actualHours || 0)
                : 0;

            row.push(Number.isFinite(value) ? value : 0);
        }

        matrix.push(row);
    }

    const lastCol = xlsxColName(totalDays + 2);
    const lastRow = matrix.length;

    const rowsXml = matrix.map((row, rIndex) => {
        const excelRow = rIndex + 1;
        const cells = row.map((value, cIndex) => {
            const ref = `${xlsxColName(cIndex + 1)}${excelRow}`;

            if (rIndex === 0 || cIndex < 2) {
                return `<c r="${ref}" s="${rIndex === 0 ? 1 : 2}" t="inlineStr"><is><t>${xlsxEscape(value)}</t></is></c>`;
            }

            return `<c r="${ref}" s="3" t="n"><v>${Number(value) || 0}</v></c>`;
        }).join("");

        return `<row r="${excelRow}">${cells}</row>`;
    }).join("");

    const sheetXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<dimension ref="A1:${lastCol}${lastRow}"/>
<sheetViews>
<sheetView workbookViewId="0">
<pane xSplit="2" ySplit="1" topLeftCell="C2" activePane="bottomRight" state="frozen"/>
</sheetView>
</sheetViews>
<sheetFormatPr defaultRowHeight="18"/>
<cols>
<col min="1" max="1" width="14" customWidth="1"/>
<col min="2" max="2" width="28" customWidth="1"/>
<col min="3" max="${totalDays + 2}" width="12" customWidth="1"/>
</cols>
<sheetData>${rowsXml}</sheetData>
<autoFilter ref="A1:${lastCol}${lastRow}"/>
</worksheet>`;

    const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="1">
<numFmt numFmtId="164" formatCode="0.00"/>
</numFmts>
<fonts count="2">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><name val="Calibri"/></font>
</fonts>
<fills count="2">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="D9EAF7"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="2">
<border><left/><right/><top/><bottom/><diagonal/></border>
<border><left style="thin"><color rgb="B7C3D0"/></left><right style="thin"><color rgb="B7C3D0"/></right><top style="thin"><color rgb="B7C3D0"/></top><bottom style="thin"><color rgb="B7C3D0"/></bottom><diagonal/></border>
</borders>
<cellStyleXfs count="1">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
</cellStyleXfs>
<cellXfs count="4">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
<xf numFmtId="0" fontId="1" fillId="1" borderId="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>
<xf numFmtId="0" fontId="1" fillId="0" borderId="1"/>
<xf numFmtId="164" fontId="0" fillId="0" borderId="1" applyNumberFormat="1"><alignment horizontal="center"/></xf>
</cellXfs>
</styleSheet>`;

    const workbookXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Attendance Monitoring" sheetId="1" r:id="rId1"/></sheets>
</workbook>`;

    const workbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`;

    const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;

    const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>`;

    return zipStore([
        {name:"[Content_Types].xml", data:contentTypes},
        {name:"_rels/.rels", data:rootRels},
        {name:"xl/workbook.xml", data:workbookXml},
        {name:"xl/_rels/workbook.xml.rels", data:workbookRels},
        {name:"xl/worksheets/sheet1.xml", data:sheetXml},
        {name:"xl/styles.xml", data:stylesXml}
    ]);
}

function buildShiftEmployeesXlsx(people) {
    const headers = ["Login", "Name", "Brigade", "Process", "Shift", "Worked days", "Planned", "Actual", "Underworked", "Break", "Status", "Confirmed by", "Last changed by", "Note"];
    const rows = [headers];
    const seen = new Set();

    for (const employee of people) {
        if (seen.has(employee.login)) continue;
        seen.add(employee.login);
        const schedule = getSchedule(employee, overviewDate);
        const data = getAttendance(employee, overviewDate);
        const planned = Number(plannedHours(employee, overviewDate) || 0);
        const actual = data.confirmed ? Number(data.actualHours || 0) : 0;
        const isAbsent = String(data.status || "").trim().toLowerCase() === "absent";
        const underworked = data.confirmed && !isAbsent && planned > actual ? planned - actual : 0;
        rows.push([
            employee.login,
            employee.name,
            employee.brigade,
            employee.process,
            schedule.shift === "day" ? "DAY" : schedule.shift === "night" ? "NIGHT" : schedule.shift === "rest" ? "R" : "OFF",
            employeeWorkedDaysForMonth(employee, overviewDate),
            planned.toFixed(2),
            actual.toFixed(2),
            underworked.toFixed(2),
            data.confirmed ? Number(data.breakMinutes || 0) : 0,
            data.confirmed ? (data.status || "Confirmed") : "Not confirmed",
            data.confirmedByName || "",
            data.lastChangedByName || "",
            data.note || ""
        ]);
    }

    const lastCol = xlsxColName(headers.length);
    const lastRow = rows.length;
    const rowsXml = rows.map((row, rIndex) => {
        const excelRow = rIndex + 1;
        return `<row r="${excelRow}">${row.map((value, cIndex) => {
            const ref = `${xlsxColName(cIndex + 1)}${excelRow}`;
            const text = xlsxEscape(value);
            if (rIndex === 0) return `<c r="${ref}" s="1" t="inlineStr"><is><t>${text}</t></is></c>`;
            const numeric = [5,6,7,8,9].includes(cIndex);
            return numeric
                ? `<c r="${ref}" s="3" t="n"><v>${Number(value) || 0}</v></c>`
                : `<c r="${ref}" s="2" t="inlineStr"><is><t>${text}</t></is></c>`;
        }).join("")}</row>`;
    }).join("");

    const sheetXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<dimension ref="A1:${lastCol}${lastRow}"/>
<sheetViews><sheetView workbookViewId="0"><pane xSplit="2" ySplit="1" topLeftCell="C2" activePane="bottomRight" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="18"/>
<cols><col min="1" max="1" width="14" customWidth="1"/><col min="2" max="2" width="28" customWidth="1"/><col min="3" max="4" width="14" customWidth="1"/><col min="5" max="14" width="16" customWidth="1"/></cols>
<sheetData>${rowsXml}</sheetData><autoFilter ref="A1:${lastCol}${lastRow}"/></worksheet>`;

    const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="1"><numFmt numFmtId="164" formatCode="0.00"/></numFmts>
<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="solid"><fgColor rgb="D9EAF7"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="B7C3D0"/></left><right style="thin"><color rgb="B7C3D0"/></right><top style="thin"><color rgb="B7C3D0"/></top><bottom style="thin"><color rgb="B7C3D0"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/><xf numFmtId="0" fontId="1" fillId="1" borderId="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1"/><xf numFmtId="164" fontId="0" fillId="0" borderId="1" applyNumberFormat="1"><alignment horizontal="center"/></xf></cellXfs></styleSheet>`;
    const workbookXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Shift Employees" sheetId="1" r:id="rId1"/></sheets></workbook>`;
    const workbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
    const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
    const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;
    return zipStore([
        {name:"[Content_Types].xml",data:contentTypes},{name:"_rels/.rels",data:rootRels},{name:"xl/workbook.xml",data:workbookXml},{name:"xl/_rels/workbook.xml.rels",data:workbookRels},{name:"xl/worksheets/sheet1.xml",data:sheetXml},{name:"xl/styles.xml",data:stylesXml}
    ]);
}

function exportShiftEmployees() {
    if (!canExportData()) {
        toast("Only Coordinator or Admin can export.");
        return;
    }

    const people = employeesAvailableOnDate(overviewDate).filter(employee => getSchedule(employee, overviewDate).shift === overviewShift);
    if (!people.length) { toast("There are no employees scheduled for this shift."); return; }
    const xlsx = buildShiftEmployeesXlsx(people);
    const date = dateKey(overviewDate);
    const shift = overviewShift === "day" ? "DAY" : "NIGHT";
    const blob = new Blob([xlsx], {type:"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `Shift_Employees_${date}_${shift}.xlsx`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    toast("Shift employees exported to Excel.");
}

function buildHoursAttendanceWorkbook(employees) {
    const year = hoursAttendanceMonth.getFullYear();
    const month = hoursAttendanceMonth.getMonth();
    const totalDays = monthDays(hoursAttendanceMonth);
    const dayHeaders = [];

    for (let day = 1; day <= totalDays; day++) {
        const date = new Date(year, month, day, 12);
        dayHeaders.push(String(day).padStart(2, "0"));
    }

    const dailyRows = [];
    const matrixRows = [];
    const summaryRows = [];
    const detailRows = [];

    for (const employee of employees) {
        const daily = [];
        const matrix = [];
        let plannedTotal = 0;
        let plannedDaysTotal = 0;
        let confirmedTotal = 0;
        let pending = 0;
        let absentDays = 0;
        let underworkedTotal = 0;
        let workedDaysTotal = 0;

        for (let day = 1; day <= totalDays; day++) {
            const date = new Date(year, month, day, 12);
            const schedule = getSchedule(employee, date);
            const data = getAttendance(employee, date);
            const planned = Number(plannedHours(employee, date) || 0);
            const actual = data.confirmed ? Number(data.actualHours || 0) : 0;
            const safeActual = Number.isFinite(actual) ? actual : 0;
            const difference = safeActual - planned;
            const isAbsent = String(data.status || "").trim().toLowerCase() === "absent";
            const leftEarly = Boolean(data.confirmed) && !isAbsent && planned > 0 && safeActual + 0.001 < planned;
            const status = isAbsent ? "Absent" : leftEarly ? "Left early" : data.confirmed ? (data.status || "Confirmed") : (planned > 0 ? "Pending" : "OFF");

            plannedTotal += planned;
            if (planned > 0) plannedDaysTotal++;
            if (isAbsent) {
                absentDays++;
            } else if (data.confirmed) {
                confirmedTotal += safeActual;
                workedDaysTotal++;
                if (leftEarly) underworkedTotal += planned - safeActual;
            }
            if (planned > 0 && !data.confirmed) pending++;
            const matrixCell = getHoursAttendanceDayCell(employee, date);
            matrix.push(matrixCell.code);
            daily.push(Number(safeActual.toFixed(2)));

            detailRows.push([
                date.toISOString().slice(0, 10),
                date.toLocaleDateString("en-US", { weekday: "long" }),
                employee.login,
                employee.name,
                employee.brigade,
                employee.process,
                schedule.shift === "day" ? "DAY" : schedule.shift === "night" ? "NIGHT" : schedule.shift === "rest" ? "R" : "OFF",
                Number(planned.toFixed(2)),
                Number(safeActual.toFixed(2)),
                Number(difference.toFixed(2)),
                status,
                data.actualStart || "",
                data.actualEnd || "",
                Number((leftEarly ? planned - safeActual : 0).toFixed(2)),
                data.reason || (isAbsent ? "Absent" : leftEarly ? "Left early" : ""),
                data.confirmedByName || "",
                data.confirmedAt || "",
                data.lastChangedByName || "",
                data.lastChangedAt || "",
                data.note || ""
            ]);
        }

        const differenceTotal = confirmedTotal - plannedTotal;
        dailyRows.push([
            employee.login,
            employee.name,
            employee.brigade,
            employee.process,
            ...daily,
            Number(confirmedTotal.toFixed(2)),
            Number(plannedTotal.toFixed(2)),
            Number(differenceTotal.toFixed(2)),
            Number(underworkedTotal.toFixed(2)),
            absentDays,
            pending,
            workedDaysTotal
        ]);

        const differenceDays = workedDaysTotal - plannedDaysTotal;
        matrixRows.push([
            employee.login,
            employee.name,
            employee.brigade,
            employee.process,
            ...matrix,
            plannedDaysTotal,
            workedDaysTotal,
            differenceDays,
            absentDays,
            pending,
            Number(underworkedTotal.toFixed(2)),
            plannedDaysTotal > 0 ? Number(((workedDaysTotal / plannedDaysTotal) * 100).toFixed(1)) : 0
        ]);

        summaryRows.push([
            employee.login,
            employee.name,
            employee.brigade,
            employee.process,
            plannedDaysTotal,
            workedDaysTotal,
            differenceDays,
            absentDays,
            pending,
            Number(underworkedTotal.toFixed(2)),
            plannedDaysTotal > 0 ? Number(((workedDaysTotal / plannedDaysTotal) * 100).toFixed(1)) : 0,
            Number(plannedTotal.toFixed(2)),
            Number(confirmedTotal.toFixed(2))
        ]);
    }

    const wb = XLSX.utils.book_new();

    // Sheet 1: visual attendance matrix (schedule-style).
    const matrixHeader = [
        "Login", "Name", "Brigade", "Process",
        ...dayHeaders,
        "Planned days", "Worked days", "Difference days", "Absent days", "Pending days", "Underworked hours", "Attendance %"
    ];
    const matrixSheet = XLSX.utils.aoa_to_sheet([matrixHeader, ...matrixRows]);
    matrixSheet["!freeze"] = { xSplit: 4, ySplit: 1 };
    matrixSheet["!autofilter"] = { ref: XLSX.utils.encode_range({ s: { r: 0, c: 0 }, e: { r: matrixRows.length, c: matrixHeader.length - 1 } }) };
    matrixSheet["!cols"] = [
        { wch: 14 }, { wch: 26 }, { wch: 10 }, { wch: 18 },
        ...dayHeaders.map(() => ({ wch: 8 })),
        { wch: 14 }, { wch: 14 }, { wch: 16 }, { wch: 14 }, { wch: 14 }, { wch: 18 }, { wch: 14 }
    ];
    XLSX.utils.book_append_sheet(wb, matrixSheet, "Attendance Matrix");

    // Legend so the exported matrix remains self-explanatory.
    const legendSheet = XLSX.utils.aoa_to_sheet([
        ["Code", "Meaning"],
        ["C", "Confirmed"],
        ["E", "Left early"],
        ["A", "Absent"],
        ["P", "Pending confirmation"],
        ["O", "Day off / no planned shift"]
    ]);
    legendSheet["!cols"] = [{ wch: 10 }, { wch: 28 }];
    XLSX.utils.book_append_sheet(wb, legendSheet, "Legend");

    // Sheet 3: daily actual-hour matrix.
    const dailyHeader = [
        "Login", "Name", "Brigade", "Process",
        ...dayHeaders,
        "Confirmed total", "Planned total", "Difference", "Underworked hours", "Absent days", "Pending days", "Worked days"
    ];
    const dailySheet = XLSX.utils.aoa_to_sheet([dailyHeader, ...dailyRows]);
    dailySheet["!freeze"] = { xSplit: 4, ySplit: 1 };
    dailySheet["!autofilter"] = { ref: XLSX.utils.encode_range({ s: { r: 0, c: 0 }, e: { r: dailyRows.length, c: dailyHeader.length - 1 } }) };
    dailySheet["!cols"] = [
        { wch: 14 }, { wch: 26 }, { wch: 10 }, { wch: 18 },
        ...dayHeaders.map(() => ({ wch: 11 })),
        { wch: 16 }, { wch: 14 }, { wch: 12 }, { wch: 14 }
    ];
    XLSX.utils.book_append_sheet(wb, dailySheet, "Daily Hours");

    // Sheet 3: one row per employee/day, designed for Excel filtering.
    const detailHeader = [
        "Date", "Day", "Login", "Name", "Brigade", "Process", "Shift",
        "Planned hours", "Actual hours", "Difference", "Status", "Actual start", "Actual end", "Underworked hours", "Reason",
        "Confirmed by", "Confirmed at", "Edit by", "Edited at", "Note"
    ];
    const detailSheet = XLSX.utils.aoa_to_sheet([detailHeader, ...detailRows]);
    detailSheet["!freeze"] = { xSplit: 4, ySplit: 1 };
    detailSheet["!autofilter"] = { ref: XLSX.utils.encode_range({ s: { r: 0, c: 0 }, e: { r: detailRows.length, c: detailHeader.length - 1 } }) };
    detailSheet["!cols"] = [
        { wch: 12 }, { wch: 12 }, { wch: 14 }, { wch: 26 }, { wch: 10 }, { wch: 18 },
        { wch: 10 }, { wch: 14 }, { wch: 13 }, { wch: 12 }, { wch: 16 }, { wch: 20 },
        { wch: 24 }, { wch: 22 }, { wch: 24 }, { wch: 22 }, { wch: 35 }
    ];
    XLSX.utils.book_append_sheet(wb, detailSheet, "Daily Details");

    // Sheet 4: compact employee-level totals.
    const summaryHeader = ["Login", "Name", "Brigade", "Process", "Planned days", "Worked days", "Difference days", "Absent days", "Pending days", "Underworked hours", "Attendance %", "Planned hours", "Confirmed hours"];
    const summarySheet = XLSX.utils.aoa_to_sheet([summaryHeader, ...summaryRows]);
    summarySheet["!freeze"] = { xSplit: 4, ySplit: 1 };
    summarySheet["!autofilter"] = { ref: XLSX.utils.encode_range({ s: { r: 0, c: 0 }, e: { r: summaryRows.length, c: summaryHeader.length - 1 } }) };
    summarySheet["!cols"] = [
        { wch: 14 }, { wch: 26 }, { wch: 10 }, { wch: 18 },
        { wch: 14 }, { wch: 14 }, { wch: 14 }, { wch: 14 },
        { wch: 18 }, { wch: 14 }, { wch: 14 }, { wch: 14 }, { wch: 15 }
    ];
    XLSX.utils.book_append_sheet(wb, summarySheet, "Employee Summary");

    return wb;
}

function exportHoursAttendanceCSV(ignoreFilters = true) {
    if (!hoursExportAllowed()) return;

    const employees = hoursAllFilterEmployees(!ignoreFilters ? false : true);
    if (!employees.length) {
        toast("There are no employees to export.");
        return;
    }

    if (typeof XLSX === "undefined") {
        toast("Excel export library is not available.");
        return;
    }

    const workbook = buildHoursAttendanceWorkbook(employees);
    const month = `${hoursAttendanceMonth.getFullYear()}-${String(hoursAttendanceMonth.getMonth() + 1).padStart(2, "0")}`;
    const suffix = ignoreFilters ? "" : "_Filtered";
    XLSX.writeFile(workbook, `Attendance_Monitoring_${month}${suffix}.xlsx`);
    toast(ignoreFilters
        ? "Attendance monitoring exported to Excel (5 sheets: 4 filterable data sheets + Legend)."
        : "Filtered attendance monitoring exported to Excel (5 sheets: 4 filterable data sheets + Legend).");
}



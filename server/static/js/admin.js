/**
 * FIM Sentinel Admin Dashboard Logic
 * Version: 2.1.0
 * Restructured for global function accessibility and robustness.
 */

// --- Global State ---
window.auditSelectionMode = false;
window.selectedAuditIds = new Set();
window.userToTerminate = null;

// --- CSRF Utility ---
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
}

// --- Global Core Dashboard Functions ---

/**
 * Updates the dashboard logs and statistics.
 * Provisioned as window function for HTML onclick access.
 */
window.refreshDashboard = function () {
    const refreshBtn = document.querySelector('button[onclick*="refreshDashboard"]');
    const icon = refreshBtn ? refreshBtn.querySelector('i') : null;

    // Safety check for icon to avoid property errors
    if (icon) icon.classList.add('fa-spin');

    if (window.showToast) window.showToast("Pulling latest telemetry logs...");

    fetch('/api/logs')
        .then(r => r.json())
        .then(res => {
            if (icon) icon.classList.remove('fa-spin');
            if (!res || !res.success) {
                if (window.showToast) window.showToast("Refresh failure", true);
                return;
            }
            if (window.showToast) window.showToast("Audit logs synchronized");
            const data = res.data;

            // Update stats
            const statIds = ['statTotal', 'statCritical', 'statHigh', 'statMedium', 'statLow', 'statInfo'];
            const statKeys = ['total_events', 'critical_events', 'high_risk', 'medium_risk', 'low_risk', 'info_risk'];

            statIds.forEach((id, i) => {
                const el = document.getElementById(id);
                if (el && data.stats && data.stats[statKeys[i]] !== undefined) {
                    el.innerText = data.stats[statKeys[i]];
                }
            });

            const tbody = document.getElementById('fimTableBody');
            if (!tbody) return;

            const isSelectionMode = window.auditSelectionMode;
            tbody.innerHTML = '';

            if (data.logs && Array.isArray(data.logs)) {
                data.logs.forEach((log, idx) => {
                    const tr = document.createElement('tr');
                    const risk = (log.risk_level || 'INFO').toUpperCase();

                    tr.setAttribute('data-severity', risk);
                    tr.setAttribute('data-id', log.id);
                    tr.setAttribute('data-rank', idx + 1);
                    tr.setAttribute('onclick', `handleRowClick(event, '${log.id}', ${idx + 1})`);
                    tr.setAttribute('data-user', log.username);

                    tr.innerHTML = `
                        <td class="col-no">
                            <span class="normal-view small text-white ${isSelectionMode ? 'd-none' : ''}">${idx + 1}</span>
                            <div class="select-view ${isSelectionMode ? '' : 'd-none'}">
                                <input type="checkbox" class="form-check-input log-cb" value="${log.id}" onclick="event.stopPropagation()" ${window.selectedAuditIds.has(String(log.id)) ? 'checked' : ''}>
                            </div>
                        </td>
                        <td class="col-path">
                            <span class="path-link">${(log.file_path || 'SYSTEM_KERNEL').replace('User: ', '')}</span>
                        </td>
                        <td class="col-action">
                            <span class="text-white fw-bold">
                                ${log.action.includes('DOWNLOAD') || log.action.includes('VIEW') ? `${log.action} <span class="text-info small">(by ${log.username})</span>` : log.action}
                            </span>
                        </td>
                        <td class="col-severity text-center">
                            <span class="badge-fim b-${risk.toLowerCase()}" style="min-width: 80px; display: inline-block;">${risk}</span>
                        </td>
                        <td class="col-time">
                            <span class="small text-white">${log.timestamp}</span>
                        </td>
                        <td class="col-operator">
                            <span class="operator-tag">${log.username}</span>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            if (typeof window.applyFilters === 'function') window.applyFilters();
        })
        .catch(err => {
            if (icon) icon.classList.remove('fa-spin');
            console.error("Refresh failed:", err);
        });
};

/**
 * Filter the logs table based on search criteria.
 */
window.applyFilters = function () {
    const userFilter = document.getElementById("userFilter");
    const severityFilter = document.getElementById("severityFilter");
    const fileSearch = document.getElementById("fileSearch");

    const user = userFilter ? userFilter.value : 'ALL';
    const severity = severityFilter ? severityFilter.value : 'ALL';
    const search = fileSearch ? fileSearch.value.toLowerCase() : '';

    document.querySelectorAll("#fimTableBody tr").forEach(row => {
        const rowUser = row.getAttribute("data-user") || '';
        const rowSeverity = row.getAttribute("data-severity") || '';
        const rowPath = row.cells[1] ? row.cells[1].innerText.toLowerCase() : '';

        const userMatch = (user === "ALL" || rowUser === user);
        const severityMatch = (severity === "ALL" || rowSeverity === severity);
        const searchMatch = (rowPath.includes(search));

        row.style.display = (userMatch && severityMatch && searchMatch) ? "" : "none";
    });
};

// --- Initialization Logic ---
document.addEventListener('DOMContentLoaded', function () {

    // Update System Clock
    function updateClock() {
        const clockEl = document.getElementById('systemClock');
        if (!clockEl) return;
        const now = new Date();
        const h = String(now.getHours()).padStart(2, '0');
        const m = String(now.getMinutes()).padStart(2, '0');
        const s = String(now.getSeconds()).padStart(2, '0');
        clockEl.innerText = `${h}:${m}:${s}`;
    }
    setInterval(updateClock, 1000);
    updateClock();

    const wrapper = document.getElementById("wrapper");
    const menuToggle = document.getElementById("menu-toggle");
    const userFilter = document.getElementById("userFilter");
    const severityFilter = document.getElementById("severityFilter");
    const fileSearch = document.getElementById("fileSearch");

    // --- Sidebar Toggle ---
    if (menuToggle && wrapper) {
        menuToggle.addEventListener("click", function (e) {
            e.preventDefault();
            wrapper.classList.toggle("toggled");
        });
    }

    if (userFilter) userFilter.addEventListener("change", window.applyFilters);
    if (severityFilter) severityFilter.addEventListener("change", window.applyFilters);
    if (fileSearch) fileSearch.addEventListener("input", window.applyFilters);

    // Initial refresh setup
    setInterval(window.refreshDashboard, 30000);

    // --- Audit Report Modal Tab Logic ---
    const auditTypeSelected = document.getElementById('auditTypeSelected');
    const auditTypeRange = document.getElementById('auditTypeRange');
    const auditSelectedView = document.getElementById('auditSelectedView');
    const auditRangeView = document.getElementById('auditRangeView');

    if (auditTypeSelected && auditTypeRange) {
        auditTypeSelected.addEventListener('change', () => {
            if (auditSelectedView) auditSelectedView.classList.remove('d-none');
            if (auditRangeView) auditRangeView.classList.add('d-none');
            const genBtn = document.getElementById('auditGenerateBtn');
            if (genBtn) genBtn.classList.add('d-none');
        });
        auditTypeRange.addEventListener('change', () => {
            if (auditSelectedView) auditSelectedView.classList.add('d-none');
            if (auditRangeView) auditRangeView.classList.remove('d-none');
            const genBtn = document.getElementById('auditGenerateBtn');
            if (genBtn) genBtn.classList.remove('d-none');
        });
    }

    // --- Form Login ---
    const addUserForm = document.getElementById('addUserForm');
    if (addUserForm) {
        addUserForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const usernameInput = document.getElementById('newUsername');
            const username = usernameInput ? usernameInput.value : '';
            const passInput = document.getElementById('newPassword');
            const confInput = document.getElementById('confirmPassword');
            const password = passInput ? passInput.value : '';
            const confirm = confInput ? confInput.value : '';
            const submitBtn = document.getElementById('addUserSubmit');
            const errorEl = document.getElementById('addUserError');

            if (errorEl) errorEl.classList.add('d-none');
            if (passInput) passInput.classList.remove('is-invalid');
            if (confInput) confInput.classList.remove('is-invalid');

            if (password !== confirm) {
                if (errorEl) { errorEl.innerText = "Passwords do not match."; errorEl.classList.remove('d-none'); }
                if (passInput) passInput.classList.add('is-invalid');
                if (confInput) confInput.classList.add('is-invalid');
                return;
            }

            if (password.length < 6) {
                if (errorEl) { errorEl.innerText = "Password must be at least 6 characters."; errorEl.classList.remove('d-none'); }
                if (passInput) passInput.classList.add('is-invalid');
                return;
            }

            const originalContent = submitBtn ? submitBtn.innerHTML : 'PROVISION ACCOUNT';
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Creating...';
            }

            fetch('/add-user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ username, password })
            })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        window.showToast(`✅ Account created: ${username}`);
                        const modal = bootstrap.Modal.getInstance(document.getElementById('addUserModal'));
                        if (modal) modal.hide();
                        addUserForm.reset();
                        // Refresh to reflect in matrix and filter
                        window.refreshDashboard();
                        location.reload(); // Hard refresh to update Jinja-rendered parts for safety
                    } else {
                        if (errorEl) { errorEl.innerText = data.message; errorEl.classList.remove('d-none'); }
                    }
                })
                .catch(() => window.showToast("❌ Connection error", true))
                .finally(() => {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = originalContent;
                    }
                });
        });
    }
});

// --- Audit Selection Mode ---
window.enterAuditSelectionMode = function () {
    const modalEl = document.getElementById('auditModal');
    const modal = bootstrap.Modal.getInstance(modalEl);
    if (modal) modal.hide();

    window.auditSelectionMode = true;
    window.selectedAuditIds.clear();
    updateSelectionTopBar();

    const defFilters = document.getElementById('defaultFilters');
    const auditBar = document.getElementById('auditSelectionBar');
    if (defFilters) defFilters.classList.add('d-none');
    if (auditBar) auditBar.classList.remove('d-none');

    document.querySelectorAll('.normal-view').forEach(el => el.classList.add('d-none'));
    document.querySelectorAll('.select-view').forEach(el => el.classList.remove('d-none'));
};

window.exitAuditSelectionMode = function () {
    window.auditSelectionMode = false;
    window.selectedAuditIds.clear();

    const defFilters = document.getElementById('defaultFilters');
    const auditBar = document.getElementById('auditSelectionBar');
    if (defFilters) defFilters.classList.remove('d-none');
    if (auditBar) auditBar.classList.add('d-none');

    document.querySelectorAll('.normal-view').forEach(el => el.classList.remove('d-none'));
    document.querySelectorAll('.select-view').forEach(el => el.classList.add('d-none'));
    document.querySelectorAll('.log-cb').forEach(cb => cb.checked = false);
};

function updateSelectionTopBar() {
    const countSpan = document.getElementById('topSelectedCount');
    if (countSpan) countSpan.innerText = window.selectedAuditIds.size;
}

window.handleRowClick = function (event, logId, rank) {
    if (window.auditSelectionMode) {
        const tr = event.currentTarget;
        const cb = tr ? tr.querySelector('.log-cb') : null;
        if (cb && event.target !== cb) {
            cb.checked = !cb.checked;
            cb.dispatchEvent(new Event('change', { bubbles: true }));
        }
    } else {
        // Pass the dashboard 'No' (rank) to the report
        window.location.href = `/report?id=${logId}&rank=${rank || ''}`;
    }
};

document.addEventListener('change', function (e) {
    if (e.target && e.target.classList.contains('log-cb')) {
        const id = e.target.value;
        if (e.target.checked) window.selectedAuditIds.add(id);
        else window.selectedAuditIds.delete(id);
        updateSelectionTopBar();
    }
});

// --- Audit Report Generation ---
window.handleAuditSubmit = async function () {
    const type = document.getElementById('auditTypeSelected').checked ? 'selected' : 'range';
    const errEl = document.getElementById('auditModalError');
    if (errEl) errEl.classList.add('d-none');

    let payload = { type };
    if (type === 'range') {
        const from = parseInt(document.getElementById('auditFrom').value);
        const to = parseInt(document.getElementById('auditTo').value);
        if (isNaN(from) || isNaN(to) || from > to) {
            if (errEl) { errEl.innerText = "Invalid range."; errEl.classList.remove('d-none'); }
            return;
        }
        payload.from = from;
        payload.to = to;
    }

    try {
        const res = await fetch('/api/audit/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) window.location.href = data.data.redirect_url;
        else if (errEl) { errEl.innerText = data.message; errEl.classList.remove('d-none'); }
    } catch (e) { console.error(e); }
};

window.generateSelectedAuditReport = async function () {
    if (window.selectedAuditIds.size === 0) {
        window.showToast("No logs selected.", true);
        return;
    }

    // Collect IDs and their corresponding ranks from the DOM
    const selectedItems = [];
    document.querySelectorAll('.log-cb:checked').forEach(cb => {
        const tr = cb.closest('tr');
        if (tr) {
            selectedItems.push({
                id: Number(cb.value),
                rank: tr.getAttribute('data-rank') || ''
            });
        }
    });

    const payload = {
        type: 'selected',
        selectedItems: selectedItems
    };

    try {
        const res = await fetch('/api/audit/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            window.exitAuditSelectionMode();
            window.location.href = data.data.redirect_url;
        }
    } catch (e) { console.error(e); }
};

// --- Purge & User Management ---
// --- LOG PURGE SYSTEM ---
let pendingPurge = null;

window.openPurgeConfirm = function (type, value, message) {
    pendingPurge = { type, value };
    document.getElementById('purgeConfirmText').innerText = message;
    const confirmModal = new bootstrap.Modal(document.getElementById('purgeConfirmModal'));
    confirmModal.show();
};

const purgeFinalBtn = document.getElementById('purgeFinalBtn');
if (purgeFinalBtn) {
    purgeFinalBtn.onclick = function () {
        if (!pendingPurge) return;

        fetch('/api/logs/purge', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify(pendingPurge)
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('purgeConfirmModal')).hide();
                    if (bootstrap.Modal.getInstance(document.getElementById('purgeModal'))) {
                        bootstrap.Modal.getInstance(document.getElementById('purgeModal')).hide();
                    }
                    window.showToast(data.message || "Logs purged successfully");
                    window.refreshDashboard();
                } else {
                    alert("Error: " + data.message);
                }
            });
    };
}

window.handleCustomRangePurge = function () {
    const start = document.getElementById('purgeDateStart').value;
    const end = document.getElementById('purgeDateEnd').value;

    if (!start || !end) {
        alert("Please select both start and end dates.");
        return;
    }

    openPurgeConfirm('range', { start, end }, `Delete all logs between ${start} and ${end}?`);
};

window.openPurgeAllNuclear = function () {
    const nuclearModal = new bootstrap.Modal(document.getElementById('purgeAllNuclearModal'));
    nuclearModal.show();
};

window.executeNuclearPurge = function () {
    const passwordInput = document.getElementById('purgeAllPassword');
    const password = passwordInput ? passwordInput.value : '';
    const confirmCheck = document.getElementById('purgeAllConfirm');
    const confirmed = confirmCheck ? confirmCheck.checked : false;
    const errorDiv = document.getElementById('purgeAllError');

    if (!confirmed) {
        if (errorDiv) {
            errorDiv.innerText = "You must check the confirmation box.";
            errorDiv.classList.remove('d-none');
        }
        return;
    }

    if (!password) {
        if (errorDiv) {
            errorDiv.innerText = "Admin password is required for this action.";
            errorDiv.classList.remove('d-none');
        }
        return;
    }

    if (errorDiv) errorDiv.classList.add('d-none');

    fetch('/api/logs/purge', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ type: 'advanced', value: 'all', password: password })
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                // Clear inputs
                if (passwordInput) passwordInput.value = '';
                if (confirmCheck) confirmCheck.checked = false;

                // Close modals
                const nuclearModalEl = document.getElementById('purgeAllNuclearModal');
                const purgeModalEl = document.getElementById('purgeModal');

                if (nuclearModalEl) {
                    const inst = bootstrap.Modal.getInstance(nuclearModalEl);
                    if (inst) inst.hide();
                }
                if (purgeModalEl) {
                    const inst = bootstrap.Modal.getInstance(purgeModalEl);
                    if (inst) inst.hide();
                }

                if (window.showToast) window.showToast("DATABASE INCINERATED: All logs have been permanently removed.");
                // Refresh dashboard stats and table
                if (window.refreshDashboard) window.refreshDashboard();
            } else {
                if (errorDiv) {
                    errorDiv.innerText = data.message || "Authentication failed or purge error.";
                    errorDiv.classList.remove('d-none');
                }
            }
        })
        .catch(err => {
            console.error("Purge failure:", err);
            if (errorDiv) {
                errorDiv.innerText = "Connection lost: Failed to reach the purge control unit.";
                errorDiv.classList.remove('d-none');
            }
        });
};

window.handleDeleteUser = function (username) {
    window.userToTerminate = username;
    const disp = document.getElementById('terminateUsernameDisplay');
    if (disp) disp.innerText = username;
    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('terminateUserModal'));
    if (modal) modal.show();
};

window.confirmTerminateUser = function () {
    if (!window.userToTerminate) return;

    const confirmBtn = document.getElementById('confirmTerminateBtn');
    const originalContent = confirmBtn ? confirmBtn.innerHTML : 'CONFIRM TERMINATION';
    if (confirmBtn) {
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
    }

    fetch('/delete-user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ username: window.userToTerminate })
    })
        .then(r => {
            // We attempt to parse JSON even for error codes like 400/500 if the server provided details
            return r.json().then(data => {
                if (!r.ok) {
                    // If not ok, throw object with server-provided message
                    throw { message: data.message || `System Error ${r.status}` };
                }
                return data;
            }).catch(err => {
                // If body isn't JSON or fails to parse
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                throw err;
            });
        })
        .then(data => {
            const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('terminateUserModal'));
            if (modal) modal.hide();

            if (data.success) {
                window.showToast("✅ SUCCESS: " + (data.message || "Account terminated."));
                if (window.refreshDashboard) window.refreshDashboard();
                setTimeout(() => location.reload(), 1500);
            } else {
                window.showToast("❌ DENIED: " + (data.message || "Termination request rejected."), true);
            }
        })
        .catch(err => {
            console.error("Termination failure:", err);
            const errorMsg = err.message || "System Link Lost: Failed to reach the control unit.";
            window.showToast("❌ " + errorMsg, true);
        })
        .finally(() => {
            if (confirmBtn) {
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = originalContent;
            }
        });
};

window.openChangePasswordModal = function (username) {
    const disp = document.getElementById('cpUsernameDisplay');
    const inp = document.getElementById('cpUsername');
    if (disp) disp.innerText = username;
    if (inp) inp.value = username;
    const modal = new bootstrap.Modal(document.getElementById('changePasswordModal'));
    modal.show();
};

window.submitChangePassword = function (e) {
    e.preventDefault();
    const username = document.getElementById('cpUsername').value;
    const password = document.getElementById('cpPassword').value;
    const confirm = document.getElementById('cpConfirmPassword').value;

    if (password !== confirm) { window.showToast("Passwords mismatch", true); return; }

    fetch('/admin/change-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ username, password })
    }).then(r => r.json()).then(data => {
        if (data.success) {
            window.showToast("Password updated");
            const modal = bootstrap.Modal.getInstance(document.getElementById('changePasswordModal'));
            if (modal) modal.hide();
        } else window.showToast(data.message, true);
    });
};

window.showToast = function (message, isError = false) {
    const toastEl = document.getElementById('sentinelToast');
    if (!toastEl) return;
    const msgEl = document.getElementById('toastMsg');
    const iconEl = toastEl.querySelector('i');

    if (msgEl) msgEl.innerText = message;
    if (iconEl) {
        iconEl.className = isError ? 'fas fa-exclamation-circle text-danger me-3' : 'fas fa-check-circle text-success me-3';
    }
    const bToast = new bootstrap.Toast(toastEl, { delay: 3000 });
    bToast.show();
};

window.switchSection = function (section) {
    const live = document.getElementById('liveMonitorSection');
    const audit = document.getElementById('auditReportSection');
    if (section === 'live') {
        if (live) live.classList.remove('d-none');
        if (audit) audit.classList.add('d-none');
    } else {
        if (live) live.classList.add('d-none');
        if (audit) audit.classList.remove('d-none');
    }
};

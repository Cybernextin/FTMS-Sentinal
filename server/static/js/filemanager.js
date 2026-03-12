/**
 * FIM Sentinel User File Manager Logic
 * Version: 2.0.0
 * Refined for Premium Theme
 */

// --- CSRF Utility ---
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
}

class FileManager {
    constructor() {
        this.selectedRow = null;
        this.currentUser = {
            id: document.body.dataset.userId ? parseInt(document.body.dataset.userId) : null,
            username: document.body.dataset.userUsername,
            role: document.body.dataset.userRole
        };
        this.allUsers = [];
        this.selectedSharingUsers = [];
        this.lastClickTime = 0;
        this.contextMenu = document.getElementById('contextMenu');

        this.init();
    }

    init() {
        this.bindEvents();
        this.refreshSecurityUI();
        setInterval(() => this.refreshSecurityUI(), 30000);
    }

    bindEvents() {
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.file-row') &&
                !e.target.closest('.btn-premium') &&
                !e.target.closest('.modal-premium-content') &&
                !e.target.closest('#globalModal')) {
                this.deselectAll();
            }
            this.hideContextMenu();
        });

        const fileTableBody = document.getElementById('fileTableBody');
        if (fileTableBody) {
            fileTableBody.oncontextmenu = (e) => {
                const row = e.target.closest('.file-row');
                if (row) {
                    e.preventDefault();
                    this.selectRow(row);
                    this.showContextMenu(e);
                }
            };
        }

        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.handleSearch(e.target.value));
        }
    }

    // --- MODAL SYSTEM ---
    openModal(title, bodyHtml, confirmText, confirmCallback) {
        const modal = document.getElementById('globalModal');
        if (!modal) return;

        const titleEl = document.getElementById('modalTitle');
        const bodyEl = document.getElementById('modalBody');
        const confirmBtn = document.getElementById('modalConfirm');

        if (titleEl) titleEl.innerText = title;
        if (bodyEl) bodyEl.innerHTML = bodyHtml;
        if (confirmBtn) {
            confirmBtn.innerText = confirmText;
            confirmBtn.onclick = confirmCallback;
        }
        modal.style.display = 'flex';
    }

    closeModal() {
        const modal = document.getElementById('globalModal');
        if (modal) modal.style.display = 'none';
    }

    // --- SELECTION ---
    selectRow(row) {
        this.deselectAll();
        row.classList.add('selected');
        this.selectedRow = row;

        const actions = document.getElementById('selectionActions');
        if (actions) {
            actions.style.setProperty('display', 'flex', 'important');

            // Robust selector for View Asset button
            const viewBtn = actions.querySelector('button[onclick*="view"]') ||
                actions.querySelector('button[title="Open"]') ||
                actions.querySelector('.fa-external-link-alt')?.closest('button');

            if (viewBtn) {
                const type = row.getAttribute('data-type');
                viewBtn.style.setProperty('display', (type === 'folder') ? 'none' : 'block', 'important');
            }
        }
    }

    deselectAll() {
        document.querySelectorAll('.file-row').forEach(r => {
            r.classList.remove('selected');
        });
        this.selectedRow = null;
        const actions = document.getElementById('selectionActions');
        if (actions) {
            actions.style.setProperty('display', 'none', 'important');
        }
    }

    // --- NAVIGATION ---
    openItem(row) {
        const path = row.getAttribute('data-path');
        const type = row.getAttribute('data-type');
        const canAccess = row.getAttribute('data-access') === 'true';

        if (!canAccess) {
            this.showToast("Access Denied: Sector restricted", true);
            return;
        }

        if (type === 'folder') {
            window.location.href = `/user/dashboard/${path}`;
        } else {
            const encodedPath = path.split('/').map(encodeURIComponent).join('/');
            window.open(`/view/${encodedPath}`, '_blank');
        }
    }

    showContextMenu(e) {
        if (!this.contextMenu) return;

        // Hide "View Asset" in context menu for folders
        const type = this.selectedRow?.getAttribute('data-type');
        const ctxView = this.contextMenu.querySelector('[onclick*="view"]');
        if (ctxView) {
            ctxView.style.display = (type === 'folder') ? 'none' : 'block';
        }

        this.contextMenu.style.display = 'block';
        this.contextMenu.style.left = e.pageX + 'px';
        this.contextMenu.style.top = e.pageY + 'px';
    }

    hideContextMenu() {
        if (this.contextMenu) {
            this.contextMenu.style.display = 'none';
        }
    }

    handleContextAction(action) {
        this.hideContextMenu();
        switch (action) {
            case 'view':
                this.openItem(this.selectedRow);
                break;
            case 'download':
                this.downloadItem();
                break;
            case 'rename':
                this.prepareRename();
                break;
            case 'move':
                this.prepareMove();
                break;
            case 'delete':
                this.prepareDelete();
                break;
            case 'toggleVisibility':
                this.toggleVisibilityItem();
                break;
        }
    }

    async toggleVisibilityItem() {
        if (!this.selectedRow) return;
        const path = this.selectedRow.getAttribute('data-path');
        const currentVisibility = this.selectedRow.querySelector('.fa-lock') ? 'private' : 'public';
        const nextState = currentVisibility === 'private' ? 'public' : 'private';

        try {
            const res = await fetch('/api/files/visibility', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ path, visibility: nextState })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast(`✅ ${data.message}`);
                setTimeout(() => location.reload(), 800);
            } else {
                this.showToast(`❌ ${data.message}`, true);
            }
        } catch (e) {
            this.showToast("Critical sync failure", true);
        }
    }

    downloadItem(e) {
        if (e) e.stopPropagation();
        if (!this.selectedRow) return;
        const path = this.selectedRow.getAttribute('data-path');
        const type = this.selectedRow.getAttribute('data-type');
        window.location.href = `/download/${path}`;
    }

    // --- OPERATIONS ---
    openUploadModal() {
        const input = document.getElementById('fileInput');
        if (input) input.click();
    }

    async handleFileUpload(event) {
        // user_dashboard.html passes 'this' (the element directly), so handle both Event and Element
        const input = event.target || event;
        const selectedFile = input.files ? input.files[0] : null;
        if (!selectedFile) return;

        console.log("selectedFile before upload:", selectedFile);

        const formData = new FormData();
        formData.append('file', selectedFile);

        let subpath = '';
        const pathname = window.location.pathname;
        if (pathname.includes('/user/dashboard/')) {
            subpath = pathname.replace('/user/dashboard/', '').replace(/^\//, '');
        } else if (pathname.endsWith('/user/dashboard')) {
            // User is at root of their dashboard, subpath is empty string
            subpath = '';
        }

        formData.append('current_path', subpath);
        formData.append('parent_path', subpath);

        try {
            const alertBox = document.createElement('div');
            alertBox.className = 'card-premium animate-fade-in pb-progress-toast';
            alertBox.style.position = 'fixed';
            alertBox.style.bottom = '6rem';
            alertBox.style.right = '2rem';
            alertBox.style.zIndex = '10000';
            alertBox.style.padding = '1rem 2rem';
            alertBox.style.borderLeft = '4px solid #3b82f6';
            alertBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <i class="fas fa-spinner fa-spin text-info"></i>
                    <div class="small bold" id="upload-progress-text">Uploading: 0%</div>
                </div>
            `;
            document.body.appendChild(alertBox);

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/upload', true);
            xhr.setRequestHeader('X-CSRFToken', getCsrfToken());

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percentComplete = Math.round((e.loaded / e.total) * 100);
                    const progressText = document.getElementById('upload-progress-text');
                    if (progressText) {
                        progressText.innerText = `Uploading: ${percentComplete}%`;
                    }
                }
            };

            xhr.onload = () => {
                alertBox.remove();
                if (xhr.status === 200) {
                    try {
                        const result = JSON.parse(xhr.responseText);
                        if (result.success || result.status === 'success') {
                            this.showToast(result.message || "Upload successful", false);
                            setTimeout(() => location.reload(), 500);
                        } else {
                            this.showToast(result.message || "Upload failed", true);
                        }
                    } catch (e) {
                        this.showToast("Upload failed", true);
                    }
                } else if (xhr.status >= 300 && xhr.status < 400 && xhr.getResponseHeader('Location')) {
                    window.location.href = xhr.getResponseHeader('Location');
                } else if (xhr.status === 413) {
                    this.showToast("File too large", true);
                } else {
                    try {
                        const result = JSON.parse(xhr.responseText);
                        this.showToast(result.message || "Upload failed", true);
                    } catch (e) {
                        this.showToast("Transmission error", true);
                    }
                }
            };

            xhr.onerror = () => {
                alertBox.remove();
                this.showToast("Transmission error", true);
            };

            xhr.send(formData);
        } catch (e) {
            console.error(e);
            this.showToast("Transmission error", true);
        }
    }

    openFolderModal() {
        const html = `
            <label class="label-premium">Directory Designation</label>
            <input type="text" id="newFolderName" class="input-premium" placeholder="e.g. CORE_SENSITIVE" autofocus>
        `;
        this.openModal("INITIALIZE DIRECTORY", html, "CREATE", () => {
            const name = document.getElementById('newFolderName').value;
            if (name) {
                this.createFolder(name);
                this.closeModal();
            }
        });
    }

    async createFolder(name) {
        const pathBadge = document.querySelector('.path-badge');
        const currentPath = pathBadge ? pathBadge.innerText.replace('ROOT', '').replace(/^\//, '').trim() : '';

        try {
            const res = await fetch('/user/folder/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({
                    folder_name: name,
                    current_path: currentPath
                })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast("✅ Sector initialized");
                setTimeout(() => location.reload(), 800);
            } else {
                this.showToast(`❌ ${data.message}`, true);
            }
        } catch (err) {
            this.showToast("Connection failure", true);
        }
    }

    // --- CONTEXT ACTIONS ---
    async prepareDelete(e) {
        if (e) e.stopPropagation();
        if (!this.selectedRow) return;

        const name = this.selectedRow.getAttribute('data-name');
        const itemPath = this.selectedRow.getAttribute('data-path') || '';

        // Determine the WORKSPACE OWNER — the person whose root folder this item lives in.
        // This is always the first segment of the path (e.g. 'alice' from 'alice/docs/report.pdf').
        // We must NOT use data-owner (file creator) because admin can create files inside
        // a user's folder — but the workspace owner still has full delete rights.
        const workspaceOwner = itemPath.split('/').filter(p => p)[0] || '';

        // If the item is inside the current user's own workspace, they always have full
        // delete permission — no security key needed from their own lock.
        // Only check lock if the item is in ANOTHER user's workspace.
        let hasLock = false;
        const isOwnWorkspace = workspaceOwner.toLowerCase() === this.currentUser.username.toLowerCase();

        if (!isOwnWorkspace && workspaceOwner) {
            // Item belongs to another user's workspace — check their security lock
            try {
                const res = await fetch(`/security-status?username=${workspaceOwner}`);
                const data = await res.json();
                hasLock = (data.data ? data.data.has_password : data.has_password) === true;
            } catch (e) { }
        }

        const html = `
            <div class="muted small mb-4">You are about to terminate <span class="text-white">${name}</span>. This action is irreversible.</div>
            ${hasLock ? '<label class="label-premium">Security Key Required</label><input type="password" id="deletePass" class="input-premium" placeholder="Enter key...">' : ''}
        `;

        this.openModal("RESOURCE TERMINATION", html, "TERMINATE", () => {
            const pass = hasLock ? document.getElementById('deletePass').value : null;
            this.deleteItem(pass);
        });
    }

    async deleteItem(password) {
        if (!this.selectedRow) return;
        const path = this.selectedRow.getAttribute('data-path');

        try {
            const res = await fetch('/user/folder/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ path, password })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast("✅ Resource incinerated");
                setTimeout(() => location.reload(), 800);
            } else {
                this.showToast(`❌ ${data.message}`, true);
            }
        } catch (e) {
            this.showToast("Action failed", true);
        }
    }

    prepareRename(e) {
        if (e) e.stopPropagation();
        if (!this.selectedRow) return;

        const name = this.selectedRow.getAttribute('data-name');
        const html = `
            <label class="label-premium">New Designation</label>
            <input type="text" id="newName" class="input-premium mb-4" value="${name}">
        `;

        this.openModal("REDESIGNATE RESOURCE", html, "UPDATE", () => {
            const n = document.getElementById('newName').value;
            this.renameItem(n);
        });
    }

    async renameItem(newName, password) {
        if (!this.selectedRow) return;
        const path = this.selectedRow.getAttribute('data-path');

        try {
            const res = await fetch('/user/folder/rename', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ old_path: path, new_name: newName, password })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast("Designation updated", false);
                location.reload();
            } else {
                this.showToast(data.message, true);
            }
        } catch (e) {
            this.showToast("Update failed", true);
        }
    }

    async prepareMove(e) {
        if (e) e.stopPropagation();
        if (!this.selectedRow) return;

        const moveModalEl = document.getElementById('moveModal');
        const confirmBtn = document.getElementById('confirmMoveBtn');
        const treeContainer = document.getElementById('moveDestTree');

        if (!moveModalEl || !confirmBtn || !treeContainer) return;

        this.selectedMoveDest = null;
        treeContainer.innerHTML = '<div class="small p-3 text-muted">Scanning for target sectors...</div>';

        const modal = new bootstrap.Modal(moveModalEl);
        modal.show();

        confirmBtn.onclick = () => {
            if (this.selectedMoveDest === null || this.selectedMoveDest === undefined) {
                this.showToast("Select a destination sector", true);
                return;
            }
            this.moveItem(this.selectedMoveDest);
            modal.hide();
        };

        try {
            const res = await fetch('/api/folders/move-targets');
            const data = await res.json();
            if (data.success) {
                const tree = new FolderTree(treeContainer, (path, id) => {
                    this.selectedMoveDest = path;
                });
                tree.setItems(data.data.targets);
            } else {
                treeContainer.innerHTML = `<div class="text-danger p-3">${data.message}</div>`;
            }
        } catch (e) {
            treeContainer.innerHTML = '<div class="text-danger p-3">Mapping failure</div>';
        }
    }

    async moveItem(destPath, password) {
        if (!this.selectedRow) return;
        const path = this.selectedRow.getAttribute('data-path');

        try {
            const res = await fetch('/user/folder/move', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ src_path: path, dest_path: destPath, password })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast("✅ Resource successfully relocated", false);
                setTimeout(() => location.reload(), 1000);
            } else {
                this.showToast(data.message, true);
            }
        } catch (e) {
            this.showToast("Critical relocation failure", true);
        }
    }

    // --- SHARING ---
    openSharingModal(event, id, name) {
        if (event) event.stopPropagation();
        if (!id && this.selectedRow) {
            id = this.selectedRow.getAttribute('data-id');
            name = this.selectedRow.getAttribute('data-name');
        }
        if (!id) return;
        const html = `
            <div class="muted small mb-3">GRANT SELECTIVE ACCESS FOR: <span class="text-white">${name}</span></div>
            <input type="text" id="userSearch" class="input-premium mb-3" placeholder="Search Users..." onkeyup="window.fileManager.renderUserList(this.value)">
            <div id="userList" class="card-premium" style="max-height: 200px; overflow-y: auto; padding: 0.5rem; border-color: #222;">
                <!-- Users -->
            </div>
        `;
        this.openModal("AUTHORIZATION OVERRIDE", html, "SAVE CHANGES", () => {
            this.saveSharing(id);
            this.closeModal();
        });
        this.loadAvailableUsers(id);
    }

    async loadAvailableUsers(id) {
        const container = document.getElementById('userList');
        if (!container) return;
        container.innerHTML = '<div class="muted small p-4">Syncing user database...</div>';

        try {
            if (this.allUsers.length === 0) {
                const res = await fetch('/api/users');
                const data = await res.json();
                if (data.success) this.allUsers = data.data.users; // Use data.data.users
            }

            this.selectedSharingUsers = JSON.parse(this.selectedRow.getAttribute('data-allowed') || '[]');
            this.renderUserList();
        } catch (e) {
            container.innerHTML = '<div class="text-danger small p-4">Sync failed</div>';
        }
    }

    renderUserList(query = '') {
        const container = document.getElementById('userList');
        if (!container) return;

        const filtered = this.allUsers.filter(u =>
            u.username.toLowerCase().includes(query.toLowerCase()) &&
            u.username !== this.currentUser.username
        );

        container.innerHTML = filtered.map(u => {
            const isSelected = this.selectedSharingUsers.includes(u.username);
            return `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; border-bottom: 1px solid #111;">
                    <div class="small">${u.username}</div>
                    <button class="btn-premium ${isSelected ? 'btn-premium-primary' : 'btn-premium-secondary'}" 
                            style="padding: 0.2rem 0.5rem; font-size: 0.6rem;"
                            onclick="window.fileManager.toggleUser('${u.username}')">
                        ${isSelected ? 'REVOKE' : 'GRANT'}
                    </button>
                </div>
            `;
        }).join('');
    }

    toggleUser(username) {
        const index = this.selectedSharingUsers.indexOf(username);
        if (index > -1) {
            this.selectedSharingUsers.splice(index, 1);
        } else {
            this.selectedSharingUsers.push(username);
        }
        const searchInput = document.getElementById('userSearch');
        this.renderUserList(searchInput ? searchInput.value : '');
    }

    async saveSharing(id) {
        try {
            const res = await fetch(`/api/folders/${id}/access`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ allowedUsers: this.selectedSharingUsers })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast("✅ Access permission updated");
                this.closeModal();
                setTimeout(() => location.reload(), 800);
            } else {
                this.showToast(`❌ ${data.message}`, true);
            }
        } catch (e) {
            this.showToast("Update failed", true);
        }
    }

    // --- SECURITY ---
    openPasswordModal() {
        const hasPass = document.body.dataset.hasPass === 'true';
        const html = hasPass ? `
            <div class="muted small mb-4">You have an active security lock. Entering the password below will allow terminal deletion.</div>
            <input type="password" id="ownerPass" class="input-premium" placeholder="Security Key">
            <button class="btn-premium btn-premium-danger w-100 mt-4" onclick="window.fileManager.deleteOwnerPassword()">TERMINATE LOCK</button>
        ` : `
            <div class="muted small mb-4">Establish a master security key to prevent unauthorized resource termination.</div>
            <input type="password" id="ownerPass" class="input-premium" placeholder="New Security Key">
        `;
        this.openModal(hasPass ? "SECURITY OVERRIDE" : "ESTABLISH LOCK", html, hasPass ? "CONFIRM" : "SET LOCK", () => {
            const pass = document.getElementById('ownerPass').value;
            if (pass) {
                this.setOwnerPassword(pass);
                this.closeModal();
            }
        });
    }

    async refreshSecurityUI() {
        try {
            const res = await fetch('/security-status');
            const data = await res.json();
            // std_response wraps payload under data.data
            const hasPassword = data.data ? data.data.has_password : data.has_password;

            // Update established button (fingerprint)
            const btn = document.getElementById('passwordToggleBtn');
            if (btn) {
                if (hasPassword) {
                    btn.classList.add('active');
                    btn.innerHTML = '<i class="fas fa-fingerprint me-2"></i>SECURED';
                    document.body.dataset.hasPass = 'true';
                } else {
                    btn.classList.remove('active');
                    btn.innerHTML = '<i class="fas fa-fingerprint me-2"></i>ESTABLISH LOCK';
                    document.body.dataset.hasPass = 'false';
                }
            }

        } catch (e) { }
    }

    async setOwnerPassword(password) {
        try {
            const res = await fetch('/set-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ password })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast("Vault lock active", false);
                this.refreshSecurityUI();
            } else {
                this.showToast(data.message, true);
            }
        } catch (e) { }
    }

    async deleteOwnerPassword() {
        try {
            const res = await fetch('/delete-password', {
                method: 'POST',
                headers: { 'X-CSRFToken': getCsrfToken() }
            });
            const data = await res.json();
            if (data.success) { // Changed from data.status === 'success'
                this.showToast("Lock deactivated", false);
                this.refreshSecurityUI();
                this.closeModal();
            } else {
                this.showToast(data.message, true);
            }
        } catch (e) { }
    }

    async handleEnvToggle() {
        const btn = document.getElementById('envToggleBtn');
        if (!btn) return;

        // Guard: prevent double-click / concurrent requests
        if (this._envPending) return;

        const prevState = btn.classList.contains('public') ? 'public' : 'private';
        const newState = prevState === 'public' ? 'private' : 'public';

        // Add loading state visually if needed
        btn.style.opacity = '0.5';
        btn.style.pointerEvents = 'none';

        // STEP 2 — Lock and call backend
        this._envPending = true;
        try {
            const res = await fetch('/api/environment', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({ visibility: newState })
            });
            const data = await res.json();

            if (data.success) {
                // Use ONLY the response value to update UI
                const permission = data.data.permission || newState;

                // Update ONLY after backend confirmation
                this._applyEnvState(btn, permission);
                this.showToast(`Environment set to ${permission.toUpperCase()}`, false);

                // Update DOM from centralized backend state
                document.querySelectorAll('.file-row').forEach(row => {
                    const rowOwner = row.getAttribute('data-owner');
                    if (rowOwner && rowOwner.toLowerCase() !== this.currentUser.username.toLowerCase()) {
                        return; // Shared folders don't change mode when personal toggle flips
                    }
                    const accessTd = row.children[3];
                    const iconBox = row.querySelector('.item-icon-box i.fas');
                    const isPrivate = (permission === 'private');

                    if (iconBox && row.getAttribute('data-type') === 'folder') {
                        iconBox.style.transform = 'scale(0)';
                        setTimeout(() => {
                            iconBox.className = isPrivate ? 'fas fa-lock text-white' : 'fas fa-globe text-white';
                            iconBox.style.transform = 'scale(1)';
                        }, 150);
                    }

                    if (accessTd) {
                        accessTd.style.opacity = '0';
                        setTimeout(() => {
                            if (permission === 'public') {
                                accessTd.innerHTML = `
                                    <span style="color: var(--public-red); font-size: 0.7rem; font-weight: 700; transition: all 0.3s ease;">
                                        <i class="fas fa-eye me-1"></i> PUBLIC
                                    </span>`;
                            } else {
                                accessTd.innerHTML = `
                                    <span style="color: var(--secure-green); font-size: 0.7rem; font-weight: 700; transition: all 0.3s ease;">
                                        <i class="fas fa-shield-check me-1"></i> SECURE
                                    </span>`;
                            }
                            accessTd.style.transition = 'opacity 0.3s ease';
                            accessTd.style.opacity = '1';
                        }, 150);
                    }
                });

                // Force Global Refresh after visual update
                setTimeout(() => location.reload(), 600);
            } else {
                this.showToast(data.message || 'Update failed', true);
            }
        } catch (e) {
            this.showToast('Connection error — update failed', true);
        } finally {
            this._envPending = false;
            btn.style.opacity = '1';
            btn.style.pointerEvents = 'all';
        }
    }

    /**
     * STEP 3 — CSS-only state application.
     * Only switches class names; CSS transitions handle the animation both directions.
     */
    _applyEnvState(btn, state) {
        // Remove both states cleanly, then apply the target
        btn.classList.remove('public', 'private');
        btn.classList.add(state);
    }

    // --- UTILS ---
    handleSearch(query) {
        const rows = document.querySelectorAll('.file-row');
        rows.forEach(row => {
            const name = row.getAttribute('data-name').toLowerCase();
            row.style.display = name.includes(query.toLowerCase()) ? '' : 'none';
        });
    }

    showToast(msg, isError) {
        const alertBox = document.createElement('div');
        alertBox.className = 'card-premium animate-fade-in';
        alertBox.style.position = 'fixed';
        alertBox.style.bottom = '2rem';
        alertBox.style.right = '2rem';
        alertBox.style.zIndex = '10000';
        alertBox.style.padding = '1rem 2rem';
        alertBox.style.borderLeft = `4px solid ${isError ? '#ff4d4d' : '#ffffff'}`;
        alertBox.innerHTML = `
            <div style="display: flex; align-items: center; gap: 1rem;">
                <i class="fas ${isError ? 'fa-exclamation-triangle text-danger' : 'fa-check-circle'}"></i>
                <div class="small bold">${msg}</div>
            </div>
        `;
        document.body.appendChild(alertBox);
        setTimeout(() => {
            alertBox.style.opacity = '0';
            alertBox.style.transform = 'translateY(10px)';
            setTimeout(() => alertBox.remove(), 300);
        }, 3000);
    }
}

// Global instance
window.fileManager = new FileManager();

// Exported functions for onclick events in HTML
window.selectRow = (el) => window.fileManager.selectRow(el);
window.openItem = (el) => window.fileManager.openItem(el);
window.handleFileUpload = (e) => window.fileManager.handleFileUpload(e);
window.openUploadModal = () => window.fileManager.openUploadModal();
window.openFolderModal = () => window.fileManager.openFolderModal();
window.openSharingModal = (event, id, name) => window.fileManager.openSharingModal(event, id, name);
window.openPasswordModal = () => window.fileManager.openPasswordModal();
window.handleEnvToggle = () => window.fileManager.handleEnvToggle();
window.prepareDelete = (e) => window.fileManager.prepareDelete(e);
window.prepareRename = (e) => window.fileManager.prepareRename(e);
window.prepareMove = (e) => window.fileManager.prepareMove(e);
window.downloadItem = (e) => window.fileManager.downloadItem(e);
window.handleContextAction = (action) => window.fileManager.handleContextAction(action);
window.closeModal = () => window.fileManager.closeModal();

// toggleMasterLock: calls the owner password modal (lock/unlock system)
window.toggleMasterLock = () => window.fileManager.openPasswordModal();

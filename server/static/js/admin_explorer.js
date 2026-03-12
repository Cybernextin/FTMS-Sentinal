// --- CSRF Utility ---
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
}

class AdminExplorer {
    constructor() {
        this.currentPath = "";
        this.selectedItem = null;
        this.allItems = []; // For filtering

        this.cacheElements();
        this.bindEvents();
        this.loadPath("");
    }

    cacheElements() {
        this.fileGrid = document.getElementById('fileGrid');
        this.breadcrumb = document.getElementById('breadcrumb');
        this.contextMenu = document.getElementById('contextMenu');
        this.fileInput = document.getElementById('fileInput');
        this.emptyState = document.getElementById('emptyState');
        this.backBtn = document.getElementById('backBtn');
        this.searchField = document.getElementById('explorerSearch');

        this.deleteConfirmModal = document.getElementById('deleteConfirmModal');
        this.renameModal = document.getElementById('renameModal');
        this.moveModal = document.getElementById('moveModal');
    }

    bindEvents() {
        // Navigation
        this.breadcrumb.onclick = (e) => {
            const item = e.target.closest('.breadcrumb-item');
            if (item) this.loadPath(item.dataset.path);
        };

        if (this.backBtn) {
            this.backBtn.onclick = () => this.navigateBack();
        }

        // Selection & Context Menu
        this.fileGrid.oncontextmenu = (e) => {
            const item = e.target.closest('.file-card-premium');
            if (item) {
                e.preventDefault();
                this.selectItem(item);
                this.showContextMenu(e, item.dataset);
            }
        };

        document.onclick = (e) => {
            this.hideContextMenu();
            if (!e.target.closest('.file-card-premium') &&
                !e.target.closest('.modal') &&
                !e.target.closest('.ctx-item') &&
                !e.target.closest('.btn-premium')) {
                this.deselectAll();
            }
        };

        // Search Filtering
        if (this.searchField) {
            this.searchField.oninput = (e) => this.filterItems(e.target.value);
        }

        // CRUD Actions Bindings
        const newFolderBtn = document.getElementById('newFolderBtn');
        if (newFolderBtn) newFolderBtn.onclick = () => this.promptCreateFolder();

        const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
        if (confirmDeleteBtn) confirmDeleteBtn.onclick = () => this.executeDelete();

        const confirmRenameBtn = document.getElementById('confirmRenameBtn');
        if (confirmRenameBtn) confirmRenameBtn.onclick = () => this.executeRename();

        const confirmMoveBtn = document.getElementById('confirmMoveBtn');
        if (confirmMoveBtn) confirmMoveBtn.onclick = () => this.executeMove();

        // Context Menu Actions
        this.contextMenu.onclick = (e) => {
            const action = e.target.closest('.ctx-item')?.dataset.action;
            if (action) this.handleContextAction(action);
        };

        const confirmCreateBtn = document.getElementById('confirmCreateFolderBtn');
        if (confirmCreateBtn) confirmCreateBtn.onclick = () => this.executeCreateFolder();

        // Bind Back Button
        const backBtn = document.getElementById('backBtn');
        if (backBtn) {
            backBtn.onclick = () => {
                if (this.currentPath) {
                    this.navigateBack();
                } else {
                    window.location.href = '/admin/dashboard';
                }
            };
        }
    }

    navigateBack() {
        if (!this.currentPath) return;
        const parts = this.currentPath.split('/').filter(p => p);
        parts.pop();
        this.loadPath(parts.join('/'));
    }

    async loadPath(path) {
        const syncIcons = document.querySelectorAll('.fa-sync-alt');
        syncIcons.forEach(i => i.classList.add('fa-spin'));

        this.currentPath = path;
        this.updateBreadcrumb();
        this.deselectAll();
        if (this.searchField) this.searchField.value = "";

        try {
            const res = await fetch(`/admin/file-api/list?subpath=${encodeURIComponent(path)}&t=${Date.now()}`);
            const data = await res.json();

            syncIcons.forEach(i => i.classList.remove('fa-spin'));

            if (data.success) {
                this.allItems = data.data.items;
                this.render(data.data.items);
            } else {
                this.showToast(data.message, true);
            }
        } catch (e) {
            syncIcons.forEach(i => i.classList.remove('fa-spin'));
            this.showToast("Network oscillation detected", true);
        }
    }

    selectItem(itemEl) {
        this.deselectAll();
        itemEl.classList.add('selected');
        this.selectedItem = itemEl.dataset;

        const actions = document.getElementById('selectionActions');
        if (actions) {
            actions.style.setProperty('display', 'flex', 'important');

            // Robust selector for View Asset button
            const viewBtn = actions.querySelector('button[onclick*="view"]') ||
                actions.querySelector('.fa-external-link-alt')?.closest('button');

            if (viewBtn) {
                viewBtn.style.setProperty('display', (this.selectedItem.type === 'folder') ? 'none' : 'block', 'important');
            }
        }
    }

    deselectAll() {
        document.querySelectorAll('.file-card-premium.selected').forEach(el => el.classList.remove('selected'));
        this.selectedItem = null;

        const actions = document.getElementById('selectionActions');
        if (actions) {
            actions.style.setProperty('display', 'none', 'important');
        }
    }

    filterItems(query) {
        const q = query.toLowerCase();
        const filtered = this.allItems.filter(i => i.name.toLowerCase().includes(q));
        this.render(filtered); // Pass filtered items to render
    }

    render(itemsToRender = this.allItems) {
        this.fileGrid.innerHTML = "";
        const fragment = document.createDocumentFragment();

        if (itemsToRender.length === 0) {
            this.emptyState.classList.remove('d-none');
            return;
        }

        this.emptyState.classList.add('d-none');
        itemsToRender.forEach(item => {
            const card = document.createElement('div');
            card.className = `file-card-premium animate__animated animate__fadeIn ${this.selectedItem && this.selectedItem.path === item.path ? 'selected' : ''}`;
            card.dataset.id = item.id;
            card.dataset.path = item.path;
            card.dataset.name = item.name;
            card.dataset.type = item.type;
            card.dataset.owner = item.owner;

            let iconClass = item.type === 'folder' ? 'fa-folder text-warning' : this.getFileIcon(item.name);

            card.innerHTML = `
                <i class="fas ${iconClass} file-icon"></i>
                <span class="file-info-label" title="${item.name}">${item.name}</span>
                <span class="file-info-meta">${item.type === 'folder' ? 'SECTOR' : this.formatSize(item.size)}</span>
            `;

            card.onclick = (e) => {
                e.stopPropagation();
                this.selectItem(card);
            };

            card.ondblclick = () => {
                if (item.type === 'folder') {
                    this.loadPath(item.path);
                } else {
                    const encodedPath = item.path.split('/').map(encodeURIComponent).join('/');
                    window.open(`/view/${encodedPath}`, '_blank');
                }
            };

            fragment.appendChild(card);
        });
        this.fileGrid.appendChild(fragment);
    }

    updateBreadcrumb() {
        const parts = this.currentPath.split('/').filter(p => p);
        let html = '<span class="breadcrumb-item muted" data-path="" style="cursor: pointer;">ROOT</span>';
        let acc = "";
        parts.forEach(p => {
            acc += (acc ? '/' : '') + p;
            html += ` <i class="fas fa-chevron-right opacity-25" style="font-size: 0.6rem;"></i> <span class="breadcrumb-item" data-path="${acc}" style="cursor: pointer;">${p.toUpperCase()}</span>`;
        });
        this.breadcrumb.innerHTML = html;
    }

    showContextMenu(e, data) {
        this.selectedItem = data;

        // Hide "View Asset" in context menu for folders
        const ctxView = this.contextMenu.querySelector('[data-action="view"]');
        if (ctxView) {
            ctxView.style.display = (data.type === 'folder') ? 'none' : 'block';
        }

        this.contextMenu.style.display = 'block';
        this.contextMenu.style.left = e.pageX + 'px';
        this.contextMenu.style.top = e.pageY + 'px';
    }

    hideContextMenu() {
        this.contextMenu.style.display = 'none';
    }

    handleContextAction(action) {
        switch (action) {
            case 'view':
                if (this.selectedItem.type === 'file') {
                    const encodedPath = this.selectedItem.path.split('/').map(encodeURIComponent).join('/');
                    window.open(`/view/${encodedPath}`, '_blank');
                }
                break;
            case 'download':
                window.location.href = `/admin/file-api/download?path=${encodeURIComponent(this.selectedItem.path)}`;
                break;
            case 'delete':
                document.getElementById('deleteItemName').innerText = this.selectedItem.name;
                new bootstrap.Modal(this.deleteConfirmModal).show();
                break;
            case 'rename':
                document.getElementById('newNameInput').value = this.selectedItem.name;
                new bootstrap.Modal(this.renameModal).show();
                break;
            case 'move':
                this.loadMoveDestinations();
                new bootstrap.Modal(this.moveModal).show();
                break;
            case 'toggleVisibility':
                this.toggleVisibilityItem();
                break;
        }
    }

    async toggleVisibilityItem() {
        if (!this.selectedItem) return;
        const path = this.selectedItem.path;

        // Find current visibility from the allItems cache
        const itemData = this.allItems.find(i => i.path === path);
        const currentVisibility = itemData ? itemData.visibility : 'public';
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
                setTimeout(() => this.loadPath(this.currentPath), 800);
            } else {
                this.showToast(`❌ ${data.message}`, true);
            }
        } catch (e) {
            this.showToast("Command failure", true);
        }
    }

    async executeDelete() {
        const res = await this.executeAction('/admin/file-api/delete', { path: this.selectedItem.path });
        if (res.success) {
            bootstrap.Modal.getInstance(this.deleteConfirmModal).hide();
        }
    }

    async executeRename() {
        const newName = document.getElementById('newNameInput').value;
        if (!newName) return;
        const res = await this.executeAction('/admin/file-api/rename', {
            old_path: this.selectedItem.path,
            new_name: newName
        });
        if (res.success) {
            bootstrap.Modal.getInstance(this.renameModal).hide();
        }
    }

    async loadMoveDestinations() {
        const container = document.getElementById('moveDestTree');
        if (!container) return;

        container.innerHTML = '<div class="small p-2 text-muted">Scanning sectors...</div>';

        try {
            const res = await fetch('/api/folders/move-targets');
            const data = await res.json();

            if (data.success) {
                // Initialize new FolderTree
                this.moveTree = new FolderTree(container, (path, id) => {
                    this.selectedMoveDest = path;
                    // Optional: Highlight UI feedback if needed
                });
                this.moveTree.setItems(data.data.targets);
            } else {
                container.innerHTML = `<div class="text-danger p-2">${data.message}</div>`;
            }
        } catch (e) {
            container.innerHTML = '<div class="text-danger p-2">Scan failed</div>';
        }
    }

    async executeMove() {
        const destPath = this.selectedMoveDest;

        if (destPath === undefined || destPath === null) {
            this.showToast("No destination sector selected", true);
            return;
        }

        const res = await this.executeAction('/admin/file-api/move', {
            src_path: this.selectedItem.path,
            dest_dir: destPath
        });
        if (res.success) {
            // Close modal manually since we might not have the instance saved cleanly
            const el = document.getElementById('moveModal');
            if (el) {
                const modal = bootstrap.Modal.getInstance(el);
                if (modal) modal.hide();
            }
        }
    }

    promptCreateFolder() {
        const modal = document.getElementById('createFolderModal');
        if (modal) {
            document.getElementById('folderNameInput').value = "";
            new bootstrap.Modal(modal).show();
        }
    }

    async executeCreateFolder() {
        const name = document.getElementById('folderNameInput').value;
        if (!name) return;

        const res = await this.executeAction('/admin/file-api/create-folder', {
            parent: this.currentPath,
            name: name
        });

        if (res.success) {
            bootstrap.Modal.getInstance(document.getElementById('createFolderModal')).hide();
        }
    }

    async handleUpload(input) {
        const files = input.files;
        if (!files.length) return;

        for (let file of files) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('parent_path', this.currentPath);

            try {
                this.showToast(`Relaying asset: ${file.name}... (0%)`);
                await new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/upload', true);
                    xhr.setRequestHeader('X-CSRFToken', getCsrfToken());
                    xhr.timeout = 120000;

                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            const percent = Math.round((e.loaded / e.total) * 100);
                            const msgEl = document.getElementById('toastMsg');
                            if (msgEl && (msgEl.innerText.includes('Relaying') || msgEl.innerText.includes('Uploading'))) {
                                msgEl.innerText = `Uploading ${file.name}: ${percent}%`;
                            }
                        }
                    };

                    xhr.onload = () => {
                        if (xhr.status >= 200 && xhr.status < 300) {
                            this.showToast(`✅ Asset ${file.name} deployed`);
                            resolve();
                        } else {
                            this.showToast(`❌ Deployment failed: ${file.name}`, true);
                            reject();
                        }
                    };

                    xhr.onerror = () => {
                        this.showToast("Transmission failure", true);
                        reject();
                    };

                    xhr.ontimeout = () => {
                        this.showToast("Transmission timed out", true);
                        reject();
                    };

                    xhr.send(formData);
                });
            } catch (e) {
                // Toast handled inside promise reject
            }
        }
        this.loadPath(this.currentPath);
        input.value = "";
    }

    async executeAction(url, body) {
        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify(body)
            });
            const data = await res.json();
            this.showToast(data.message, !data.success);
            if (data.success) this.loadPath(this.currentPath);
            return data;
        } catch (e) {
            this.showToast("Command failed", true);
            return { status: 'error' };
        }
    }

    getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const icons = {
            'pdf': 'fa-file-pdf text-danger',
            'doc': 'fa-file-word text-primary',
            'docx': 'fa-file-word text-primary',
            'xls': 'fa-file-excel text-success',
            'xlsx': 'fa-file-excel text-success',
            'png': 'fa-file-image text-info',
            'jpg': 'fa-file-image text-info',
            'zip': 'fa-file-archive text-warning',
            'txt': 'fa-file-alt muted',
            'py': 'fa-file-code text-primary',
            'js': 'fa-file-code text-warning',
            'html': 'fa-file-code text-danger'
        };
        return icons[ext] || 'fa-file-lines muted';
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    showToast(message, isError = false) {
        const toastEl = document.getElementById('sentinelToast');
        if (!toastEl) return;

        const msgEl = document.getElementById('toastMsg');
        const iconEl = document.getElementById('toastIcon');

        if (msgEl) msgEl.innerText = message;
        if (iconEl) {
            if (isError) {
                iconEl.className = 'fas fa-exclamation-triangle text-danger me-3';
                toastEl.style.borderColor = 'rgba(239, 68, 68, 0.4)';
            } else {
                iconEl.className = 'fas fa-check-circle text-success me-3';
                toastEl.style.borderColor = 'rgba(255, 255, 255, 0.1)';
            }
        }

        const bToast = new bootstrap.Toast(toastEl, { delay: 3000 });
        bToast.show();
    }
}

// Global handle for Environment Toggle
window.handleAdminEnvToggle = async () => {
    const btn = document.getElementById('envToggleBtn');
    if (!btn) return;

    const isPublic = btn.classList.contains('public');
    const nextState = isPublic ? 'private' : 'public';

    try {
        btn.style.opacity = "0.5";
        btn.style.pointerEvents = "none";

        const res = await fetch('/api/environment', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ visibility: nextState })
        });
        const data = await res.json();

        if (data.success) {
            const permission = data.data.permission || data.data.visibility;
            btn.classList.remove('public', 'private');
            btn.classList.add(permission);
            if (window.adminExplorer) {
                window.adminExplorer.showToast("👑 System reconfiguration successful");
                // Always fetch updated permission state from backend
                window.adminExplorer.loadPath(window.adminExplorer.currentPath);
            }
        } else {
            if (window.adminExplorer) window.adminExplorer.showToast(`❌ ${data.message}`, true);
        }
    } catch (e) {
        console.error(e);
    } finally {
        btn.style.opacity = "1";
        btn.style.pointerEvents = "all";
    }
};

document.addEventListener('DOMContentLoaded', () => {
    window.adminExplorer = new AdminExplorer();
});

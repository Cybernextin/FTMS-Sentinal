/**
 * FolderTree Component (Vanilla JS Implementation of Recursive Tree)
 * Supports nested rendering, expansion states, and selection.
 */

class FolderTree {
    constructor(container, onSelect) {
        this.container = container;
        this.onSelect = onSelect;
        this.rootNodes = [];
        this.selectedPath = null;
        this.expandedNodes = new Set();
        this.nodeMap = new Map(); // Store nodes for easy updates
    }

    setItems(items) {
        // Items is expected to be a nested tree structure now
        // e.g. [{ id: 0, children: [...] }]
        this.rootNodes = items;
        // Default expand ROOT
        if (this.rootNodes.length > 0) {
            this.expandedNodes.add(this.rootNodes[0].id);
        }
        this.render();
    }

    render() {
        this.container.innerHTML = '';
        const fragment = document.createDocumentFragment();
        const rootDiv = document.createElement('div');
        rootDiv.className = 'tree-root';

        this.rootNodes.forEach(node => {
            rootDiv.appendChild(this.createNodeElement(node, 0));
        });

        fragment.appendChild(rootDiv);
        this.container.appendChild(fragment);
    }

    /**
     * Recursive function to create node and its children
     */
    createNodeElement(node, depth) {
        const nodeContainer = document.createElement('div');
        nodeContainer.className = 'tree-node-container';
        nodeContainer.dataset.id = node.id;

        // --- ROW WRAPPER ---
        const row = document.createElement('div');
        row.className = 'tree-row';
        if (this.selectedPath === node.path) row.classList.add('selected');

        // Indentation padding
        row.style.paddingLeft = `${depth * 16 + 8}px`;

        // --- ARROW ---
        const hasChildren = node.children && node.children.length > 0;
        const arrow = document.createElement('div');
        arrow.className = 'tree-arrow';

        if (hasChildren) {
            const icon = document.createElement('i');
            const isExpanded = this.expandedNodes.has(node.id);
            icon.className = `fas fa-play tree-chevron ${isExpanded ? 'rotated' : ''}`;
            icon.style.fontSize = '0.6rem';
            arrow.appendChild(icon);

            // Expand/Collapse Click
            arrow.onclick = (e) => {
                e.stopPropagation();
                this.toggleNode(node.id);
            };
        }
        row.appendChild(arrow);

        // --- ICON ---
        const folderIcon = document.createElement('i');
        folderIcon.className = node.id === 0 ? 'fas fa-hdd tree-icon-root' : 'fas fa-folder tree-icon-folder';
        row.appendChild(folderIcon);

        // --- LABEL ---
        const label = document.createElement('span');
        label.className = 'tree-label';
        label.textContent = node.name;
        row.appendChild(label);

        // --- SELECTION CLICK ---
        row.onclick = (e) => {
            e.stopPropagation();
            this.selectNode(node, row);
        };

        nodeContainer.appendChild(row);

        // --- CHILDREN RENDER ---
        if (hasChildren && this.expandedNodes.has(node.id)) {
            const childrenContainer = document.createElement('div');
            childrenContainer.className = 'tree-children';
            node.children.forEach(child => {
                childrenContainer.appendChild(this.createNodeElement(child, depth + 1));
            });
            nodeContainer.appendChild(childrenContainer);
        }

        return nodeContainer;
    }

    toggleNode(id) {
        if (this.expandedNodes.has(id)) {
            this.expandedNodes.delete(id);
        } else {
            this.expandedNodes.add(id);
        }
        this.render(); // Re-render to update view (React-like behavior)
    }

    selectNode(node, rowEl) {
        this.selectedPath = node.path;
        this.render(); // Re-render to update highlights
        if (this.onSelect) this.onSelect(node.path, node.id);
    }
}

window.FolderTree = FolderTree;

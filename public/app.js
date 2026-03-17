let sbomData = null;
let allComponents = [];

// DOM Elements
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const uploadBtn = document.getElementById('uploadBtn');
const loading = document.getElementById('loading');
const error = document.getElementById('error');
const results = document.getElementById('results');
const statsDiv = document.getElementById('stats');
const dependencyTree = document.getElementById('dependencyTree');
const componentsTableBody = document.getElementById('componentsTableBody');
const expandAllBtn = document.getElementById('expandAll');
const collapseAllBtn = document.getElementById('collapseAll');
const searchBox = document.getElementById('searchBox');

// Event Listeners
fileInput.addEventListener('change', handleFileSelect);
uploadBtn.addEventListener('click', handleUpload);
expandAllBtn.addEventListener('click', () => toggleAllNodes(true));
collapseAllBtn.addEventListener('click', () => toggleAllNodes(false));
searchBox.addEventListener('input', handleSearch);

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
        fileName.textContent = file.name;
        uploadBtn.disabled = false;
    } else {
        fileName.textContent = 'Choose SBOM File (.json or .xml)';
        uploadBtn.disabled = true;
    }
}

async function handleUpload() {
    const file = fileInput.files[0];
    if (!file) return;

    showLoading();
    hideError();
    hideResults();

    const formData = new FormData();
    formData.append('sbom', file);

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Upload failed');
        }

        sbomData = result.data;
        processSBOM(sbomData);
        hideLoading();
        showResults();
    } catch (err) {
        hideLoading();
        showError(err.message);
    }
}

function processSBOM(data) {
    // Handle both CycloneDX 1.x formats
    allComponents = data.components || [];

    // Generate statistics
    generateStats(data);

    // Render dependency tree
    renderDependencyTree(data);

    // Render components table
    renderComponentsTable(allComponents);
}

function generateStats(data) {
    const metadata = data.metadata || {};
    const component = metadata.component || {};
    const components = data.components || [];

    const stats = {
        'SBOM Format': `CycloneDX ${data.bomFormat || 'Unknown'} v${data.specVersion || 'Unknown'}`,
        'Main Component': component.name ? `${component.name} ${component.version || ''}` : 'N/A',
        'Total Components': components.length,
        'Unique Licenses': getUniqueLicenses(components).size,
        'Component Types': getComponentTypes(components).size
    };

    statsDiv.innerHTML = Object.entries(stats)
        .map(([key, value]) => `
            <div class="stat-item">
                <div class="stat-label">${key}</div>
                <div class="stat-value">${value}</div>
            </div>
        `).join('');
}

function getUniqueLicenses(components) {
    const licenses = new Set();
    components.forEach(comp => {
        if (comp.licenses) {
            comp.licenses.forEach(lic => {
                if (lic.license) {
                    licenses.add(lic.license.id || lic.license.name || 'Unknown');
                }
            });
        }
    });
    return licenses;
}

function getComponentTypes(components) {
    const types = new Set();
    components.forEach(comp => {
        if (comp.type) types.add(comp.type);
    });
    return types;
}

function renderDependencyTree(data) {
    const dependencies = data.dependencies || [];
    const components = data.components || [];
    const mainComponent = data.metadata?.component;

    // Build dependency map
    const depMap = new Map();
    dependencies.forEach(dep => {
        depMap.set(dep.ref, dep.dependsOn || []);
    });

    // Build component map for quick lookup
    const componentMap = new Map();
    components.forEach(comp => {
        const ref = comp['bom-ref'] || `${comp.name}@${comp.version}`;
        componentMap.set(ref, comp);
    });

    // Add main component if exists
    if (mainComponent) {
        const mainRef = mainComponent['bom-ref'] || `${mainComponent.name}@${mainComponent.version}`;
        componentMap.set(mainRef, mainComponent);
    }

    let treeHTML = '';

    if (mainComponent) {
        const mainRef = mainComponent['bom-ref'] || `${mainComponent.name}@${mainComponent.version}`;
        treeHTML = renderTreeNode(mainRef, componentMap, depMap, new Set(), 0);
    } else if (dependencies.length > 0) {
        // Find root dependencies (those that are not depended upon by others)
        const allDeps = new Set();
        dependencies.forEach(dep => {
            (dep.dependsOn || []).forEach(d => allDeps.add(d));
        });

        const roots = dependencies
            .map(d => d.ref)
            .filter(ref => !allDeps.has(ref));

        if (roots.length === 0 && dependencies.length > 0) {
            // If no clear roots, use the first dependency
            roots.push(dependencies[0].ref);
        }

        treeHTML = roots.map(root =>
            renderTreeNode(root, componentMap, depMap, new Set(), 0)
        ).join('');
    } else {
        // No dependency information, show all components as a flat list
        treeHTML = components.map(comp => {
            const ref = comp['bom-ref'] || `${comp.name}@${comp.version}`;
            return renderComponentNode(comp, ref, 0);
        }).join('');
    }

    dependencyTree.innerHTML = treeHTML || '<p class="empty-state">No dependency information available</p>';
}

function renderTreeNode(ref, componentMap, depMap, visited, depth) {
    if (visited.has(ref)) {
        return `<div class="tree-node circular" style="padding-left: ${depth * 20}px">
            <span class="node-icon">↻</span>
            <span class="node-name">${ref} (circular reference)</span>
        </div>`;
    }

    visited.add(ref);
    const component = componentMap.get(ref);
    const deps = depMap.get(ref) || [];

    let html = renderComponentNode(component, ref, depth);

    if (deps.length > 0) {
        const childrenHTML = deps.map(depRef =>
            renderTreeNode(depRef, componentMap, depMap, new Set(visited), depth + 1)
        ).join('');

        html = html.replace('</div>', `
            <div class="tree-children">${childrenHTML}</div>
        </div>`);
    }

    return html;
}

function renderComponentNode(component, ref, depth) {
    if (!component) {
        return `<div class="tree-node" style="padding-left: ${depth * 20}px">
            <span class="node-icon">📦</span>
            <span class="node-name">${ref}</span>
            <span class="node-type">unknown</span>
        </div>`;
    }

    const name = component.name || 'Unknown';
    const version = component.version || '';
    const type = component.type || 'library';
    const license = getLicenseString(component);

    const hasChildren = depth === 0 ? 'has-children' : '';

    return `<div class="tree-node ${hasChildren}" style="padding-left: ${depth * 20}px}" data-name="${name.toLowerCase()}" data-ref="${ref}">
        <span class="node-toggle">▼</span>
        <span class="node-icon">${getTypeIcon(type)}</span>
        <span class="node-name">${name}</span>
        ${version ? `<span class="node-version">@${version}</span>` : ''}
        <span class="node-type">${type}</span>
        ${license ? `<span class="node-license">${license}</span>` : ''}
    </div>`;
}

function getLicenseString(component) {
    if (!component.licenses || component.licenses.length === 0) return '';
    const license = component.licenses[0].license;
    return license ? (license.id || license.name || '') : '';
}

function getTypeIcon(type) {
    const icons = {
        'application': '🚀',
        'framework': '🏗️',
        'library': '📚',
        'container': '📦',
        'operating-system': '💻',
        'device': '🔧',
        'firmware': '⚙️',
        'file': '📄'
    };
    return icons[type] || '📦';
}

function renderComponentsTable(components) {
    componentsTableBody.innerHTML = components.map(comp => `
        <tr>
            <td>${comp.name || 'Unknown'}</td>
            <td>${comp.version || 'N/A'}</td>
            <td>${comp.type || 'N/A'}</td>
            <td>${getLicenseString(comp) || 'N/A'}</td>
            <td>${comp.supplier?.name || 'N/A'}</td>
        </tr>
    `).join('');
}

function toggleAllNodes(expand) {
    const nodes = document.querySelectorAll('.tree-node.has-children');
    nodes.forEach(node => {
        if (expand) {
            node.classList.add('expanded');
        } else {
            node.classList.remove('expanded');
        }
    });
}

function handleSearch(e) {
    const searchTerm = e.target.value.toLowerCase();
    const nodes = document.querySelectorAll('.tree-node');

    nodes.forEach(node => {
        const name = node.getAttribute('data-name') || '';
        if (searchTerm === '' || name.includes(searchTerm)) {
            node.style.display = '';
        } else {
            node.style.display = 'none';
        }
    });
}

// Tree node expand/collapse
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('node-toggle')) {
        const node = e.target.closest('.tree-node');
        node.classList.toggle('expanded');
    }
});

function showLoading() {
    loading.classList.remove('hidden');
}

function hideLoading() {
    loading.classList.add('hidden');
}

function showError(message) {
    error.textContent = message;
    error.classList.remove('hidden');
}

function hideError() {
    error.classList.add('hidden');
}

function showResults() {
    results.classList.remove('hidden');
}

function hideResults() {
    results.classList.add('hidden');
}

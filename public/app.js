let sbomData = null;
let allComponents = [];
let sbomFormat = 'cyclonedx';

// DOM Elements
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const uploadBtn = document.getElementById('uploadBtn');
const loading = document.getElementById('loading');
const error = document.getElementById('error');
const results = document.getElementById('results');
const statsDiv = document.getElementById('stats');
const chartContainer = document.getElementById('chartContainer');
const sunburstChart = document.getElementById('sunburstChart');
const tooltip = document.getElementById('tooltip');
const breadcrumb = document.getElementById('breadcrumb');
const componentsTableBody = document.getElementById('componentsTableBody');
const resetZoomBtn = document.getElementById('resetZoom');
const searchBox = document.getElementById('searchBox');
const formatSelect = document.getElementById('formatSelect');

// Chart state
let currentRoot = null;
let chartData = null;

// Event Listeners
fileInput.addEventListener('change', handleFileSelect);
uploadBtn.addEventListener('click', handleUpload);
resetZoomBtn.addEventListener('click', resetChart);
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
    formData.append('format', formatSelect.value);

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
        sbomFormat = result.format;
        processSBOM(sbomData, sbomFormat);
        hideLoading();
        showResults();
    } catch (err) {
        hideLoading();
        showError(err.message);
    }
}

function convertSPDXToCommon(spdxData) {
    // Convert SPDX format to common format compatible with our visualizer
    const components = [];
    const dependencies = [];

    // Extract packages from SPDX
    const packages = spdxData.packages || [];

    packages.forEach(pkg => {
        // Convert SPDX package to component format
        const component = {
            'bom-ref': pkg.SPDXID || pkg.name,
            name: pkg.name,
            version: pkg.versionInfo || '',
            type: mapSPDXType(pkg.primaryPackagePurpose),
            description: pkg.description || '',
            supplier: pkg.supplier ? { name: pkg.supplier } : undefined,
            licenses: extractSPDXLicenses(pkg)
        };

        components.push(component);
    });

    // Extract relationships (dependencies)
    const relationships = spdxData.relationships || [];
    const depMap = new Map();

    relationships.forEach(rel => {
        if (rel.relationshipType === 'DEPENDS_ON') {
            // A DEPENDS_ON B means A depends on B
            const ref = rel.spdxElementId;
            if (!depMap.has(ref)) {
                depMap.set(ref, []);
            }
            depMap.get(ref).push(rel.relatedSpdxElement);
        } else if (rel.relationshipType === 'DEPENDENCY_OF') {
            // A DEPENDENCY_OF B means A is a dependency of B (i.e., B depends on A)
            // So we need to reverse it: B depends on A
            const ref = rel.relatedSpdxElement;
            if (!depMap.has(ref)) {
                depMap.set(ref, []);
            }
            depMap.get(ref).push(rel.spdxElementId);
        } else if (rel.relationshipType === 'CONTAINS') {
            // A CONTAINS B means A contains B (used for root packages in SPDX 2.3)
            // Treat this similarly to depends on for visualization purposes
            const ref = rel.spdxElementId;
            if (!depMap.has(ref)) {
                depMap.set(ref, []);
            }
            depMap.get(ref).push(rel.relatedSpdxElement);
        }
    });

    // Convert dependency map to array format
    depMap.forEach((deps, ref) => {
        dependencies.push({
            ref: ref,
            dependsOn: deps
        });
    });

    // Extract main component from document describes
    let mainComponent = null;
    const describes = relationships.filter(r => r.relationshipType === 'DESCRIBES');
    if (describes.length > 0) {
        const mainPkgId = describes[0].relatedSpdxElement;
        const mainPkg = packages.find(p => p.SPDXID === mainPkgId);
        if (mainPkg) {
            mainComponent = {
                'bom-ref': mainPkg.SPDXID,
                name: mainPkg.name,
                version: mainPkg.versionInfo || '',
                type: mapSPDXType(mainPkg.primaryPackagePurpose) || 'application'
            };
        }
    }

    return {
        spdxVersion: spdxData.spdxVersion,
        metadata: {
            component: mainComponent
        },
        components: components,
        dependencies: dependencies
    };
}

function mapSPDXType(purpose) {
    const typeMap = {
        'APPLICATION': 'application',
        'FRAMEWORK': 'framework',
        'LIBRARY': 'library',
        'CONTAINER': 'container',
        'OPERATING-SYSTEM': 'operating-system',
        'DEVICE': 'device',
        'FIRMWARE': 'firmware',
        'FILE': 'file'
    };
    return typeMap[purpose] || 'library';
}

function extractSPDXLicenses(pkg) {
    const licenses = [];

    if (pkg.licenseConcluded && pkg.licenseConcluded !== 'NOASSERTION' && pkg.licenseConcluded !== 'NONE') {
        licenses.push({
            license: {
                id: pkg.licenseConcluded
            }
        });
    } else if (pkg.licenseDeclared && pkg.licenseDeclared !== 'NOASSERTION' && pkg.licenseDeclared !== 'NONE') {
        licenses.push({
            license: {
                id: pkg.licenseDeclared
            }
        });
    }

    return licenses;
}

function processSBOM(data, format) {
    console.log('Processing SBOM, format:', format);
    console.log('Original data:', data);

    if (format === 'spdx') {
        // Convert SPDX to common format
        data = convertSPDXToCommon(data);
        console.log('Converted SPDX data:', data);
    }

    // Handle both CycloneDX and normalized SPDX formats
    allComponents = data.components || [];
    console.log('Components count:', allComponents.length);
    console.log('Dependencies count:', (data.dependencies || []).length);

    // Generate statistics
    generateStats(data, format);

    // Render dependency chart
    renderDependencyChart(data);

    // Render components table
    renderComponentsTable(allComponents);
}

function generateStats(data, format) {
    const metadata = data.metadata || {};
    const component = metadata.component || {};
    const components = data.components || [];

    let formatString;
    if (format === 'spdx') {
        formatString = `SPDX v${data.spdxVersion || '2.3'}`;
    } else {
        formatString = `CycloneDX ${data.bomFormat || 'Unknown'} v${data.specVersion || 'Unknown'}`;
    }

    const stats = {
        'SBOM Format': formatString,
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

function renderDependencyChart(data) {
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

    // Build hierarchical data structure
    let rootNode;
    if (mainComponent) {
        const mainRef = mainComponent['bom-ref'] || `${mainComponent.name}@${mainComponent.version}`;
        rootNode = buildHierarchy(mainRef, componentMap, depMap, new Set());
    } else if (dependencies.length > 0) {
        // Find root dependencies
        const allDeps = new Set();
        dependencies.forEach(dep => {
            (dep.dependsOn || []).forEach(d => allDeps.add(d));
        });

        const roots = dependencies
            .map(d => d.ref)
            .filter(ref => !allDeps.has(ref));

        if (roots.length === 0 && dependencies.length > 0) {
            roots.push(dependencies[0].ref);
        }

        rootNode = {
            name: 'Root',
            ref: 'root',
            children: roots.map(root => buildHierarchy(root, componentMap, depMap, new Set()))
        };
    } else {
        // No dependency information
        rootNode = {
            name: 'All Components',
            ref: 'root',
            children: components.map(comp => ({
                name: comp.name || 'Unknown',
                ref: comp['bom-ref'] || comp.name,
                component: comp,
                value: 1
            }))
        };
    }

    chartData = rootNode;
    currentRoot = rootNode;
    renderSunburst(rootNode);
}

function buildHierarchy(ref, componentMap, depMap, visited) {
    if (visited.has(ref)) {
        return {
            name: '↻ Circular',
            ref: ref,
            value: 1,
            circular: true
        };
    }

    visited.add(ref);
    const component = componentMap.get(ref);
    const deps = depMap.get(ref) || [];

    const node = {
        name: component?.name || ref,
        ref: ref,
        component: component,
        value: deps.length === 0 ? 1 : undefined
    };

    if (deps.length > 0) {
        node.children = deps.map(depRef =>
            buildHierarchy(depRef, componentMap, depMap, new Set(visited))
        );
    }

    return node;
}

function renderSunburst(data) {
    // Clear previous chart
    d3.select('#sunburstChart').selectAll('*').remove();

    const width = chartContainer.clientWidth;
    const height = chartContainer.clientHeight;
    const radius = Math.min(width, height) / 2 - 10;

    const svg = d3.select('#sunburstChart')
        .attr('viewBox', `${-width / 2} ${-height / 2} ${width} ${height}`)
        .style('width', '100%')
        .style('height', '100%')
        .style('font', '12px sans-serif');

    // Color scale
    const color = d3.scaleOrdinal(d3.quantize(d3.interpolateRainbow, data.children ? data.children.length + 1 : 1));

    // Compute hierarchy
    const hierarchy = d3.hierarchy(data)
        .sum(d => d.value)
        .sort((a, b) => b.value - a.value);

    const root = d3.partition()
        .size([2 * Math.PI, radius])
        (hierarchy);

    // Initialize current position for each node
    root.each(d => d.current = {
        x0: d.x0,
        x1: d.x1,
        y0: d.y0,
        y1: d.y1
    });

    // Arc generator
    const arc = d3.arc()
        .startAngle(d => d.x0)
        .endAngle(d => d.x1)
        .padAngle(d => Math.min((d.x1 - d.x0) / 2, 0.005))
        .padRadius(radius / 2)
        .innerRadius(d => d.y0)
        .outerRadius(d => d.y1 - 1);

    // Create arcs
    const path = svg.append('g')
        .selectAll('path')
        .data(root.descendants().filter(d => d.depth))
        .join('path')
        .attr('class', 'chart-arc')
        .attr('fill', d => {
            if (d.data.circular) return '#f59e0b';
            while (d.depth > 1) d = d.parent;
            return color(d.data.name);
        })
        .attr('fill-opacity', 1)
        .attr('pointer-events', 'auto')
        .attr('d', d => arc(d.current))
        .style('cursor', 'pointer')
        .on('click', clicked)
        .on('mouseover', function(event, d) {
            d3.select(this).attr('fill-opacity', 0.8);
            showTooltip(event, d);
        })
        .on('mouseout', function() {
            d3.select(this).attr('fill-opacity', 1);
            hideTooltip();
        });

    // Add labels
    const label = svg.append('g')
        .attr('pointer-events', 'none')
        .attr('text-anchor', 'middle')
        .style('user-select', 'none')
        .selectAll('text')
        .data(root.descendants().filter(d => d.depth && (d.y0 + d.y1) / 2 * (d.x1 - d.x0) > 10))
        .join('text')
        .attr('class', 'chart-arc-text')
        .attr('dy', '0.35em')
        .attr('fill-opacity', 1)
        .attr('transform', d => labelTransform(d.current))
        .text(d => d.data.name);

    // Center text
    const centerText = svg.append('text')
        .attr('class', 'chart-center-text')
        .attr('dy', '0.35em')
        .text(data.name);

    function clicked(event, p) {
        currentRoot = p;
        updateBreadcrumb(p);

        // Calculate new positions
        root.each(d => d.target = {
            x0: Math.max(0, Math.min(1, (d.x0 - p.x0) / (p.x1 - p.x0))) * 2 * Math.PI,
            x1: Math.max(0, Math.min(1, (d.x1 - p.x0) / (p.x1 - p.x0))) * 2 * Math.PI,
            y0: Math.max(0, d.y0 - p.depth),
            y1: Math.max(0, d.y1 - p.depth)
        });

        const t = svg.transition().duration(750);

        // Transition the arcs
        path.transition(t)
            .tween('data', d => {
                const i = d3.interpolate(d.current, d.target);
                return t => d.current = i(t);
            })
            .attrTween('d', d => () => arc(d.current))
            .attr('fill-opacity', d => arcVisible(d.target) ? 1 : 0)
            .attr('pointer-events', d => arcVisible(d.target) ? 'auto' : 'none');

        // Transition the labels
        label.transition(t)
            .attr('fill-opacity', d => labelVisible(d.target) ? 1 : 0)
            .attrTween('transform', d => () => labelTransform(d.current));

        // Update center text
        centerText.transition(t)
            .tween('text', function() {
                const i = d3.interpolate(this.textContent, p.data.name);
                return function(t) {
                    this.textContent = i(t);
                };
            });
    }

    function arcVisible(d) {
        return d.y1 > d.y0 && d.x1 > d.x0;
    }

    function labelVisible(d) {
        return d.y1 > d.y0 && d.x1 > d.x0 && (d.y1 - d.y0) > 0.1;
    }

    function labelTransform(d) {
        const x = (d.x0 + d.x1) / 2 * 180 / Math.PI;
        const y = (d.y0 + d.y1) / 2;
        return `rotate(${x - 90}) translate(${y},0) rotate(${x < 180 ? 0 : 180})`;
    }

    updateBreadcrumb(root);
}

function showTooltip(event, d) {
    const component = d.data.component;
    if (!component) return;

    let html = `<div class="tooltip-name">${component.name || 'Unknown'}</div>`;
    if (component.version) {
        html += `<div class="tooltip-version">v${component.version}</div>`;
    }
    html += `<div class="tooltip-info">`;
    if (component.type) {
        html += `<div class="tooltip-info-item"><span class="tooltip-label">Type:</span> ${component.type}</div>`;
    }
    if (component.licenses && component.licenses.length > 0) {
        const license = component.licenses[0].license;
        html += `<div class="tooltip-info-item"><span class="tooltip-label">License:</span> ${license.id || license.name || 'Unknown'}</div>`;
    }
    if (component.supplier) {
        html += `<div class="tooltip-info-item"><span class="tooltip-label">Supplier:</span> ${component.supplier.name}</div>`;
    }
    html += `</div>`;

    tooltip.innerHTML = html;
    tooltip.classList.add('visible');
    tooltip.style.left = (event.pageX + 10) + 'px';
    tooltip.style.top = (event.pageY + 10) + 'px';
}

function hideTooltip() {
    tooltip.classList.remove('visible');
}

function updateBreadcrumb(node) {
    const ancestors = node.ancestors().reverse();

    breadcrumb.innerHTML = ancestors.map((d, i) => {
        const isLast = i === ancestors.length - 1;
        return `<span class="breadcrumb-item" data-depth="${d.depth}">${d.data.name}</span>${isLast ? '' : '<span class="breadcrumb-separator">›</span>'}`;
    }).join('');

    // Add click handlers to breadcrumb items
    breadcrumb.querySelectorAll('.breadcrumb-item').forEach((item, i) => {
        item.addEventListener('click', () => {
            const ancestor = ancestors[i];
            if (ancestor !== currentRoot) {
                // Re-render to zoom to this ancestor
                zoomToNode(ancestor);
            }
        });
    });
}

function zoomToNode(node) {
    // This will be called when clicking breadcrumb items
    // We need to re-trigger the zoom effect
    const svg = d3.select('#sunburstChart');
    const paths = svg.selectAll('.chart-arc');

    // Find the path element that matches this node
    paths.each(function(d) {
        if (d === node) {
            // Simulate a click on this arc
            const event = new MouseEvent('click');
            this.dispatchEvent(event);
        }
    });
}

function resetChart() {
    if (chartData) {
        renderSunburst(chartData);
    }
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

function handleSearch(e) {
    const searchTerm = e.target.value.toLowerCase();
    const rows = componentsTableBody.querySelectorAll('tr');

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        if (searchTerm === '' || text.includes(searchTerm)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });

    // Highlight matching segments in the chart
    if (searchTerm === '') {
        d3.selectAll('.chart-arc').attr('opacity', 1);
    } else {
        d3.selectAll('.chart-arc').attr('opacity', d => {
            const name = d.data.name ? d.data.name.toLowerCase() : '';
            return name.includes(searchTerm) ? 1 : 0.2;
        });
    }
}


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

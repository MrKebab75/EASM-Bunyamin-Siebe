document.addEventListener('DOMContentLoaded', function() {
    // Initialize loading state
    const mainContent = document.getElementById('main-content');
    if (mainContent) {
        mainContent.innerHTML = '<div class="text-center p-5"><div class="loader"></div><p class="mt-3">Loading port scan data...</p></div>';
    }

    // Fetch port services data
    fetch('/api/port_services')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            processPortData(data);
        })
        .catch(error => {
            console.error('Error fetching port services data:', error);
            if (mainContent) {
                mainContent.innerHTML = `<div class="alert alert-danger">Error loading data: ${error.message}</div>`;
            }
        });
});

// Process and display port scan data
function processPortData(data) {
    // Count statistics
    const stats = calculateStats(data);
    updateStatCounters(stats);

    // Generate port service list for filter dropdown
    const portServices = generatePortServicesList(data);
    populatePortFilter(portServices);

    // Render data cards
    renderPortCards(data);

    // Set up event listeners for search and filters
    setupEventListeners(data);
}

function calculateStats(data) {
    let stats = {
        ips: data.length,
        domains: 0,
        openPorts: 0,
        vulnerabilities: 0,
        portCounts: {},
        vulnerabilitiesBySeverity: {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unknown': 0
        }
    };

    data.forEach(ip => {
        // Count domains
        if (ip.domains && ip.domains.length) {
            stats.domains += ip.domains.length;
        }

        // Count open ports and vulnerabilities
        if (ip.ports) {
            const ports = Object.keys(ip.ports);
            stats.openPorts += ports.length;

            ports.forEach(port => {
                // Count port occurrences
                if (!stats.portCounts[port]) {
                    stats.portCounts[port] = 0;
                }
                stats.portCounts[port]++;

                // Count vulnerabilities
                const portData = ip.ports[port];
                if (portData.vulnerabilities && portData.vulnerabilities.length) {
                    stats.vulnerabilities += portData.vulnerabilities.length;

                    // Count by severity
                    portData.vulnerabilities.forEach(vuln => {
                        const severity = vuln.severity ? vuln.severity.toLowerCase() : 'unknown';
                        if (stats.vulnerabilitiesBySeverity.hasOwnProperty(severity)) {
                            stats.vulnerabilitiesBySeverity[severity]++;
                        } else {
                            stats.vulnerabilitiesBySeverity.unknown++;
                        }
                    });
                }
            });
        }
    });

    return stats;
}

function updateStatCounters(stats) {
    document.getElementById('total-ips').textContent = stats.ips;
    document.getElementById('total-domains').textContent = stats.domains;
    document.getElementById('total-open-ports').textContent = stats.openPorts;
    document.getElementById('total-vulnerabilities').textContent = stats.vulnerabilities;
}

function generatePortServicesList(data) {
    const portServices = new Set();
    
    data.forEach(ip => {
        if (ip.ports) {
            Object.keys(ip.ports).forEach(port => {
                const service = ip.ports[port].service_name || 'unknown';
                portServices.add(`${port} (${service})`);
            });
        }
    });
    
    return Array.from(portServices).sort((a, b) => {
        const portA = parseInt(a.split(' ')[0]);
        const portB = parseInt(b.split(' ')[0]);
        return portA - portB;
    });
}

function populatePortFilter(portServices) {
    const portFilter = document.getElementById('port-filter');
    
    // Clear existing options but keep the "All Ports" option
    while (portFilter.options.length > 1) {
        portFilter.remove(1);
    }
    
    // Add new options
    portServices.forEach(portService => {
        const option = document.createElement('option');
        const port = portService.split(' ')[0];
        option.value = port;
        option.textContent = portService;
        portFilter.appendChild(option);
    });
}

function renderPortCards(data) {
    const mainContent = document.getElementById('main-content');
    if (!mainContent) return;

    // Sort data by vulnerability count (highest first)
    data.sort((a, b) => {
        const vulnCountA = getVulnerabilityCount(a);
        const vulnCountB = getVulnerabilityCount(b);
        return vulnCountB - vulnCountA;
    });

    let html = '';

    if (data.length === 0) {
        html = '<div class="alert alert-info">No port scan data available.</div>';
    } else {
        html = '<div class="row" id="ip-cards">';
        
        data.forEach(ip => {
            const vulnCount = getVulnerabilityCount(ip);
            const highestSeverity = getHighestSeverity(ip);
            const severityClass = getSeverityClass(highestSeverity);
            
            html += `
            <div class="col-lg-6 mb-4 ip-card-container" data-ip="${ip.ip}" data-domains="${ip.domains ? ip.domains.join(',') : ''}">
                <div class="card port-card ${severityClass}">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">IP: ${ip.ip}</h5>
                        <div>
                            <span class="badge bg-primary">${Object.keys(ip.ports || {}).length} Ports</span>
                            <span class="badge ${vulnCount > 0 ? 'bg-danger' : 'bg-success'}">${vulnCount} Vulnerabilities</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="domains mb-3">
                            <h6>Domains:</h6>
                            ${renderDomains(ip.domains)}
                        </div>
                        
                        <div class="ports">
                            <h6>Open Ports:</h6>
                            ${renderPorts(ip.ports)}
                        </div>
                    </div>
                </div>
            </div>`;
        });
        
        html += '</div>';
    }

    mainContent.innerHTML = html;

    // Add event listeners for expanding vulnerability details
    setupVulnerabilityExpanders();
}

function getVulnerabilityCount(ip) {
    let count = 0;
    if (ip.ports) {
        Object.values(ip.ports).forEach(port => {
            if (port.vulnerabilities) {
                count += port.vulnerabilities.length;
            }
        });
    }
    return count;
}

function getHighestSeverity(ip) {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    let highestIndex = severityOrder.length - 1; // Default to unknown

    if (ip.ports) {
        Object.values(ip.ports).forEach(port => {
            if (port.vulnerabilities) {
                port.vulnerabilities.forEach(vuln => {
                    const severity = vuln.severity ? vuln.severity.toLowerCase() : 'unknown';
                    const severityIndex = severityOrder.indexOf(severity);
                    if (severityIndex !== -1 && severityIndex < highestIndex) {
                        highestIndex = severityIndex;
                    }
                });
            }
        });
    }

    return severityOrder[highestIndex];
}

function getSeverityClass(severity) {
    switch(severity.toLowerCase()) {
        case 'critical': return 'critical';
        case 'high': return 'high';
        case 'medium': return 'medium';
        case 'low': return 'low';
        case 'info': return 'info';
        default: return 'unknown';
    }
}

function renderDomains(domains) {
    if (!domains || domains.length === 0) {
        return '<p class="text-muted">No domains associated</p>';
    }
    
    return `<div class="domains-list">
        ${domains.map(domain => `<div class="badge bg-secondary me-1 mb-1">${domain}</div>`).join('')}
    </div>`;
}

function renderPorts(ports) {
    if (!ports || Object.keys(ports).length === 0) {
        return '<p class="text-muted">No open ports detected</p>';
    }
    
    let html = '<div class="accordion" id="portsAccordion">';
    
    Object.keys(ports).forEach((port, index) => {
        const portData = ports[port];
        const portId = `port-${port}-${index}`;
        const hasVulnerabilities = portData.vulnerabilities && portData.vulnerabilities.length > 0;
        const vulnCount = hasVulnerabilities ? portData.vulnerabilities.length : 0;
        const highestSeverity = getPortHighestSeverity(portData);
        
        html += `
        <div class="accordion-item mb-2">
            <h2 class="accordion-header" id="heading-${portId}">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${portId}" aria-expanded="false" aria-controls="collapse-${portId}">
                    <div class="d-flex w-100 justify-content-between align-items-center">
                        <span>Port ${port} - ${portData.service_name || 'Unknown'} ${portData.service_version ? '(' + portData.service_version + ')' : ''}</span>
                        ${vulnCount > 0 ? `<span class="badge badge-${getSeverityClass(highestSeverity)} ms-2">${vulnCount} Vulnerabilities</span>` : ''}
                    </div>
                </button>
            </h2>
            <div id="collapse-${portId}" class="accordion-collapse collapse" aria-labelledby="heading-${portId}" data-bs-parent="#portsAccordion">
                <div class="accordion-body">
                    <div class="mb-2">
                        <strong>Service:</strong> ${portData.service || 'Unknown'}
                    </div>
                    <div class="mb-3">
                        <strong>State:</strong> ${portData.state || 'Unknown'}
                    </div>
                    
                    ${renderVulnerabilities(portData.vulnerabilities)}
                    
                    ${renderTechnologies(portData.technologies)}
                </div>
            </div>
        </div>`;
    });
    
    html += '</div>';
    return html;
}

function getPortHighestSeverity(portData) {
    if (!portData.vulnerabilities || portData.vulnerabilities.length === 0) {
        return 'unknown';
    }
    
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    let highestIndex = severityOrder.length - 1;
    
    portData.vulnerabilities.forEach(vuln => {
        const severity = vuln.severity ? vuln.severity.toLowerCase() : 'unknown';
        const severityIndex = severityOrder.indexOf(severity);
        if (severityIndex !== -1 && severityIndex < highestIndex) {
            highestIndex = severityIndex;
        }
    });
    
    return severityOrder[highestIndex];
}

function renderVulnerabilities(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
        return '<div class="alert alert-success mb-3">No vulnerabilities detected</div>';
    }
    
    let html = `
    <div class="vulnerabilities mb-3">
        <h6 class="mb-3">Vulnerabilities (${vulnerabilities.length}):</h6>
        <div class="vulnerabilities-list">`;
    
    vulnerabilities.forEach((vuln, index) => {
        const vulnId = `vuln-${index}-${Date.now()}`;
        const severity = vuln.severity ? vuln.severity.toLowerCase() : 'unknown';
        const severityClass = getSeverityClass(severity);
        
        html += `
        <div class="card mb-2 vulnerability-card">
            <div class="card-header bg-light d-flex justify-content-between align-items-center">
                <h6 class="mb-0">${vuln.id || 'Unknown CVE'}</h6>
                <span class="badge badge-${severityClass}">${vuln.severity || 'Unknown'}</span>
            </div>
            <div class="card-body">
                ${vuln.cvss ? `<div class="mb-2"><strong>CVSS:</strong> ${vuln.cvss}</div>` : ''}
                <div class="mb-2">
                    <strong>Details:</strong>
                    <button class="btn btn-sm btn-outline-secondary ms-2 toggle-details" data-target="${vulnId}">Show Details</button>
                </div>
                <div id="${vulnId}" class="vulnerability-details collapse">
                    <pre class="bg-light p-3 mt-2" style="white-space: pre-wrap;">${vuln.details || 'No details available'}</pre>
                </div>
                ${vuln.url ? `<div class="mt-2"><a href="${vuln.url}" target="_blank" class="btn btn-sm btn-outline-primary">View Reference <i class="bi bi-box-arrow-up-right ms-1"></i></a></div>` : ''}
            </div>
        </div>`;
    });
    
    html += '</div></div>';
    return html;
}

function renderTechnologies(technologies) {
    if (!technologies || technologies.length === 0) {
        return '';
    }
    
    let html = `
    <div class="technologies">
        <h6 class="mb-2">Associated Technologies:</h6>
        <div class="techs-container">`;
    
    technologies.forEach(tech => {
        html += `<span class="badge tech-badge">${tech.name} ${tech.version !== 'Unknown' ? tech.version : ''}</span>`;
    });
    
    html += '</div></div>';
    return html;
}

function setupVulnerabilityExpanders() {
    document.querySelectorAll('.toggle-details').forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const detailsElement = document.getElementById(targetId);
            
            if (detailsElement.classList.contains('show')) {
                detailsElement.classList.remove('show');
                this.textContent = 'Show Details';
            } else {
                detailsElement.classList.add('show');
                this.textContent = 'Hide Details';
            }
        });
    });
}

function setupEventListeners(data) {
    // Search functionality
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            filterCards();
        });
    }
    
    // Port filter
    const portFilter = document.getElementById('port-filter');
    if (portFilter) {
        portFilter.addEventListener('change', function() {
            filterCards();
        });
    }
    
    // Vulnerability filter
    const vulnFilter = document.getElementById('vulnerability-filter');
    if (vulnFilter) {
        vulnFilter.addEventListener('change', function() {
            filterCards();
        });
    }
    
    // Reset filters
    const resetButton = document.getElementById('reset-filters');
    if (resetButton) {
        resetButton.addEventListener('click', function() {
            if (searchInput) searchInput.value = '';
            if (portFilter) portFilter.value = 'all';
            if (vulnFilter) vulnFilter.value = 'all';
            filterCards();
        });
    }
}

function filterCards() {
    const searchValue = document.getElementById('search-input').value.toLowerCase();
    const portValue = document.getElementById('port-filter').value;
    const vulnValue = document.getElementById('vulnerability-filter').value;
    
    const cards = document.querySelectorAll('.ip-card-container');
    
    cards.forEach(card => {
        const ip = card.getAttribute('data-ip').toLowerCase();
        const domains = (card.getAttribute('data-domains') || '').toLowerCase();
        
        // Check if card matches the search query
        const matchesSearch = searchValue === '' || 
                             ip.includes(searchValue) || 
                             domains.includes(searchValue);
        
        // Check if card has the selected port
        let matchesPort = portValue === 'all';
        if (!matchesPort) {
            const portElements = card.querySelectorAll('.accordion-item');
            portElements.forEach(portElement => {
                const headerText = portElement.querySelector('.accordion-button').textContent;
                if (headerText.includes(`Port ${portValue}`)) {
                    matchesPort = true;
                }
            });
        }
        
        // Check if card matches the vulnerability filter
        let matchesVuln = vulnValue === 'all';
        if (!matchesVuln) {
            const vulnElements = card.querySelectorAll('.vulnerability-card');
            
            if (vulnValue === 'any') {
                matchesVuln = vulnElements.length > 0;
            } else if (vulnValue === 'none') {
                matchesVuln = vulnElements.length === 0;
            } else {
                vulnElements.forEach(vulnElement => {
                    const severityBadge = vulnElement.querySelector('.badge');
                    if (severityBadge && severityBadge.textContent.toLowerCase() === vulnValue) {
                        matchesVuln = true;
                    }
                });
            }
        }
        
        // Show or hide the card based on the filters
        if (matchesSearch && matchesPort && matchesVuln) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
} 
// Global variables
let allDomains = [];
let domainsTable;
let statusChart;
let registrarsChart;
let expirationChart;

// DOM Elements
const domainSearch = document.getElementById('domain-search');
const statusFilter = document.getElementById('status-filter');
const registrarFilter = document.getElementById('registrar-filter');
const resetFiltersBtn = document.getElementById('reset-filters');
const domainsTableBody = document.getElementById('domains-table-body');
const domainsCards = document.getElementById('domains-cards');
const tableLoader = document.getElementById('table-loader');
const cardsLoader = document.getElementById('cards-loader');
const tableContainer = document.getElementById('table-container');
const totalDomainsEl = document.getElementById('total-domains');
const validDomainsEl = document.getElementById('valid-domains');
const expiringDomainsEl = document.getElementById('expiring-domains');
const expiredDomainsEl = document.getElementById('expired-domains');

// Colors for charts
const chartColors = [
    '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
    '#5a5c69', '#858796', '#6f42c1', '#20c9a6', '#fd7e14'
];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    
    // Set up event listeners
    domainSearch.addEventListener('input', filterDomains);
    statusFilter.addEventListener('change', filterDomains);
    registrarFilter.addEventListener('change', filterDomains);
    resetFiltersBtn.addEventListener('click', resetFilters);
    
    // Set up tab change event to redraw charts
    document.querySelectorAll('button[data-bs-toggle="pill"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(e) {
            if (e.target.id === 'pills-chart-tab') {
                if (statusChart) statusChart.update();
                if (registrarsChart) registrarsChart.update();
                if (expirationChart) expirationChart.update();
            }
        });
    });
});

// Load data from JSON files
async function loadData() {
    try {
        // Fetch domains data
        const response = await fetch('/api/domain_lease');
        allDomains = await response.json();
        
        console.log('Domain leases loaded:', allDomains.length);
        
        // Process domains (categorize by expiry)
        processDomains();
        
        // Initialize the UI
        initializeUI();
        
        // Hide loaders and show content
        tableLoader.style.display = 'none';
        cardsLoader.style.display = 'none';
        tableContainer.style.display = 'block';
        domainsCards.style.display = 'flex';
        
        // Initialize DataTable
        domainsTable = $('#domains-table').DataTable({
            paging: true,
            searching: false, // We'll use our own search
            ordering: true,
            order: [[4, 'asc']], // Sort by days left
            info: true,
            pageLength: 10,
            lengthMenu: [10, 25, 50, 100]
        });
        
        // Initialize charts
        initializeCharts();
        
    } catch (error) {
        console.error('Error loading data:', error);
        tableLoader.innerHTML = 'Error loading data. Please try again.';
        cardsLoader.innerHTML = 'Error loading data. Please try again.';
    }
}

// Process domains for display
function processDomains() {
    // Add display status category (valid, expiring, expired, unknown)
    allDomains.forEach(domain => {
        if (domain.status === 'unknown' || !domain.days_remaining) {
            domain.displayStatus = 'unknown';
        } else if (domain.days_remaining <= 0) {
            domain.displayStatus = 'expired';
        } else if (domain.days_remaining <= 90) {
            domain.displayStatus = 'expiring';
        } else {
            domain.displayStatus = 'valid';
        }
    });
}

// Initialize the UI with domain data
function initializeUI() {
    // Update statistics
    updateStats();
    
    // Populate the registrar filter dropdown
    populateRegistrarFilter();
    
    // Populate the table and cards
    populateTable();
    populateCards();
}

// Update statistics in the UI
function updateStats() {
    const validCount = allDomains.filter(domain => domain.displayStatus === 'valid').length;
    const expiringCount = allDomains.filter(domain => domain.displayStatus === 'expiring').length;
    const expiredCount = allDomains.filter(domain => 
        domain.displayStatus === 'expired' || domain.displayStatus === 'unknown'
    ).length;
    
    totalDomainsEl.textContent = allDomains.length;
    validDomainsEl.textContent = validCount;
    expiringDomainsEl.textContent = expiringCount;
    expiredDomainsEl.textContent = expiredCount;
}

// Populate the registrar filter dropdown
function populateRegistrarFilter() {
    // Get unique registrars (excluding null/undefined values)
    const registrars = [...new Set(
        allDomains
            .filter(domain => domain.registrar)
            .map(domain => domain.registrar)
    )].sort();
    
    // Add options to the dropdown
    registrars.forEach(registrar => {
        const option = document.createElement('option');
        option.value = registrar;
        option.textContent = registrar;
        registrarFilter.appendChild(option);
    });
}

// Populate the table with domain data
function populateTable() {
    // Clear existing table data
    domainsTableBody.innerHTML = '';
    
    // Generate table rows
    allDomains.forEach(domain => {
        const row = document.createElement('tr');
        
        // Domain name
        const domainCell = document.createElement('td');
        domainCell.textContent = domain.domain;
        row.appendChild(domainCell);
        
        // Status
        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.classList.add('badge', 'rounded-pill');
        
        if (domain.displayStatus === 'valid') {
            statusBadge.classList.add('bg-success');
            statusBadge.textContent = 'Valid';
        } else if (domain.displayStatus === 'expiring') {
            statusBadge.classList.add('bg-warning', 'text-dark');
            statusBadge.textContent = 'Expiring Soon';
        } else if (domain.displayStatus === 'expired') {
            statusBadge.classList.add('bg-danger');
            statusBadge.textContent = 'Expired';
        } else {
            statusBadge.classList.add('bg-secondary');
            statusBadge.textContent = 'Unknown';
        }
        statusCell.appendChild(statusBadge);
        row.appendChild(statusCell);
        
        // Registrar
        const registrarCell = document.createElement('td');
        registrarCell.textContent = domain.registrar || 'N/A';
        row.appendChild(registrarCell);
        
        // Expiration date
        const expiresCell = document.createElement('td');
        expiresCell.textContent = domain.expiration_date ? formatDate(domain.expiration_date) : 'N/A';
        row.appendChild(expiresCell);
        
        // Days remaining
        const daysCell = document.createElement('td');
        if (domain.displayStatus === 'unknown') {
            daysCell.innerHTML = `<span class="text-secondary">Unknown</span>`;
        } else if (domain.displayStatus === 'expired') {
            daysCell.innerHTML = `<span class="text-danger">Expired</span>`;
        } else {
            daysCell.textContent = domain.days_remaining;
            
            // Add progress bar for expiration
            const progressDiv = document.createElement('div');
            progressDiv.className = 'progress';
            
            let progressClass = 'progress-bar-safe';
            let progressWidth = 100;
            
            if (domain.days_remaining <= 30) {
                progressClass = 'progress-bar-danger';
                progressWidth = domain.days_remaining / 30 * 100;
            } else if (domain.days_remaining <= 90) {
                progressClass = 'progress-bar-expiring';
                progressWidth = domain.days_remaining / 90 * 100;
            } else {
                progressWidth = Math.min(100, domain.days_remaining / 365 * 100);
            }
            
            progressDiv.innerHTML = `<div class="progress-bar ${progressClass}" role="progressbar" style="width: ${progressWidth}%" aria-valuenow="${progressWidth}" aria-valuemin="0" aria-valuemax="100"></div>`;
            daysCell.appendChild(progressDiv);
        }
        row.appendChild(daysCell);
        
        // Actions
        const actionsCell = document.createElement('td');
        const viewBtn = document.createElement('button');
        viewBtn.classList.add('btn', 'btn-sm', 'btn-primary');
        viewBtn.innerHTML = '<i class="bi bi-eye"></i> Details';
        viewBtn.setAttribute('data-domain', domain.domain);
        viewBtn.addEventListener('click', function() {
            showDomainDetails(domain);
        });
        actionsCell.appendChild(viewBtn);
        row.appendChild(actionsCell);
        
        domainsTableBody.appendChild(row);
    });
}

// Populate cards view with domain data
function populateCards() {
    // Clear existing cards
    domainsCards.innerHTML = '';
    
    // Generate cards for each domain
    allDomains.forEach(domain => {
        const card = document.createElement('div');
        card.classList.add('col-md-4', 'mb-4');
        
        let statusClass = 'border-success';
        let statusText = 'Valid';
        let statusBadgeClass = 'bg-success';
        
        if (domain.displayStatus === 'expiring') {
            statusClass = 'border-warning';
            statusText = 'Expiring Soon';
            statusBadgeClass = 'bg-warning text-dark';
        } else if (domain.displayStatus === 'expired') {
            statusClass = 'border-danger';
            statusText = 'Expired';
            statusBadgeClass = 'bg-danger';
        } else if (domain.displayStatus === 'unknown') {
            statusClass = 'border-secondary';
            statusText = 'Unknown';
            statusBadgeClass = 'bg-secondary';
        }
        
        let expirationInfo = '';
        if (domain.displayStatus === 'unknown') {
            expirationInfo = `<p class="text-secondary">Status unknown</p>`;
        } else if (domain.displayStatus === 'expired') {
            expirationInfo = `<p class="text-danger">Expired</p>`;
        } else {
            const progressClass = domain.days_remaining <= 30 ? 'progress-bar-danger' : 
                                 (domain.days_remaining <= 90 ? 'progress-bar-expiring' : 'progress-bar-safe');
            const progressWidth = domain.days_remaining <= 30 ? (domain.days_remaining / 30 * 100) :
                                 (domain.days_remaining <= 90 ? (domain.days_remaining / 90 * 100) :
                                 Math.min(100, domain.days_remaining / 365 * 100));
                                 
            expirationInfo = `
                <p>Days remaining: ${domain.days_remaining}</p>
                <div class="progress">
                    <div class="progress-bar ${progressClass}" 
                         role="progressbar" 
                         style="width: ${progressWidth}%" 
                         aria-valuenow="${progressWidth}" 
                         aria-valuemin="0" 
                         aria-valuemax="100"></div>
                </div>
            `;
        }
        
        card.innerHTML = `
            <div class="card h-100 ${statusClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${domain.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p><strong>Registrar:</strong> ${domain.registrar || 'N/A'}</p>
                    <p><strong>Expires:</strong> ${domain.expiration_date ? formatDate(domain.expiration_date) : 'N/A'}</p>
                    ${expirationInfo}
                    <button class="btn btn-primary view-details mt-3" data-domain="${domain.domain}">
                        <i class="bi bi-eye"></i> View Details
                    </button>
                </div>
            </div>
        `;
        
        domainsCards.appendChild(card);
        
        // Add event listener to the button
        const detailsBtn = card.querySelector('.view-details');
        detailsBtn.addEventListener('click', function() {
            showDomainDetails(domain);
        });
    });
}

// Initialize charts
function initializeCharts() {
    initializeStatusChart();
    initializeRegistrarsChart();
    initializeExpirationChart();
}

// Initialize status distribution chart
function initializeStatusChart() {
    const validCount = allDomains.filter(domain => domain.displayStatus === 'valid').length;
    const expiringCount = allDomains.filter(domain => domain.displayStatus === 'expiring').length;
    const expiredCount = allDomains.filter(domain => domain.displayStatus === 'expired').length;
    const unknownCount = allDomains.filter(domain => domain.displayStatus === 'unknown').length;
    
    const ctx = document.getElementById('status-chart').getContext('2d');
    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Valid', 'Expiring Soon', 'Expired', 'Unknown'],
            datasets: [{
                data: [validCount, expiringCount, expiredCount, unknownCount],
                backgroundColor: ['#28a745', '#ffc107', '#dc3545', '#6c757d'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((acc, val) => acc + val, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Initialize registrars distribution chart
function initializeRegistrarsChart() {
    // Count domains by registrar
    const registrarCounts = {};
    allDomains.forEach(domain => {
        const registrar = domain.registrar || 'Unknown';
        if (!registrarCounts[registrar]) {
            registrarCounts[registrar] = 0;
        }
        registrarCounts[registrar]++;
    });
    
    // Sort registrars by count (descending)
    const sortedRegistrars = Object.entries(registrarCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10); // Show top 10 registrars
    
    const ctx = document.getElementById('registrars-chart').getContext('2d');
    registrarsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedRegistrars.map(entry => entry[0]),
            datasets: [{
                label: 'Number of Domains',
                data: sortedRegistrars.map(entry => entry[1]),
                backgroundColor: chartColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

// Initialize expiration timeline chart
function initializeExpirationChart() {
    // Group domains by expiration month
    const expirationMonths = {};
    
    // Only include domains with valid expiration dates
    const validDomains = allDomains.filter(domain => 
        domain.expiration_date && 
        domain.displayStatus !== 'expired' && 
        domain.displayStatus !== 'unknown'
    );
    
    validDomains.forEach(domain => {
        const date = new Date(domain.expiration_date);
        const monthYear = `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, '0')}`;
        
        if (!expirationMonths[monthYear]) {
            expirationMonths[monthYear] = 0;
        }
        expirationMonths[monthYear]++;
    });
    
    // Sort months chronologically
    const sortedMonths = Object.keys(expirationMonths).sort();
    
    const ctx = document.getElementById('expiration-chart').getContext('2d');
    expirationChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: sortedMonths.map(month => formatMonth(month)),
            datasets: [{
                label: 'Domains Expiring',
                data: sortedMonths.map(month => expirationMonths[month]),
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 2,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                tooltip: {
                    callbacks: {
                        title: function(tooltipItems) {
                            return formatMonth(tooltipItems[0].label);
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

// Show domain details in modal
function showDomainDetails(domain) {
    const modalTitle = document.getElementById('domainDetailsModalLabel');
    const modalBody = document.getElementById('modal-body-content');
    
    // Set modal title
    modalTitle.textContent = `Domain Lease Details: ${domain.domain}`;
    
    // Clear previous content
    modalBody.innerHTML = '';
    
    // Create status badge
    const statusBadge = document.createElement('div');
    statusBadge.classList.add('mb-3');
    
    let badgeClass = 'bg-success';
    let statusText = 'Valid';
    
    if (domain.displayStatus === 'expiring') {
        badgeClass = 'bg-warning text-dark';
        statusText = 'Expiring Soon';
    } else if (domain.displayStatus === 'expired') {
        badgeClass = 'bg-danger';
        statusText = 'Expired';
    } else if (domain.displayStatus === 'unknown') {
        badgeClass = 'bg-secondary';
        statusText = 'Unknown';
    }
    
    statusBadge.innerHTML = `
        <span class="badge ${badgeClass} rounded-pill">
            ${statusText}
        </span>
    `;
    modalBody.appendChild(statusBadge);
    
    // Add domain info
    const infoDiv = document.createElement('div');
    infoDiv.classList.add('mb-3');
    
    // Expiration indicator
    let expirationIndicator = '';
    if (domain.displayStatus !== 'unknown' && domain.displayStatus !== 'expired') {
        let progressClass = 'progress-bar-safe';
        let statusClass = 'status-valid';
        let statusText = 'Valid';
        
        if (domain.days_remaining <= 30) {
            progressClass = 'progress-bar-danger';
            statusClass = 'status-expired';
            statusText = 'Critical - Expires Very Soon';
        } else if (domain.days_remaining <= 90) {
            progressClass = 'progress-bar-expiring';
            statusClass = 'status-expiring';
            statusText = 'Warning - Expires Soon';
        }
        
        expirationIndicator = `
            <div class="expiration-indicator">
                <div class="progress flex-grow-1" style="width: 50%;">
                    <div class="progress-bar ${progressClass}" role="progressbar" 
                         style="width: ${Math.min(100, domain.days_remaining / 365 * 100)}%" 
                         aria-valuenow="${Math.min(100, domain.days_remaining / 365 * 100)}" 
                         aria-valuemin="0" 
                         aria-valuemax="100"></div>
                </div>
                <div class="expiration-text ${statusClass}">
                    ${statusText} (${domain.days_remaining} days remaining)
                </div>
            </div>
        `;
    }
    
    // Build the table with domain details
    let tableHTML = `
        <table class="table table-bordered">
            <tr>
                <th>Domain</th>
                <td>${domain.domain}</td>
            </tr>
            <tr>
                <th>Status</th>
                <td>${domain.status}</td>
            </tr>
            <tr>
                <th>Registrar</th>
                <td>${domain.registrar || 'N/A'}</td>
            </tr>
            <tr>
                <th>WHOIS Server</th>
                <td>${domain.whois_server || 'N/A'}</td>
            </tr>
            <tr>
                <th>Creation Date</th>
                <td>${domain.creation_date ? formatDate(domain.creation_date) : 'N/A'}</td>
            </tr>
            <tr>
                <th>Expiration Date</th>
                <td>${domain.expiration_date ? formatDate(domain.expiration_date) : 'N/A'}</td>
            </tr>
            <tr>
                <th>Last Updated</th>
                <td>${domain.last_updated ? formatDate(domain.last_updated) : 'N/A'}</td>
            </tr>
            <tr>
                <th>Days Remaining</th>
                <td>
                    ${domain.displayStatus === 'unknown' ? 
                      '<span class="text-secondary">Unknown</span>' : 
                      (domain.displayStatus === 'expired' ? 
                       '<span class="text-danger">Expired</span>' : 
                       domain.days_remaining)}
                    ${domain.displayStatus !== 'unknown' && domain.displayStatus !== 'expired' ? expirationIndicator : ''}
                </td>
            </tr>
            <tr>
                <th>Registrant</th>
                <td>${domain.registrant || 'N/A'}</td>
            </tr>
        </table>
    `;
    
    infoDiv.innerHTML = tableHTML;
    modalBody.appendChild(infoDiv);
    
    // Add name servers if available
    if (domain.name_servers && domain.name_servers.length > 0) {
        const nameServersDiv = document.createElement('div');
        
        let nameServersList = '';
        domain.name_servers.forEach(server => {
            nameServersList += `<li>${server}</li>`;
        });
        
        nameServersDiv.innerHTML = `
            <h5 class="mt-3 mb-2">Name Servers</h5>
            <ul>
                ${nameServersList}
            </ul>
        `;
        modalBody.appendChild(nameServersDiv);
    }
    
    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('domainDetailsModal'));
    modal.show();
}

// Filter domains based on search and filter settings
function filterDomains() {
    const searchTerm = domainSearch.value.toLowerCase();
    const statusValue = statusFilter.value;
    const registrarValue = registrarFilter.value;
    
    // Filter the domains
    const filteredDomains = allDomains.filter(domain => {
        // Search filter
        const matchesSearch = domain.domain.toLowerCase().includes(searchTerm);
        
        // Status filter
        let matchesStatus = true;
        if (statusValue === 'valid') {
            matchesStatus = domain.displayStatus === 'valid';
        } else if (statusValue === 'expiring') {
            matchesStatus = domain.displayStatus === 'expiring';
        } else if (statusValue === 'expired') {
            matchesStatus = domain.displayStatus === 'expired' || domain.displayStatus === 'unknown';
        }
        
        // Registrar filter
        let matchesRegistrar = true;
        if (registrarValue !== 'all') {
            matchesRegistrar = domain.registrar === registrarValue;
        }
        
        return matchesSearch && matchesStatus && matchesRegistrar;
    });
    
    // Update the UI with filtered domains
    updateUI(filteredDomains);
}

// Update the UI with filtered domains
function updateUI(filteredDomains) {
    // Clear existing table rows
    domainsTable.clear();
    
    // Add filtered domains to the table
    filteredDomains.forEach(domain => {
        let statusBadge = '';
        if (domain.displayStatus === 'valid') {
            statusBadge = '<span class="badge bg-success rounded-pill">Valid</span>';
        } else if (domain.displayStatus === 'expiring') {
            statusBadge = '<span class="badge bg-warning text-dark rounded-pill">Expiring Soon</span>';
        } else if (domain.displayStatus === 'expired') {
            statusBadge = '<span class="badge bg-danger rounded-pill">Expired</span>';
        } else {
            statusBadge = '<span class="badge bg-secondary rounded-pill">Unknown</span>';
        }
        
        let daysCell = '';
        if (domain.displayStatus === 'unknown') {
            daysCell = '<span class="text-secondary">Unknown</span>';
        } else if (domain.displayStatus === 'expired') {
            daysCell = '<span class="text-danger">Expired</span>';
        } else {
            const progressClass = domain.days_remaining <= 30 ? 'progress-bar-danger' : 
                                 (domain.days_remaining <= 90 ? 'progress-bar-expiring' : 'progress-bar-safe');
            const progressWidth = Math.min(100, domain.days_remaining <= 30 ? 
                                         (domain.days_remaining / 30 * 100) : 
                                         (domain.days_remaining <= 90 ? 
                                          (domain.days_remaining / 90 * 100) : 
                                          (domain.days_remaining / 365 * 100)));
            
            daysCell = `${domain.days_remaining}
                <div class="progress">
                    <div class="progress-bar ${progressClass}" role="progressbar" style="width: ${progressWidth}%" 
                        aria-valuenow="${progressWidth}" aria-valuemin="0" aria-valuemax="100"></div>
                </div>`;
        }
        
        domainsTable.row.add([
            domain.domain,
            statusBadge,
            domain.registrar || 'N/A',
            domain.expiration_date ? formatDate(domain.expiration_date) : 'N/A',
            daysCell,
            `<button class="btn btn-sm btn-primary view-details" data-domain="${domain.domain}"><i class="bi bi-eye"></i> Details</button>`
        ]).draw(false);
    });
    
    // Update cards view
    updateCardsView(filteredDomains);
    
    // Reattach event listeners to the table buttons
    document.querySelectorAll('.view-details').forEach(button => {
        const domainName = button.getAttribute('data-domain');
        const domain = allDomains.find(d => d.domain === domainName);
        if (domain) {
            button.addEventListener('click', function() {
                showDomainDetails(domain);
            });
        }
    });
}

// Update cards view with filtered domains
function updateCardsView(filteredDomains) {
    // Clear existing cards
    domainsCards.innerHTML = '';
    
    // Generate cards for filtered domains
    filteredDomains.forEach(domain => {
        const card = document.createElement('div');
        card.classList.add('col-md-4', 'mb-4');
        
        let statusClass = 'border-success';
        let statusText = 'Valid';
        let statusBadgeClass = 'bg-success';
        
        if (domain.displayStatus === 'expiring') {
            statusClass = 'border-warning';
            statusText = 'Expiring Soon';
            statusBadgeClass = 'bg-warning text-dark';
        } else if (domain.displayStatus === 'expired') {
            statusClass = 'border-danger';
            statusText = 'Expired';
            statusBadgeClass = 'bg-danger';
        } else if (domain.displayStatus === 'unknown') {
            statusClass = 'border-secondary';
            statusText = 'Unknown';
            statusBadgeClass = 'bg-secondary';
        }
        
        let expirationInfo = '';
        if (domain.displayStatus === 'unknown') {
            expirationInfo = `<p class="text-secondary">Status unknown</p>`;
        } else if (domain.displayStatus === 'expired') {
            expirationInfo = `<p class="text-danger">Expired</p>`;
        } else {
            const progressClass = domain.days_remaining <= 30 ? 'progress-bar-danger' : 
                                 (domain.days_remaining <= 90 ? 'progress-bar-expiring' : 'progress-bar-safe');
            const progressWidth = domain.days_remaining <= 30 ? (domain.days_remaining / 30 * 100) :
                                 (domain.days_remaining <= 90 ? (domain.days_remaining / 90 * 100) :
                                 Math.min(100, domain.days_remaining / 365 * 100));
                                 
            expirationInfo = `
                <p>Days remaining: ${domain.days_remaining}</p>
                <div class="progress">
                    <div class="progress-bar ${progressClass}" 
                         role="progressbar" 
                         style="width: ${progressWidth}%" 
                         aria-valuenow="${progressWidth}" 
                         aria-valuemin="0" 
                         aria-valuemax="100"></div>
                </div>
            `;
        }
        
        card.innerHTML = `
            <div class="card h-100 ${statusClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${domain.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p><strong>Registrar:</strong> ${domain.registrar || 'N/A'}</p>
                    <p><strong>Expires:</strong> ${domain.expiration_date ? formatDate(domain.expiration_date) : 'N/A'}</p>
                    ${expirationInfo}
                    <button class="btn btn-primary view-details mt-3" data-domain="${domain.domain}">
                        <i class="bi bi-eye"></i> View Details
                    </button>
                </div>
            </div>
        `;
        
        domainsCards.appendChild(card);
        
        // Add event listener to the button
        const detailsBtn = card.querySelector('.view-details');
        detailsBtn.addEventListener('click', function() {
            showDomainDetails(domain);
        });
    });
}

// Reset all filters
function resetFilters() {
    domainSearch.value = '';
    statusFilter.value = 'all';
    registrarFilter.value = 'all';
    
    // Trigger filter update
    filterDomains();
}

// Helper function to format date
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

// Helper function to format month
function formatMonth(monthString) {
    const [year, month] = monthString.split('-');
    const date = new Date(parseInt(year), parseInt(month) - 1, 1);
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short' });
} 
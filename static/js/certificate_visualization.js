// Global variables
let allCertificates = [];
let certsTable;
let statusChart;
let issuersChart;
let expirationChart;

// DOM Elements
const certSearch = document.getElementById('cert-search');
const statusFilter = document.getElementById('status-filter');
const issuerFilter = document.getElementById('issuer-filter');
const resetFiltersBtn = document.getElementById('reset-filters');
const certificatesTableBody = document.getElementById('certificates-table-body');
const certificatesCards = document.getElementById('certificates-cards');
const tableLoader = document.getElementById('table-loader');
const cardsLoader = document.getElementById('cards-loader');
const tableContainer = document.getElementById('table-container');
const totalCertificatesEl = document.getElementById('total-certificates');
const validCertificatesEl = document.getElementById('valid-certificates');
const expiringCertificatesEl = document.getElementById('expiring-certificates');
const expiredCertificatesEl = document.getElementById('expired-certificates');

// Colors for charts
const chartColors = [
    '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
    '#5a5c69', '#858796', '#6f42c1', '#20c9a6', '#fd7e14'
];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    
    // Set up event listeners
    certSearch.addEventListener('input', filterCertificates);
    statusFilter.addEventListener('change', filterCertificates);
    issuerFilter.addEventListener('change', filterCertificates);
    resetFiltersBtn.addEventListener('click', resetFilters);
    
    // Set up tab change event to redraw charts
    document.querySelectorAll('button[data-bs-toggle="pill"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(e) {
            if (e.target.id === 'pills-chart-tab') {
                if (statusChart) statusChart.update();
                if (issuersChart) issuersChart.update();
                if (expirationChart) expirationChart.update();
            }
        });
    });
});

// Load data from JSON files
async function loadData() {
    try {
        // Fetch certificates data
        const response = await fetch('/api/certificates');
        allCertificates = await response.json();
        
        console.log('Certificates loaded:', allCertificates.length);
        
        // Process certificates (categorize by expiry)
        processCertificates();
        
        // Initialize the UI
        initializeUI();
        
        // Hide loaders and show content
        tableLoader.style.display = 'none';
        cardsLoader.style.display = 'none';
        tableContainer.style.display = 'block';
        certificatesCards.style.display = 'flex';
        
        // Initialize DataTable
        certsTable = $('#certificates-table').DataTable({
            paging: true,
            searching: false, // We'll use our own search
            ordering: true,
            order: [[4, 'asc']], // Sort by days left
            info: true,
            pageLength: 10,
            lengthMenu: [10, 25, 50, 100],
            drawCallback: function() {
                // Reattach event listeners after table redraw (pagination, sorting, etc.)
                attachDetailsButtonListeners();
            }
        });
        
        // Initialize charts
        initializeCharts();
        
    } catch (error) {
        console.error('Error loading data:', error);
        tableLoader.innerHTML = 'Error loading data. Please try again.';
        cardsLoader.innerHTML = 'Error loading data. Please try again.';
    }
}

// Process certificates for display
function processCertificates() {
    // Add display status category (valid, expiring, expired, unknown)
    // Also validate and fix any potentially missing or malformed data
    allCertificates.forEach(cert => {
        // Ensure required properties exist
        if (!cert.domain) cert.domain = 'Unknown';
        if (!cert.issuer) cert.issuer = 'Unknown';
        if (!cert.valid_until) cert.valid_until = null;
        if (!cert.valid_from) cert.valid_from = null;
        if (!cert.subject) cert.subject = 'Unknown';
        if (!cert.alt_names) cert.alt_names = [];
        if (!cert.serial_number) cert.serial_number = 'Unknown';
        
        // Set display status
        if (cert.status === 'unknown') {
            cert.displayStatus = 'unknown';
            if (!cert.days_remaining) cert.days_remaining = 0;
        } else if (cert.expired || !cert.days_remaining || cert.days_remaining <= 0) {
            cert.displayStatus = 'expired';
            cert.expired = true;
            if (!cert.days_remaining) cert.days_remaining = 0;
        } else if (cert.days_remaining <= 30) {
            cert.displayStatus = 'expiring';
        } else {
            cert.displayStatus = 'valid';
        }
    });
}

// Initialize the UI with certificate data
function initializeUI() {
    // Update statistics
    updateStats();
    
    // Populate the issuer filter dropdown
    populateIssuerFilter();
    
    // Populate the table and cards
    populateTable();
    populateCards();
}

// Update statistics in the UI
function updateStats() {
    const validCount = allCertificates.filter(cert => cert.displayStatus === 'valid').length;
    const expiringCount = allCertificates.filter(cert => cert.displayStatus === 'expiring').length;
    const expiredCount = allCertificates.filter(cert => cert.displayStatus === 'expired').length;
    const unknownCount = allCertificates.filter(cert => cert.displayStatus === 'unknown').length;
    
    totalCertificatesEl.textContent = allCertificates.length;
    validCertificatesEl.textContent = validCount;
    expiringCertificatesEl.textContent = expiringCount;
    expiredCertificatesEl.textContent = expiredCount + unknownCount;
}

// Populate the issuer filter dropdown
function populateIssuerFilter() {
    // Get unique issuers
    const issuers = [...new Set(allCertificates.map(cert => cert.issuer))].sort();
    
    // Add options to the dropdown
    issuers.forEach(issuer => {
        const option = document.createElement('option');
        option.value = issuer;
        option.textContent = issuer;
        issuerFilter.appendChild(option);
    });
}

// Populate the table with certificate data
function populateTable() {
    // Clear existing table data
    certificatesTableBody.innerHTML = '';
    
    // Generate table rows
    allCertificates.forEach(cert => {
        const row = document.createElement('tr');
        
        // Domain name
        const domainCell = document.createElement('td');
        domainCell.textContent = cert.domain || 'Unknown';
        row.appendChild(domainCell);
        
        // Status
        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.classList.add('badge', 'rounded-pill');
        
        if (cert.displayStatus === 'valid') {
            statusBadge.classList.add('bg-success');
            statusBadge.textContent = 'Valid';
        } else if (cert.displayStatus === 'expiring') {
            statusBadge.classList.add('bg-warning', 'text-dark');
            statusBadge.textContent = 'Expiring Soon';
        } else if (cert.displayStatus === 'expired') {
            statusBadge.classList.add('bg-danger');
            statusBadge.textContent = 'Expired';
        } else if (cert.displayStatus === 'unknown') {
            statusBadge.classList.add('bg-secondary');
            statusBadge.textContent = 'Unknown';
        }
        statusCell.appendChild(statusBadge);
        row.appendChild(statusCell);
        
        // Issuer
        const issuerCell = document.createElement('td');
        issuerCell.textContent = cert.issuer || 'Unknown';
        row.appendChild(issuerCell);
        
        // Expiration date
        const expiresCell = document.createElement('td');
        expiresCell.textContent = cert.valid_until ? formatDate(cert.valid_until) : 'N/A';
        row.appendChild(expiresCell);
        
        // Days remaining
        const daysCell = document.createElement('td');
        if (cert.expired) {
            daysCell.innerHTML = `<span class="text-danger">Expired</span>`;
        } else {
            daysCell.textContent = cert.days_remaining;
            
            // Add progress bar for expiration
            const progressDiv = document.createElement('div');
            progressDiv.className = 'progress';
            
            let progressClass = 'progress-bar-safe';
            let progressWidth = 100;
            
            if (cert.days_remaining <= 15) {
                progressClass = 'progress-bar-danger';
                progressWidth = cert.days_remaining / 15 * 100;
            } else if (cert.days_remaining <= 30) {
                progressClass = 'progress-bar-expiring';
                progressWidth = cert.days_remaining / 30 * 100;
            } else {
                progressWidth = Math.min(100, cert.days_remaining / 90 * 100);
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
        viewBtn.setAttribute('data-domain', cert.domain || 'Unknown');
        viewBtn.addEventListener('click', function() {
            showCertificateDetails(cert);
        });
        actionsCell.appendChild(viewBtn);
        row.appendChild(actionsCell);
        
        certificatesTableBody.appendChild(row);
    });
}

// Populate cards view with certificate data
function populateCards() {
    // Clear existing cards
    certificatesCards.innerHTML = '';
    
    // Generate cards for each certificate
    allCertificates.forEach(cert => {
        const card = document.createElement('div');
        card.classList.add('col-md-4', 'mb-4');
        
        let statusClass = 'border-success';
        let statusText = 'Valid';
        let statusBadgeClass = 'bg-success';
        
        if (cert.displayStatus === 'expiring') {
            statusClass = 'border-warning';
            statusText = 'Expiring Soon';
            statusBadgeClass = 'bg-warning text-dark';
        } else if (cert.displayStatus === 'expired') {
            statusClass = 'border-danger';
            statusText = 'Expired';
            statusBadgeClass = 'bg-danger';
        } else if (cert.displayStatus === 'unknown') {
            statusClass = 'border-secondary';
            statusText = 'Unknown';
            statusBadgeClass = 'bg-secondary';
        }
        
        let expirationInfo = '';
        if (cert.expired) {
            expirationInfo = `<p class="text-danger">Expired</p>`;
        } else {
            expirationInfo = `
                <p>Days remaining: ${cert.days_remaining}</p>
                <div class="progress">
                    <div class="progress-bar ${cert.days_remaining <= 15 ? 'progress-bar-danger' : (cert.days_remaining <= 30 ? 'progress-bar-expiring' : 'progress-bar-safe')}" 
                         role="progressbar" 
                         style="width: ${Math.min(100, cert.days_remaining / 90 * 100)}%" 
                         aria-valuenow="${Math.min(100, cert.days_remaining / 90 * 100)}" 
                         aria-valuemin="0" 
                         aria-valuemax="100"></div>
                </div>
            `;
        }
        
        card.innerHTML = `
            <div class="card h-100 ${statusClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${cert.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p><strong>Issuer:</strong> ${cert.issuer}</p>
                    <p><strong>Expires:</strong> ${formatDate(cert.valid_until)}</p>
                    ${expirationInfo}
                    <button class="btn btn-primary view-details mt-3" data-domain="${cert.domain}">
                        <i class="bi bi-eye"></i> View Details
                    </button>
                </div>
            </div>
        `;
        
        certificatesCards.appendChild(card);
        
        // Add event listener to the button
        const detailsBtn = card.querySelector('.view-details');
        detailsBtn.addEventListener('click', function() {
            showCertificateDetails(cert);
        });
    });
}

// Initialize charts
function initializeCharts() {
    initializeStatusChart();
    initializeIssuersChart();
    initializeExpirationChart();
}

// Initialize status distribution chart
function initializeStatusChart() {
    const validCount = allCertificates.filter(cert => cert.displayStatus === 'valid').length;
    const expiringCount = allCertificates.filter(cert => cert.displayStatus === 'expiring').length;
    const expiredCount = allCertificates.filter(cert => cert.displayStatus === 'expired').length;
    const unknownCount = allCertificates.filter(cert => cert.displayStatus === 'unknown').length;
    
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

// Initialize issuers distribution chart
function initializeIssuersChart() {
    // Count certificates by issuer
    const issuerCounts = {};
    allCertificates.forEach(cert => {
        if (!issuerCounts[cert.issuer]) {
            issuerCounts[cert.issuer] = 0;
        }
        issuerCounts[cert.issuer]++;
    });
    
    // Sort issuers by count (descending)
    const sortedIssuers = Object.entries(issuerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10); // Show top 10 issuers
    
    const ctx = document.getElementById('issuers-chart').getContext('2d');
    issuersChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedIssuers.map(entry => entry[0]),
            datasets: [{
                label: 'Number of Certificates',
                data: sortedIssuers.map(entry => entry[1]),
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
    // Group certificates by expiration month
    const expirationMonths = {};
    
    // Only include non-expired certificates
    const validCerts = allCertificates.filter(cert => !cert.expired);
    
    validCerts.forEach(cert => {
        const date = new Date(cert.valid_until);
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
                label: 'Certificates Expiring',
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

// Show certificate details in modal
function showCertificateDetails(cert) {
    const modalTitle = document.getElementById('certDetailsModalLabel');
    const modalBody = document.getElementById('modal-body-content');
    
    // Set modal title
    modalTitle.textContent = `Certificate for ${cert.domain}`;
    
    // Clear previous content
    modalBody.innerHTML = '';
    
    // Create status badge
    const statusBadge = document.createElement('div');
    statusBadge.classList.add('mb-3');
    
    let badgeClass = 'bg-success';
    let statusText = 'Valid';
    
    if (cert.displayStatus === 'expiring') {
        badgeClass = 'bg-warning text-dark';
        statusText = 'Expiring Soon';
    } else if (cert.displayStatus === 'expired') {
        badgeClass = 'bg-danger';
        statusText = 'Expired';
    } else if (cert.displayStatus === 'unknown') {
        badgeClass = 'bg-secondary';
        statusText = 'Unknown';
    }
    
    statusBadge.innerHTML = `
        <span class="badge ${badgeClass} rounded-pill">
            ${statusText}
        </span>
    `;
    modalBody.appendChild(statusBadge);
    
    // Add certificate info
    const infoDiv = document.createElement('div');
    infoDiv.classList.add('mb-3');
    
    // Expiration indicator
    let expirationIndicator = '';
    if (!cert.expired) {
        let progressClass = 'progress-bar-safe';
        let statusClass = 'status-valid';
        let statusText = 'Valid';
        
        if (cert.days_remaining <= 15) {
            progressClass = 'progress-bar-danger';
            statusClass = 'status-expired';
            statusText = 'Critical - Expires Very Soon';
        } else if (cert.days_remaining <= 30) {
            progressClass = 'progress-bar-expiring';
            statusClass = 'status-expiring';
            statusText = 'Warning - Expires Soon';
        }
        
        expirationIndicator = `
            <div class="expiration-indicator">
                <div class="progress flex-grow-1" style="width: 50%;">
                    <div class="progress-bar ${progressClass}" role="progressbar" 
                         style="width: ${Math.min(100, cert.days_remaining / 90 * 100)}%" 
                         aria-valuenow="${Math.min(100, cert.days_remaining / 90 * 100)}" 
                         aria-valuemin="0" 
                         aria-valuemax="100"></div>
                </div>
                <div class="expiration-text ${statusClass}">
                    ${statusText} (${cert.days_remaining} days remaining)
                </div>
            </div>
        `;
    }
    
    infoDiv.innerHTML = `
        <table class="table table-bordered">
            <tr>
                <th>Domain</th>
                <td>${cert.domain}</td>
            </tr>
            <tr>
                <th>Issuer</th>
                <td>${cert.issuer}</td>
            </tr>
            <tr>
                <th>Subject</th>
                <td>${cert.subject}</td>
            </tr>
            <tr>
                <th>Valid From</th>
                <td>${formatDate(cert.valid_from)}</td>
            </tr>
            <tr>
                <th>Valid Until</th>
                <td>${formatDate(cert.valid_until)}</td>
            </tr>
            <tr>
                <th>Days Remaining</th>
                <td>
                    ${cert.expired ? '<span class="text-danger">Expired</span>' : cert.days_remaining}
                    ${!cert.expired ? expirationIndicator : ''}
                </td>
            </tr>
            <tr>
                <th>Version</th>
                <td>${cert.version}</td>
            </tr>
            <tr>
                <th>Serial Number</th>
                <td><code>${cert.serial_number}</code></td>
            </tr>
        </table>
    `;
    modalBody.appendChild(infoDiv);
    
    // Add alternative names if available
    if (cert.alt_names && cert.alt_names.length > 0) {
        const altNamesDiv = document.createElement('div');
        
        let altNamesList = '';
        cert.alt_names.forEach(name => {
            altNamesList += `<li>${name}</li>`;
        });
        
        altNamesDiv.innerHTML = `
            <h5 class="mt-3 mb-2">Alternative Names</h5>
            <ul>
                ${altNamesList}
            </ul>
        `;
        modalBody.appendChild(altNamesDiv);
    }
    
    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('certDetailsModal'));
    modal.show();
}

// Filter certificates based on search and filter settings
function filterCertificates() {
    const searchTerm = certSearch.value.toLowerCase();
    const statusValue = statusFilter.value;
    const issuerValue = issuerFilter.value;
    
    // Filter the certificates
    const filteredCertificates = allCertificates.filter(cert => {
        // Search filter
        const matchesSearch = cert.domain.toLowerCase().includes(searchTerm);
        
        // Status filter
        let matchesStatus = true;
        if (statusValue === 'valid') {
            matchesStatus = cert.displayStatus === 'valid';
        } else if (statusValue === 'expiring') {
            matchesStatus = cert.displayStatus === 'expiring';
        } else if (statusValue === 'expired') {
            matchesStatus = cert.displayStatus === 'expired' || cert.displayStatus === 'unknown';
        }
        
        // Issuer filter
        let matchesIssuer = true;
        if (issuerValue !== 'all') {
            matchesIssuer = cert.issuer === issuerValue;
        }
        
        return matchesSearch && matchesStatus && matchesIssuer;
    });
    
    // Update the UI with filtered certificates
    updateUI(filteredCertificates);
    
    // Reset to first page
    if (certsTable) {
        certsTable.page(0).draw(false);
    }
}

// Update the UI with filtered certificates
function updateUI(filteredCertificates) {
    // Clear existing table rows
    certsTable.clear();
    
    // Add filtered certificates to the table
    filteredCertificates.forEach(cert => {
        let statusBadge = '';
        if (cert.displayStatus === 'valid') {
            statusBadge = '<span class="badge bg-success rounded-pill">Valid</span>';
        } else if (cert.displayStatus === 'expiring') {
            statusBadge = '<span class="badge bg-warning text-dark rounded-pill">Expiring Soon</span>';
        } else if (cert.displayStatus === 'expired') {
            statusBadge = '<span class="badge bg-danger rounded-pill">Expired</span>';
        } else if (cert.displayStatus === 'unknown') {
            statusBadge = '<span class="badge bg-secondary rounded-pill">Unknown</span>';
        }
        
        let daysCell = '';
        if (cert.expired) {
            daysCell = '<span class="text-danger">Expired</span>';
        } else {
            const progressClass = cert.days_remaining <= 15 ? 'progress-bar-danger' : 
                                (cert.days_remaining <= 30 ? 'progress-bar-expiring' : 'progress-bar-safe');
            const progressWidth = Math.min(100, cert.days_remaining / 90 * 100);
            
            daysCell = `${cert.days_remaining}
                <div class="progress">
                    <div class="progress-bar ${progressClass}" role="progressbar" style="width: ${progressWidth}%" 
                        aria-valuenow="${progressWidth}" aria-valuemin="0" aria-valuemax="100"></div>
                </div>`;
        }
        
        const domainName = cert.domain || 'Unknown';
        const issuer = cert.issuer || 'Unknown';
        const validUntil = cert.valid_until ? formatDate(cert.valid_until) : 'N/A';
        
        const actionButton = `<button class="btn btn-sm btn-primary view-details" data-domain="${domainName}">
                <i class="bi bi-eye"></i> Details
             </button>`;
             
        certsTable.row.add([
            domainName,
            statusBadge,
            issuer,
            validUntil,
            daysCell,
            actionButton
        ]).draw(false);
    });
    
    // Update cards view
    certificatesCards.innerHTML = '';
    filteredCertificates.forEach(cert => {
        const card = document.createElement('div');
        card.classList.add('col-md-4', 'mb-4');
        
        let statusClass = 'border-success';
        let statusText = 'Valid';
        let statusBadgeClass = 'bg-success';
        
        if (cert.displayStatus === 'expiring') {
            statusClass = 'border-warning';
            statusText = 'Expiring Soon';
            statusBadgeClass = 'bg-warning text-dark';
        } else if (cert.displayStatus === 'expired') {
            statusClass = 'border-danger';
            statusText = 'Expired';
            statusBadgeClass = 'bg-danger';
        } else if (cert.displayStatus === 'unknown') {
            statusClass = 'border-secondary';
            statusText = 'Unknown';
            statusBadgeClass = 'bg-secondary';
        }
        
        let expirationInfo = '';
        if (cert.expired) {
            expirationInfo = `<p class="text-danger">Expired</p>`;
        } else {
            expirationInfo = `
                <p>Days remaining: ${cert.days_remaining}</p>
                <div class="progress">
                    <div class="progress-bar ${cert.days_remaining <= 15 ? 'progress-bar-danger' : (cert.days_remaining <= 30 ? 'progress-bar-expiring' : 'progress-bar-safe')}" 
                         role="progressbar" 
                         style="width: ${Math.min(100, cert.days_remaining / 90 * 100)}%" 
                         aria-valuenow="${Math.min(100, cert.days_remaining / 90 * 100)}" 
                         aria-valuemin="0" 
                         aria-valuemax="100"></div>
                </div>
            `;
        }
        
        card.innerHTML = `
            <div class="card h-100 ${statusClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${cert.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p><strong>Issuer:</strong> ${cert.issuer}</p>
                    <p><strong>Expires:</strong> ${formatDate(cert.valid_until)}</p>
                    ${expirationInfo}
                    <button class="btn btn-primary view-details mt-3" data-domain="${cert.domain}">
                        <i class="bi bi-eye"></i> View Details
                    </button>
                </div>
            </div>
        `;
        
        certificatesCards.appendChild(card);
        
        // Add event listener to the button
        const detailsBtn = card.querySelector('.view-details');
        detailsBtn.addEventListener('click', function() {
            showCertificateDetails(cert);
        });
    });
    
    // Reattach event listeners to buttons
    // Note: For table view, this is now handled by the drawCallback
    // but we still attach listeners to cards here
    document.querySelectorAll('#certificates-cards .view-details').forEach(button => {
        const domainName = button.getAttribute('data-domain');
        const cert = allCertificates.find(c => c.domain === domainName);
        if (cert) {
            // Remove existing event listeners to prevent duplicates
            const newButton = button.cloneNode(true);
            button.parentNode.replaceChild(newButton, button);
            
            newButton.addEventListener('click', function() {
                showCertificateDetails(cert);
            });
        }
    });
}

// Reset all filters
function resetFilters() {
    certSearch.value = '';
    statusFilter.value = 'all';
    issuerFilter.value = 'all';
    
    // Trigger filter update
    filterCertificates();
}

// Helper function to format date
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    try {
        const date = new Date(dateString);
        // Check if date is valid
        if (isNaN(date.getTime())) {
            return 'N/A';
        }
        
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        return date.toLocaleDateString(undefined, options);
    } catch (e) {
        console.error('Error formatting date:', e);
        return 'N/A';
    }
}

// Helper function to format month
function formatMonth(monthString) {
    const [year, month] = monthString.split('-');
    const date = new Date(parseInt(year), parseInt(month) - 1, 1);
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short' });
}

// Function to attach event listeners to all details buttons
function attachDetailsButtonListeners() {
    document.querySelectorAll('.view-details').forEach(button => {
        // Remove existing event listeners to prevent duplicates
        const newButton = button.cloneNode(true);
        button.parentNode.replaceChild(newButton, button);
        
        const domainName = newButton.getAttribute('data-domain');
        const cert = allCertificates.find(c => c.domain === domainName);
        if (cert) {
            newButton.addEventListener('click', function() {
                showCertificateDetails(cert);
            });
        }
    });
} 
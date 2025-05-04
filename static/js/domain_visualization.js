// Global variables
let allDomains = [];
let inactiveDomains = [];
let domainsTable;

// DOM Elements
const domainSearch = document.getElementById('domain-search');
const statusFilter = document.getElementById('status-filter');
const subdomainFilter = document.getElementById('subdomain-filter');
const resetFiltersBtn = document.getElementById('reset-filters');
const domainsTableBody = document.getElementById('domains-table-body');
const domainsCards = document.getElementById('domains-cards');
const tableLoader = document.getElementById('table-loader');
const cardsLoader = document.getElementById('cards-loader');
const tableContainer = document.getElementById('table-container');
const totalDomainsEl = document.getElementById('total-domains');
const totalSubdomainsEl = document.getElementById('total-subdomains');
const activeDomainsEl = document.getElementById('active-domains');
const inactiveDomainsEl = document.getElementById('inactive-domains');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    
    // Set up event listeners
    domainSearch.addEventListener('input', filterDomains);
    statusFilter.addEventListener('change', filterDomains);
    subdomainFilter.addEventListener('change', filterDomains);
    resetFiltersBtn.addEventListener('click', resetFilters);
});

// Load data from JSON files
async function loadData() {
    try {
        // Fetch all domains data
        const domainsResponse = await fetch('/api/domains');
        allDomains = await domainsResponse.json();
        
        // Fetch inactive domains data
        const inactiveResponse = await fetch('/api/inactive_domains');
        inactiveDomains = await inactiveResponse.json();
        
        console.log('All domains count:', allDomains.length);
        console.log('Inactive domains count:', inactiveDomains.length);
        
        // Mark inactive domains
        markInactiveDomains();
        
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
            info: true,
            pageLength: 10,
            lengthMenu: [10, 25, 50, 100]
        });
    } catch (error) {
        console.error('Error loading data:', error);
        tableLoader.innerHTML = 'Error loading data. Please try again.';
        cardsLoader.innerHTML = 'Error loading data. Please try again.';
    }
}

// Mark inactive domains in the allDomains array
function markInactiveDomains() {
    // Create a Set from inactiveDomains for faster lookups
    const inactiveDomainsSet = new Set(inactiveDomains);
    
    // Check each domain in allDomains against the Set of inactive domains
    allDomains.forEach(domain => {
        domain.isActive = !inactiveDomainsSet.has(domain.domain);
    });
    
    // Also create entries for inactive domains that are not in allDomains
    inactiveDomains.forEach(inactiveDomain => {
        // Check if this inactive domain exists in allDomains
        const exists = allDomains.some(domain => domain.domain === inactiveDomain);
        
        if (!exists) {
            // Add it to allDomains with inactive status
            allDomains.push({
                domain: inactiveDomain,
                subdomains_found: 0,
                results: [],
                isActive: false
            });
        }
    });
    
    console.log('After marking, active domains:', allDomains.filter(d => d.isActive).length);
    console.log('After marking, inactive domains:', allDomains.filter(d => !d.isActive).length);
}

// Initialize the UI with domain data
function initializeUI() {
    // Update statistics
    updateStats();
    
    // Populate the table and cards
    populateTable();
    populateCards();
}

// Update statistics in the UI
function updateStats() {
    let totalSubdomains = 0;
    let activeDomains = 0;
    let inactiveCount = 0;
    
    allDomains.forEach(domain => {
        totalSubdomains += domain.subdomains_found;
        if (domain.isActive) {
            activeDomains++;
        } else {
            inactiveCount++;
        }
    });
    
    totalDomainsEl.textContent = allDomains.length;
    totalSubdomainsEl.textContent = totalSubdomains;
    activeDomainsEl.textContent = activeDomains;
    inactiveDomainsEl.textContent = inactiveCount;
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
        if (domain.isActive) {
            statusBadge.classList.add('bg-success');
            statusBadge.textContent = 'Active';
        } else {
            statusBadge.classList.add('bg-danger');
            statusBadge.textContent = 'Inactive';
        }
        statusCell.appendChild(statusBadge);
        row.appendChild(statusCell);
        
        // Subdomains count
        const subdomainsCell = document.createElement('td');
        subdomainsCell.textContent = domain.subdomains_found;
        row.appendChild(subdomainsCell);
        
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
        
        const statusClass = domain.isActive ? 'border-success' : 'border-danger';
        const statusText = domain.isActive ? 'Active' : 'Inactive';
        const statusBadgeClass = domain.isActive ? 'bg-success' : 'bg-danger';
        
        card.innerHTML = `
            <div class="card h-100 ${statusClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${domain.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p>Subdomains found: ${domain.subdomains_found}</p>
                    <button class="btn btn-primary view-details" data-domain="${domain.domain}">
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

// Show domain details in modal
function showDomainDetails(domain) {
    const modalTitle = document.getElementById('domainDetailsModalLabel');
    const modalBody = document.getElementById('modal-body-content');
    
    // Set modal title
    modalTitle.textContent = domain.domain;
    
    // Clear previous content
    modalBody.innerHTML = '';
    
    // Create status badge
    const statusBadge = document.createElement('div');
    statusBadge.classList.add('mb-3');
    statusBadge.innerHTML = `
        <span class="badge ${domain.isActive ? 'bg-success' : 'bg-danger'} rounded-pill">
            ${domain.isActive ? 'Active' : 'Inactive'}
        </span>
    `;
    modalBody.appendChild(statusBadge);
    
    // Add domain info
    const infoDiv = document.createElement('div');
    infoDiv.classList.add('mb-3');
    infoDiv.innerHTML = `
        <p><strong>Total Subdomains:</strong> ${domain.subdomains_found}</p>
    `;
    modalBody.appendChild(infoDiv);
    
    // Add subdomains table if available
    if (domain.results && domain.results.length > 0) {
        const subdomainsDiv = document.createElement('div');
        subdomainsDiv.innerHTML = `
            <h5 class="mt-4 mb-3">Subdomains</h5>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    ${domain.results.map(result => `
                        <tr>
                            <td>${result.subdomain}</td>
                            <td>${result.ip || 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        modalBody.appendChild(subdomainsDiv);
    }
    
    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('domainDetailsModal'));
    modal.show();
}

// Filter domains based on search and filter settings
function filterDomains() {
    const searchTerm = domainSearch.value.toLowerCase();
    const statusValue = statusFilter.value;
    const subdomainValue = subdomainFilter.value;
    
    // Filter the domains
    const filteredDomains = allDomains.filter(domain => {
        // Search filter
        const matchesSearch = domain.domain.toLowerCase().includes(searchTerm);
        
        // Status filter
        let matchesStatus = true;
        if (statusValue === 'active') {
            matchesStatus = domain.isActive;
        } else if (statusValue === 'inactive') {
            matchesStatus = !domain.isActive;
        }
        
        // Subdomain filter
        let matchesSubdomain = true;
        if (subdomainValue === 'with-subdomains') {
            matchesSubdomain = domain.subdomains_found > 0;
        } else if (subdomainValue === 'without-subdomains') {
            matchesSubdomain = domain.subdomains_found === 0;
        }
        
        return matchesSearch && matchesStatus && matchesSubdomain;
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
        domainsTable.row.add([
            domain.domain,
            `<span class="badge ${domain.isActive ? 'bg-success' : 'bg-danger'} rounded-pill">${domain.isActive ? 'Active' : 'Inactive'}</span>`,
            domain.subdomains_found,
            `<button class="btn btn-sm btn-primary view-details" data-domain="${domain.domain}"><i class="bi bi-eye"></i> Details</button>`
        ]).draw(false);
    });
    
    // Update cards view
    domainsCards.innerHTML = '';
    filteredDomains.forEach(domain => {
        const card = document.createElement('div');
        card.classList.add('col-md-4', 'mb-4');
        
        const statusClass = domain.isActive ? 'border-success' : 'border-danger';
        const statusText = domain.isActive ? 'Active' : 'Inactive';
        const statusBadgeClass = domain.isActive ? 'bg-success' : 'bg-danger';
        
        card.innerHTML = `
            <div class="card h-100 ${statusClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${domain.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p>Subdomains found: ${domain.subdomains_found}</p>
                    <button class="btn btn-primary view-details" data-domain="${domain.domain}">
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

// Reset all filters
function resetFilters() {
    domainSearch.value = '';
    statusFilter.value = 'all';
    subdomainFilter.value = 'all';
    
    // Trigger filter update
    filterDomains();
} 
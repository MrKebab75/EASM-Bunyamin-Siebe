function updateUI(filteredCertificates) {
    // Clear current table
    certsTable.clear();
    
    // Update stats
    updateStats();
    
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
        const subject = cert.subject || 'Unknown';
        const issuer = cert.issuer || 'Unknown';
        const validUntil = cert.valid_until ? formatDate(cert.valid_until) : 'N/A';
        
        const actionButton = `<button class="btn btn-sm btn-primary view-details" data-domain="${domainName}">
                <i class="bi bi-eye"></i> Details
             </button>`;
        
        // Add row to the DataTable
        const rowNode = certsTable.row.add([
            domainName,
            statusBadge,
            issuer,
            subject,
            validUntil,
            daysCell,
            actionButton
        ]).draw(false).node();
        
        // Add imperva highlight if needed
        if (cert.subject.toLowerCase() === 'imperva.com') {
            $(rowNode).addClass('imperva-highlight');
        }
    });
    
    // Reattach event listeners to detail buttons
    setTimeout(attachDetailsButtonListeners, 100);
    
    // Update cards
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
        
        // Add special styling for imperva.com certificates
        const isImperva = cert.subject.toLowerCase() === 'imperva.com';
        const impervaClass = isImperva ? 'imperva-highlight' : '';
        
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
            <div class="card h-100 ${statusClass} ${impervaClass}" style="border-width: 2px;">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${cert.domain}</h5>
                    <span class="badge ${statusBadgeClass} rounded-pill">${statusText}</span>
                </div>
                <div class="card-body">
                    <p><strong>Subject:</strong> ${cert.subject || 'Unknown'}</p>
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
    
    // Update charts if they exist
    updateCharts(filteredCertificates);
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

// Update statistics in the UI with filtered data
function updateFilteredStats(filteredCerts) {
    const validCount = filteredCerts.filter(cert => cert.displayStatus === 'valid').length;
    const expiringCount = filteredCerts.filter(cert => cert.displayStatus === 'expiring').length;
    const expiredCount = filteredCerts.filter(cert => cert.displayStatus === 'expired').length;
    const unknownCount = filteredCerts.filter(cert => cert.displayStatus === 'unknown').length;
    
    totalCertificatesEl.textContent = filteredCerts.length;
    validCertificatesEl.textContent = validCount;
    expiringCertificatesEl.textContent = expiringCount;
    expiredCertificatesEl.textContent = expiredCount + unknownCount;
}
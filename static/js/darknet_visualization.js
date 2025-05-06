document.addEventListener('DOMContentLoaded', function() {
    // Initialize loading state
    fetchDarknetData();
});

// Global variables
let darknetData = null;
let allResults = [];
let currentPage = 1;
const resultsPerPage = 10;

// Fetch darknet data from API
function fetchDarknetData() {
    fetch('/api/darknet')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            darknetData = data;
            processDarknetData(data);
        })
        .catch(error => {
            console.error('Error fetching darknet data:', error);
            document.getElementById('results-content').innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle"></i> Error loading data: ${error.message}
                </div>`;
        });
}

// Process and display darknet data
function processDarknetData(data) {
    // Update statistics
    updateStatistics(data);
    
    // Populate search engines information
    populateEnginesInfo(data);
    
    // Extract all results from all engines
    extractAllResults(data);
    
    // Render results
    renderResultsPage(1);
    
    // Set up event listeners
    setupEventListeners();
    
    // Set up charts
    setupCharts(data);
}

// Update the statistics in the header
function updateStatistics(data) {
    document.getElementById('search-term').textContent = data.search_term || '-';
    document.getElementById('total-results').textContent = data.total_results || 0;
    document.getElementById('engines-searched').textContent = data.engines_searched || 0;
    document.getElementById('timestamp').textContent = formatDate(data.timestamp) || '-';
}

// Format date for better readability
function formatDate(dateString) {
    if (!dateString) return '-';
    
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Populate engines information
function populateEnginesInfo(data) {
    const enginesContainer = document.getElementById('engines-container');
    
    let html = '<div class="row">';
    
    // Successful engines
    if (data.successful_engines && data.successful_engines.length > 0) {
        html += '<div class="col-md-6"><h5>Successful Engines</h5><div class="d-flex flex-wrap mt-2">';
        
        data.successful_engines.forEach(engine => {
            html += `<span class="engine-badge me-2 mb-2">${engine} <i class="bi bi-check-circle-fill text-success ms-1"></i></span>`;
        });
        
        html += '</div></div>';
    }
    
    // Failed engines
    if (data.failed_engines && data.failed_engines.length > 0) {
        html += '<div class="col-md-6"><h5>Failed Engines</h5><div class="d-flex flex-wrap mt-2">';
        
        data.failed_engines.forEach(engineData => {
            const tooltipText = engineData.reason ? `title="${engineData.reason.substring(0, 100)}${engineData.reason.length > 100 ? '...' : ''}"` : '';
            html += `<span class="engine-badge failed-engine me-2 mb-2" ${tooltipText}>${engineData.engine} <i class="bi bi-x-circle-fill text-danger ms-1"></i></span>`;
        });
        
        html += '</div></div>';
    }
    
    html += '</div>';
    enginesContainer.innerHTML = html;
}

// Extract all results from all engines
function extractAllResults(data) {
    allResults = [];
    
    if (data.engines) {
        for (const [engineName, results] of Object.entries(data.engines)) {
            if (Array.isArray(results)) {
                results.forEach(result => {
                    // Add engine name to the result
                    result.engine = engineName;
                    // Extract onion domain from URL or text
                    result.onion_domain = extractOnionDomain(result.url, result.text);
                    // Add to all results
                    allResults.push(result);
                });
            }
        }
    }
    
    // Sort by relevance score (highest first)
    allResults.sort((a, b) => (b.relevance_score || 0) - (a.relevance_score || 0));
}

// Extract onion domain from URL or text
function extractOnionDomain(url, text) {
    // Try to find onion domain in text first
    const onionRegex = /([a-z2-7]{55,56}\.onion)/i;
    
    if (text) {
        const match = text.match(onionRegex);
        if (match && match[1]) {
            return match[1];
        }
    }
    
    // Try to extract from URL if available
    if (url) {
        const urlMatch = url.match(onionRegex);
        if (urlMatch && urlMatch[1]) {
            return urlMatch[1];
        }
    }
    
    return 'Unknown .onion domain';
}

// Render results page
function renderResultsPage(page) {
    currentPage = page;
    const resultsContent = document.getElementById('results-content');
    const filteredResults = filterResults();
    
    if (filteredResults.length === 0) {
        resultsContent.innerHTML = '<div class="alert alert-info">No results found matching your filter criteria.</div>';
        document.getElementById('pagination-container').innerHTML = '';
        return;
    }
    
    const startIndex = (page - 1) * resultsPerPage;
    const endIndex = Math.min(startIndex + resultsPerPage, filteredResults.length);
    const currentResults = filteredResults.slice(startIndex, endIndex);
    
    let html = '';
    
    currentResults.forEach(result => {
        // Extract title from the text - first line or first 50 chars
        let title = result.text ? result.text.split('\n')[0].trim() : 'No title available';
        if (title.length > 70) {
            title = title.substring(0, 70) + '...';
        }
        
        // Format result text for display
        let displayText = result.text ? formatResultText(result.text) : 'No content available';
        
        // Determine age display
        let ageDisplay = 'Unknown age';
        if (result.text && result.text.includes('—')) {
            const ageMatch = result.text.match(/—\s+(.*?)\s+—/);
            if (ageMatch && ageMatch[1]) {
                ageDisplay = ageMatch[1].trim();
            }
        }
        
        html += `
        <div class="card result-card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">${title}</h5>
                <span class="relevance-badge">Relevance: ${result.relevance_score || 'N/A'}</span>
            </div>
            <div class="card-body">
                <p class="text-muted mb-2">
                    <i class="bi bi-link-45deg"></i> ${result.onion_domain} 
                    <span class="ms-3"><i class="bi bi-clock"></i> ${ageDisplay}</span>
                    <span class="ms-3"><i class="bi bi-search"></i> Found by ${result.engine}</span>
                </p>
                <div class="result-text mb-3">
                    ${displayText}
                </div>
                <button class="btn btn-sm btn-outline-info view-details" data-index="${allResults.indexOf(result)}">
                    <i class="bi bi-eye"></i> View Full Details
                </button>
            </div>
        </div>`;
    });
    
    resultsContent.innerHTML = html;
    
    // Set up view details event listeners
    document.querySelectorAll('.view-details').forEach(button => {
        button.addEventListener('click', function() {
            const index = parseInt(this.getAttribute('data-index'));
            showResultDetails(allResults[index]);
        });
    });
    
    // Set up pagination
    setupPagination(filteredResults.length, page);
    
    // Update table view
    updateTableView(filteredResults);
}

// Format result text for display
function formatResultText(text) {
    if (!text) return '';
    
    // Limit to 200 characters and add ellipsis for longer text
    if (text.length > 200) {
        return text.substring(0, 200) + '... <span class="text-muted">(click View Full Details to see more)</span>';
    }
    
    return text;
}

// Set up pagination
function setupPagination(totalResults, currentPage) {
    const paginationContainer = document.getElementById('pagination-container');
    const totalPages = Math.ceil(totalResults / resultsPerPage);
    
    if (totalPages <= 1) {
        paginationContainer.innerHTML = '';
        return;
    }
    
    let html = '<nav aria-label="Results pagination"><ul class="pagination">';
    
    // Previous button
    html += `
        <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${currentPage - 1}" aria-label="Previous">
                <span aria-hidden="true">&laquo;</span>
            </a>
        </li>`;
    
    // Page numbers
    const maxVisiblePages = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
    
    if (endPage - startPage + 1 < maxVisiblePages) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    
    // First page
    if (startPage > 1) {
        html += `<li class="page-item"><a class="page-link" href="#" data-page="1">1</a></li>`;
        if (startPage > 2) {
            html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
    }
    
    // Page numbers
    for (let i = startPage; i <= endPage; i++) {
        html += `<li class="page-item ${i === currentPage ? 'active' : ''}"><a class="page-link" href="#" data-page="${i}">${i}</a></li>`;
    }
    
    // Last page
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
        html += `<li class="page-item"><a class="page-link" href="#" data-page="${totalPages}">${totalPages}</a></li>`;
    }
    
    // Next button
    html += `
        <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${currentPage + 1}" aria-label="Next">
                <span aria-hidden="true">&raquo;</span>
            </a>
        </li>`;
    
    html += '</ul></nav>';
    
    paginationContainer.innerHTML = html;
    
    // Add event listeners to pagination links
    document.querySelectorAll('.pagination .page-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const page = parseInt(this.getAttribute('data-page'));
            if (!isNaN(page)) {
                renderResultsPage(page);
                // Scroll to top of results
                document.getElementById('pills-results').scrollIntoView({behavior: 'smooth'});
            }
        });
    });
}

// Filter results based on search input and relevance filter
function filterResults() {
    const searchTerm = document.getElementById('search-input').value.toLowerCase();
    const relevanceFilter = document.getElementById('relevance-filter').value;
    
    return allResults.filter(result => {
        // Search term filter
        const matchesSearch = !searchTerm || 
            (result.text && result.text.toLowerCase().includes(searchTerm)) || 
            (result.url && result.url.toLowerCase().includes(searchTerm)) ||
            (result.onion_domain && result.onion_domain.toLowerCase().includes(searchTerm));
        
        // Relevance filter
        let matchesRelevance = true;
        if (relevanceFilter !== 'all') {
            const relevanceScore = result.relevance_score || 0;
            
            if (relevanceFilter === '10') {
                matchesRelevance = relevanceScore === 10;
            } else if (relevanceFilter === '9') {
                matchesRelevance = relevanceScore === 9;
            } else if (relevanceFilter === '8') {
                matchesRelevance = relevanceScore === 8;
            } else if (relevanceFilter === '7') {
                matchesRelevance = relevanceScore === 7;
            } else if (relevanceFilter === '6') {
                matchesRelevance = relevanceScore <= 6;
            }
        }
        
        return matchesSearch && matchesRelevance;
    });
}

// Update table view
function updateTableView(filteredResults) {
    const tableContainer = document.getElementById('table-container');
    const tableLoader = document.getElementById('table-loader');
    const tableBody = document.getElementById('results-table-body');
    
    tableLoader.style.display = 'none';
    tableContainer.style.display = 'block';
    
    let html = '';
    
    filteredResults.forEach(result => {
        let contentText = result.text ? result.text.substring(0, 100) : 'No content available';
        if (result.text && result.text.length > 100) {
            contentText += '...';
        }
        
        // Determine age display
        let ageDisplay = 'Unknown';
        if (result.text && result.text.includes('—')) {
            const ageMatch = result.text.match(/—\s+(.*?)\s+—/);
            if (ageMatch && ageMatch[1]) {
                ageDisplay = ageMatch[1].trim();
            }
        }
        
        html += `
        <tr>
            <td class="text-center">${result.relevance_score || 'N/A'}</td>
            <td>${contentText}</td>
            <td>${result.onion_domain}</td>
            <td>${ageDisplay}</td>
        </tr>`;
    });
    
    tableBody.innerHTML = html;
    
    // Initialize DataTable
    if ($.fn.DataTable.isDataTable('#results-table')) {
        $('#results-table').DataTable().destroy();
    }
    
    $('#results-table').DataTable({
        "pageLength": 25,
        "order": [[0, "desc"]],
        "language": {
            "search": "Quick search:",
            "lengthMenu": "Show _MENU_ results per page",
            "info": "Showing _START_ to _END_ of _TOTAL_ results"
        }
    });
}

// Show result details in modal
function showResultDetails(result) {
    const modalBody = document.getElementById('resultDetailsModalBody');
    const modal = new bootstrap.Modal(document.getElementById('resultDetailsModal'));
    
    // Determine age display
    let ageDisplay = 'Unknown';
    if (result.text && result.text.includes('—')) {
        const ageMatch = result.text.match(/—\s+(.*?)\s+—/);
        if (ageMatch && ageMatch[1]) {
            ageDisplay = ageMatch[1].trim();
        }
    }
    
    let html = `
    <div class="mb-4">
        <h5>Search Engine: ${result.engine}</h5>
        <p class="text-muted">
            <i class="bi bi-link-45deg"></i> ${result.onion_domain}<br>
            <i class="bi bi-clock"></i> Age: ${ageDisplay}<br>
            <i class="bi bi-star-fill"></i> Relevance Score: ${result.relevance_score || 'N/A'}
        </p>
    </div>
    
    <div class="card bg-dark mb-3">
        <div class="card-header">Full Content</div>
        <div class="card-body">
            <pre class="text-light" style="white-space: pre-wrap;">${result.text || 'No content available'}</pre>
        </div>
    </div>
    
    <div class="card bg-dark">
        <div class="card-header">Original URL</div>
        <div class="card-body">
            <pre class="text-light" style="white-space: pre-wrap; overflow-wrap: break-word;">${result.url || 'No URL available'}</pre>
        </div>
    </div>`;
    
    modalBody.innerHTML = html;
    modal.show();
}

// Set up event listeners
function setupEventListeners() {
    // Search input
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            renderResultsPage(1);
        });
    }
    
    // Relevance filter
    const relevanceFilter = document.getElementById('relevance-filter');
    if (relevanceFilter) {
        relevanceFilter.addEventListener('change', function() {
            renderResultsPage(1);
        });
    }
    
    // Reset filters
    const resetButton = document.getElementById('reset-filters');
    if (resetButton) {
        resetButton.addEventListener('click', function() {
            if (searchInput) searchInput.value = '';
            if (relevanceFilter) relevanceFilter.value = 'all';
            renderResultsPage(1);
        });
    }
}

// Set up charts
function setupCharts(data) {
    setupRelevanceDistributionChart();
    setupAgeDistributionChart();
    setupWordCloudChart();
}

// Set up relevance distribution chart
function setupRelevanceDistributionChart() {
    const ctx = document.getElementById('relevanceDistributionChart');
    
    // Count results by relevance score
    const relevanceCounts = {};
    
    allResults.forEach(result => {
        const score = result.relevance_score || 0;
        relevanceCounts[score] = (relevanceCounts[score] || 0) + 1;
    });
    
    // Sort by relevance score
    const sortedScores = Object.keys(relevanceCounts).sort((a, b) => parseInt(b) - parseInt(a));
    
    const data = {
        labels: sortedScores.map(score => `Score ${score}`),
        datasets: [{
            label: 'Results Count',
            data: sortedScores.map(score => relevanceCounts[score]),
            backgroundColor: [
                '#e94560',
                '#ff6b81',
                '#ff7f9d',
                '#ff97b7',
                '#ffb0d1',
                '#ffcae6'
            ],
            borderWidth: 1
        }]
    };
    
    const config = {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Result Count by Relevance Score',
                    color: '#e6e6e6',
                    font: {
                        size: 16
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#e6e6e6'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#e6e6e6'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    };
    
    if (window.relevanceChart) {
        window.relevanceChart.destroy();
    }
    
    window.relevanceChart = new Chart(ctx, config);
}

// Set up age distribution chart
function setupAgeDistributionChart() {
    const ctx = document.getElementById('ageDistributionChart');
    
    // Count results by age
    const ageCounts = {
        'Days': 0,
        'Weeks': 0,
        'Months': 0,
        'Years': 0,
        'Unknown': 0
    };
    
    allResults.forEach(result => {
        let ageCategory = 'Unknown';
        
        if (result.text && result.text.includes('—')) {
            const ageMatch = result.text.match(/—\s+(.*?)\s+—/);
            if (ageMatch && ageMatch[1]) {
                const ageText = ageMatch[1].trim().toLowerCase();
                
                if (ageText.includes('day')) {
                    ageCategory = 'Days';
                } else if (ageText.includes('week')) {
                    ageCategory = 'Weeks';
                } else if (ageText.includes('month')) {
                    ageCategory = 'Months';
                } else if (ageText.includes('year')) {
                    ageCategory = 'Years';
                }
            }
        }
        
        ageCounts[ageCategory]++;
    });
    
    const data = {
        labels: Object.keys(ageCounts),
        datasets: [{
            label: 'Results Count',
            data: Object.values(ageCounts),
            backgroundColor: [
                '#e94560',
                '#0f3460',
                '#16213e',
                '#1a1a2e',
                '#9ba4b4'
            ],
            borderWidth: 1
        }]
    };
    
    const config = {
        type: 'pie',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e6e6e6',
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Results by Age Category',
                    color: '#e6e6e6',
                    font: {
                        size: 16
                    }
                }
            }
        }
    };
    
    if (window.ageChart) {
        window.ageChart.destroy();
    }
    
    window.ageChart = new Chart(ctx, config);
}

// Set up word cloud chart (actually a bar chart with common terms)
function setupWordCloudChart() {
    const ctx = document.getElementById('wordCloudChart');
    
    // Extract common terms
    const termFrequency = {};
    const commonWords = new Set(['the', 'and', 'of', 'to', 'a', 'in', 'for', 'is', 'on', 'that', 'with', 'by', 'this', 'as', 'at', 'from', 'or', 'an', 'be']);
    
    allResults.forEach(result => {
        if (!result.text) return;
        
        // Split text into words and count frequency
        const words = result.text.toLowerCase()
            .replace(/[^\w\s]/g, '')
            .split(/\s+/)
            .filter(word => word.length > 3 && !commonWords.has(word));
        
        words.forEach(word => {
            termFrequency[word] = (termFrequency[word] || 0) + 1;
        });
    });
    
    // Get top 15 terms
    const sortedTerms = Object.entries(termFrequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20);
    
    const data = {
        labels: sortedTerms.map(([term]) => term),
        datasets: [{
            label: 'Frequency',
            data: sortedTerms.map(([_, count]) => count),
            backgroundColor: '#e94560',
            borderWidth: 1
        }]
    };
    
    const config = {
        type: 'bar',
        data: data,
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Most Common Terms in Results',
                    color: '#e6e6e6',
                    font: {
                        size: 16
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#e6e6e6'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: '#e6e6e6'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    };
    
    if (window.wordCloudChart) {
        window.wordCloudChart.destroy();
    }
    
    window.wordCloudChart = new Chart(ctx, config);
} 
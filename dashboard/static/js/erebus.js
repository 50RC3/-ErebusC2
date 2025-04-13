/**
 * ErebusC2 Dashboard Common JavaScript
 */

// Global notification system
const ErebusNotifications = {
    show: function(title, message, type = 'info') {
        // Create toast element
        const toast = $(`
            <div class="toast" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="5000">
                <div class="toast-header bg-${type} text-white">
                    <strong class="me-auto">${title}</strong>
                    <small>${new Date().toLocaleTimeString()}</small>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            </div>
        `);
        
        // Append to toast container
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) {
            $('body').append('<div id="toastContainer" class="toast-container position-fixed bottom-0 end-0 p-3"></div>');
        }
        
        $('#toastContainer').append(toast);
        
        // Initialize and show the toast
        const bsToast = new bootstrap.Toast(toast[0]);
        bsToast.show();
        
        // Remove toast after it's hidden
        toast.on('hidden.bs.toast', function() {
            toast.remove();
        });
    },
    
    error: function(title, message) {
        this.show(title, message, 'danger');
    },
    
    success: function(title, message) {
        this.show(title, message, 'success');
    },
    
    warning: function(title, message) {
        this.show(title, message, 'warning');
    },
    
    info: function(title, message) {
        this.show(title, message, 'info');
    }
};

// Authentication functions
const ErebusAuth = {
    isAuthenticated: function() {
        return localStorage.getItem('auth_token') !== null;
    },
    
    getToken: function() {
        return localStorage.getItem('auth_token');
    },
    
    setToken: function(token) {
        localStorage.setItem('auth_token', token);
    },
    
    clearToken: function() {
        localStorage.removeItem('auth_token');
    },
    
    login: function(username, password) {
        return $.ajax({
            url: '/api/auth/login',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                username: username,
                password: password
            })
        }).then(response => {
            if (response.status === 'success' && response.token) {
                this.setToken(response.token);
                return true;
            }
            return false;
        });
    },
    
    logout: function() {
        this.clearToken();
        window.location.href = '/login';
    }
};

// Setup AJAX defaults for authorization
$.ajaxSetup({
    beforeSend: function(xhr) {
        if (ErebusAuth.isAuthenticated()) {
            xhr.setRequestHeader('Authorization', `Bearer ${ErebusAuth.getToken()}`);
        }
    },
    statusCode: {
        401: function() {
            // If unauthorized, redirect to login
            ErebusAuth.clearToken();
            window.location.href = '/login';
        }
    }
});

// Dashboard health updates
function updateDashboardHealth() {
    $.ajax({
        url: '/api/health',
        type: 'GET',
        success: function(data) {
            $('#serverStatus').text(data.status);
            $('#implantCount').text(data.implants.total);
            $('#activeImplantCount').text(data.implants.active);
            $('#listenerCount').text(data.listeners.total);
            $('#activeListenerCount').text(data.listeners.active);
        },
        error: function() {
            // Update status indicators to show offline status
            $('#serverStatus').text('Offline').removeClass('bg-success').addClass('bg-danger');
        }
    });
}

// Refresh implant list
function refreshImplantList() {
    if ($('#implantList').length) {
        $.ajax({
            url: '/api/dashboard/implants',
            type: 'GET',
            success: function(data) {
                updateImplantTable(data.implants || []);
            }
        });
    }
}

// Update implant table with data
function updateImplantTable(implants) {
    const table = $('#implantList tbody');
    table.empty();
    
    if (implants.length === 0) {
        table.append('<tr><td colspan="7" class="text-center">No implants registered</td></tr>');
        return;
    }
    
    implants.forEach(implant => {
        const isOnline = implant.status === 'active';
        const statusClass = isOnline ? 'success' : 'danger';
        
        const row = `
            <tr class="align-middle">
                <td>
                    <span class="status-dot status-dot-${isOnline ? 'online' : 'offline'}"></span>
                </td>
                <td>${implant.hostname || implant.name || 'Unnamed'}</td>
                <td>${implant.type || 'Unknown'}</td>
                <td>${implant.ip || implant.ip_address || 'Unknown'}</td>
                <td>${implant.os || 'Unknown'}</td>
                <td>${implant.last_seen || 'Unknown'}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <a href="/implant/${implant.id}" class="btn btn-outline-primary">
                            <i class="fas fa-terminal"></i>
                        </a>
                        <button type="button" class="btn btn-outline-danger implant-action" data-action="kill" data-implant-id="${implant.id}">
                            <i class="fas fa-skull"></i>
                        </button>
                        <button type="button" class="btn btn-outline-warning implant-action" data-action="restart" data-implant-id="${implant.id}">
                            <i class="fas fa-redo-alt"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
        
        table.append(row);
    });
    
    // Enable tooltips
    $('[data-bs-toggle="tooltip"]').tooltip();
}

// Socket.IO connection handling
function initSocketIO() {
    if (typeof io !== 'undefined') {
        const socket = io();
        
        socket.on('connect', function() {
            console.log('Socket.IO connected');
            
            // Authenticate socket if we have a token
            if (ErebusAuth.isAuthenticated()) {
                socket.emit('authenticate', {
                    token: ErebusAuth.getToken()
                });
            }
        });
        
        socket.on('authentication_result', function(data) {
            if (data.status === 'success') {
                console.log('Socket.IO authenticated');
            } else {
                console.warn('Socket.IO authentication failed');
            }
        });
        
        socket.on('implant_registered', function(data) {
            ErebusNotifications.success('New Implant', `Implant ${data.hostname || data.implant_id} registered`);
            refreshDashboardData();
        });
        
        socket.on('implant_beacon', function(data) {
            refreshDashboardData();
        });
        
        socket.on('command_queued', function(data) {
            ErebusNotifications.info('Command Queued', `Command ${data.type} queued for execution`);
            refreshDashboardData();
        });
        
        socket.on('command_completed', function(data) {
            ErebusNotifications.success('Command Completed', `Command ${data.type} completed successfully`);
            refreshDashboardData();
        });
        
        socket.on('command_failed', function(data) {
            ErebusNotifications.error('Command Failed', `Command ${data.type} failed: ${data.error}`);
            refreshDashboardData();
        });
        
        socket.on('command_cancelled', function(data) {
            ErebusNotifications.warning('Command Cancelled', `Command ${data.command_id} has been cancelled`);
            refreshDashboardData();
        });
        
        socket.on('disconnect', function() {
            console.warn('Socket.IO disconnected');
        });
        
        return socket;
    }
    
    return null;
}

function refreshDashboardData() {
    updateDashboardHealth();
    refreshImplantList();
    
    // If we have a network visualization, refresh it
    if (typeof initNetworkVisualization === 'function') {
        initNetworkVisualization();
    }
}

// Format timestamps consistently
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (e) {
        return timestamp;
    }
}

// Execute when document is ready
$(document).ready(function() {
    // Initialize tooltips
    $('[data-bs-toggle="tooltip"]').tooltip();
    
    // Initialize popovers
    $('[data-bs-toggle="popover"]').popover();
    
    // Initialize Socket.IO if available
    const socket = initSocketIO();
    
    // Setup login form handling
    $('#loginForm').on('submit', function(e) {
        e.preventDefault();
        
        const username = $('#username').val();
        const password = $('#password').val();
        
        $('#loginSpinner').removeClass('d-none');
        
        ErebusAuth.login(username, password).then(success => {
            if (success) {
                window.location.href = '/';
            } else {
                $('#loginError').text('Invalid username or password').removeClass('d-none');
                $('#loginSpinner').addClass('d-none');
            }
        }).catch(error => {
            $('#loginError').text('Login failed: ' + (error.responseJSON?.message || error.statusText || 'Unknown error')).removeClass('d-none');
            $('#loginSpinner').addClass('d-none');
        });
    });
    
    // Setup logout button
    $('#logoutBtn').on('click', function(e) {
        e.preventDefault();
        ErebusAuth.logout();
    });
    
    // Update dashboard health immediately and then every 30 seconds
    if ($('.dashboard-overview').length) {
        updateDashboardHealth();
        setInterval(updateDashboardHealth, 30000);
    }
    
    // Setup implant list refresh
    if ($('#implantList').length) {
        refreshImplantList();
        setInterval(refreshImplantList, 30000);
    }
    
    // Implant action buttons
    $(document).on('click', '.implant-action', function() {
        const action = $(this).data('action');
        const implantId = $(this).data('implant-id');
        
        if (confirm(`Are you sure you want to ${action} this implant?`)) {
            $.ajax({
                url: `/api/dashboard/implants/${implantId}/command`,
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    type: action,
                    params: {}
                }),
                success: function(response) {
                    ErebusNotifications.success('Success', `Implant ${action} command sent successfully.`);
                    setTimeout(refreshImplantList, 2000);
                },
                error: function(xhr) {
                    ErebusNotifications.error('Error', `Failed to ${action} implant: ${xhr.responseJSON?.error || 'Unknown error'}`);
                }
            });
        }
    });
});

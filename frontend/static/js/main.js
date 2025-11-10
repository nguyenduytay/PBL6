/**
 * Malware Detector - Main JavaScript
 * Orchestrates all modules and UI interactions
 */

// Import modules (using ES6 modules - will need to be bundled or use type="module")
import { formatFileSize, formatDate, copyToClipboard, showToast } from './modules/utils.js';
import { chartManager } from './modules/charts.js';
import { uploadManager } from './modules/upload.js';
import { apiClient } from './modules/api.js';

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initSidebar();
    initNavigation();
    initTabs();
    initAlerts();
    initTimeDisplay();
    initFileUpload();
    
    // Make utilities globally available for backward compatibility
    window.formatFileSize = formatFileSize;
    window.formatDate = formatDate;
    window.copyToClipboard = copyToClipboard;
    window.showToast = showToast;
    window.chartManager = chartManager;
    window.uploadManager = uploadManager;
    window.apiClient = apiClient;
});

/**
 * Initialize sidebar toggle for mobile
 */
function initSidebar() {
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('-translate-x-full');
        });
    }
    
    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', (e) => {
        if (window.innerWidth < 1024) {
            if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
                sidebar.classList.add('-translate-x-full');
            }
        }
    });
}

/**
 * Initialize active navigation state
 */
function initNavigation() {
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll('.nav-item[data-page]');
    
    navItems.forEach(item => {
        const page = item.getAttribute('data-page');
        if (
            (page === 'dashboard' && currentPath === '/') ||
            (page === 'submit' && currentPath === '/submit') ||
            (page === 'analyses' && currentPath.startsWith('/analyses'))
        ) {
            item.classList.add('active');
        }
    });
}

/**
 * Initialize tab functionality
 */
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.getAttribute('data-tab');
            
            // Remove active from all tabs and contents
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            // Add active to clicked tab and corresponding content
            tab.classList.add('active');
            const content = document.getElementById(`tab-${tabName}`);
            if (content) {
                content.classList.add('active');
            }
        });
    });
}

/**
 * Initialize auto-hide alerts
 */
function initAlerts() {
    const alerts = document.querySelectorAll('.alert:not(.alert-dismissible)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
}

/**
 * Initialize current time display
 */
function initTimeDisplay() {
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        function updateTime() {
            const now = new Date();
            timeElement.textContent = now.toLocaleTimeString('vi-VN', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
        
        updateTime();
        setInterval(updateTime, 1000);
    }
}

/**
 * Initialize file upload (backward compatibility)
 */
function initFileUpload() {
    const fileInput = document.getElementById("fileInput");
    const fileName = document.getElementById("fileName");
    const folderInput = document.getElementById("folderInput");
    const folderName = document.getElementById("folderName");

    if (fileInput && fileName) {
        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                fileName.textContent = fileInput.files[0].name;
            } else {
                fileName.textContent = "Chưa chọn file";
            }
        });
    }

    if (folderInput && folderName) {
        folderInput.addEventListener("change", () => {
            if (folderInput.files.length > 0) {
                folderName.textContent = `${folderInput.files.length} file đã chọn`;
            } else {
                folderName.textContent = "Chưa chọn folder";
            }
        });
    }
}

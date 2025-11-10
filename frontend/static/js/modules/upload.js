/**
 * File Upload Module
 * Handles file upload with drag & drop and progress tracking
 */

import { formatFileSize, showToast } from './utils.js';

export class FileUploadManager {
    constructor(options = {}) {
        this.options = {
            maxFileSize: options.maxFileSize || 100 * 1024 * 1024, // 100MB
            allowedTypes: options.allowedTypes || [],
            onProgress: options.onProgress || null,
            onSuccess: options.onSuccess || null,
            onError: options.onError || null,
            ...options
        };
        
        this.uploadZone = null;
        this.fileInput = null;
        this.progressBar = null;
        this.init();
    }
    
    init() {
        this.uploadZone = document.getElementById('file-upload-zone');
        this.fileInput = document.getElementById('file-input');
        this.progressBar = document.getElementById('upload-progress');
        
        if (this.uploadZone) {
            this.setupDragAndDrop();
        }
        
        if (this.fileInput) {
            this.fileInput.addEventListener('change', (e) => {
                this.handleFiles(e.target.files);
            });
        }
    }
    
    setupDragAndDrop() {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            this.uploadZone.addEventListener(eventName, this.preventDefaults, false);
        });
        
        ['dragenter', 'dragover'].forEach(eventName => {
            this.uploadZone.addEventListener(eventName, () => {
                this.uploadZone.classList.add('dragover');
            }, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            this.uploadZone.addEventListener(eventName, () => {
                this.uploadZone.classList.remove('dragover');
            }, false);
        });
        
        this.uploadZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            this.handleFiles(files);
        }, false);
    }
    
    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    handleFiles(files) {
        if (files.length === 0) return;
        
        const file = files[0];
        
        // Validate file size
        if (file.size > this.options.maxFileSize) {
            showToast(`File quá lớn! Tối đa ${formatFileSize(this.options.maxFileSize)}`, 'error');
            return;
        }
        
        // Validate file type
        if (this.options.allowedTypes.length > 0) {
            const isValidType = this.options.allowedTypes.some(type => {
                return file.type.includes(type) || file.name.endsWith(type);
            });
            
            if (!isValidType) {
                showToast('Loại file không được hỗ trợ!', 'error');
                return;
            }
        }
        
        // Update UI
        this.updateFileInfo(file);
        
        // Trigger upload if auto-upload is enabled
        if (this.options.autoUpload) {
            this.uploadFile(file);
        }
    }
    
    updateFileInfo(file) {
        const fileNameEl = document.getElementById('file-name');
        const fileSizeEl = document.getElementById('file-size');
        
        if (fileNameEl) {
            fileNameEl.textContent = file.name;
        }
        
        if (fileSizeEl) {
            fileSizeEl.textContent = formatFileSize(file.size);
        }
    }
    
    async uploadFile(file, endpoint = '/submit') {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const xhr = new XMLHttpRequest();
            
            // Progress tracking
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    this.updateProgress(percentComplete);
                    
                    if (this.options.onProgress) {
                        this.options.onProgress(percentComplete);
                    }
                }
            });
            
            // Handle completion
            xhr.addEventListener('load', () => {
                if (xhr.status === 200) {
                    this.updateProgress(100);
                    const response = JSON.parse(xhr.responseText);
                    
                    if (this.options.onSuccess) {
                        this.options.onSuccess(response);
                    } else {
                        // Default: redirect to analysis detail
                        if (response.analysis_id) {
                            window.location.href = `/analyses/${response.analysis_id}`;
                        }
                    }
                } else {
                    this.handleError('Upload failed');
                }
            });
            
            // Handle errors
            xhr.addEventListener('error', () => {
                this.handleError('Network error');
            });
            
            xhr.open('POST', endpoint);
            xhr.send(formData);
            
        } catch (error) {
            this.handleError(error.message);
        }
    }
    
    updateProgress(percent) {
        if (this.progressBar) {
            this.progressBar.style.width = `${percent}%`;
            this.progressBar.setAttribute('aria-valuenow', percent);
        }
    }
    
    handleError(message) {
        showToast(message, 'error');
        this.updateProgress(0);
        
        if (this.options.onError) {
            this.options.onError(message);
        }
    }
    
    reset() {
        if (this.fileInput) {
            this.fileInput.value = '';
        }
        
        if (this.progressBar) {
            this.updateProgress(0);
        }
        
        const fileNameEl = document.getElementById('file-name');
        const fileSizeEl = document.getElementById('file-size');
        
        if (fileNameEl) fileNameEl.textContent = '';
        if (fileSizeEl) fileSizeEl.textContent = '';
    }
}

// Export singleton instance
export const uploadManager = new FileUploadManager({
    autoUpload: false
});


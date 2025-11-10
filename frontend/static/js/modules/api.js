/**
 * API Module
 * Handles API requests and responses
 */

import { showToast } from './utils.js';

const API_BASE_URL = '/api/v1';

export class APIClient {
    constructor(baseURL = API_BASE_URL) {
        this.baseURL = baseURL;
    }
    
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        // Remove Content-Type for FormData
        if (options.body instanceof FormData) {
            delete config.headers['Content-Type'];
        }
        
        try {
            const response = await fetch(url, config);
            
            // Handle non-JSON responses
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                return {
                    ok: response.ok,
                    status: response.status,
                    data: await response.text()
                };
            }
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || data.message || 'Request failed');
            }
            
            return {
                ok: true,
                status: response.status,
                data
            };
            
        } catch (error) {
            console.error('API Error:', error);
            showToast(error.message || 'Có lỗi xảy ra', 'error');
            throw error;
        }
    }
    
    async get(endpoint, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, { method: 'GET' });
    }
    
    async post(endpoint, data) {
        const body = data instanceof FormData ? data : JSON.stringify(data);
        return this.request(endpoint, {
            method: 'POST',
            body
        });
    }
    
    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
    
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
    
    // Specific API methods
    async getAnalyses(params = {}) {
        return this.get('/analyses', params);
    }
    
    async getAnalysis(analysisId) {
        return this.get(`/analyses/${analysisId}`);
    }
    
    async submitFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        return this.post('/analyze', formData);
    }
    
    async submitFolder(files) {
        const formData = new FormData();
        files.forEach(file => {
            formData.append('folderFiles', file);
        });
        return this.post('/analyze', formData);
    }
    
    async getHealth() {
        return this.get('/health');
    }
}

// Export singleton instance
export const apiClient = new APIClient();

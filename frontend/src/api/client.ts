/**
 * API Client - Axios instance configuration
 */
import axios, { AxiosInstance, AxiosError } from 'axios'
import { ErrorResponse } from '../datahelper/client.dataHelper'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 seconds
})

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    // Có thể thêm token hoặc headers khác ở đây
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
apiClient.interceptors.response.use(
  (response) => {
    return response
  },
  (error: AxiosError<ErrorResponse>) => {
    // Handle common errors
    if (error.response) {
      const apiError: ErrorResponse = {
        detail: error.response.data?.detail || 'An error occurred',
        status_code: error.response.status,
      }
      return Promise.reject(apiError)
    } else if (error.request) {
      const apiError: ErrorResponse = {
        detail: 'Network error. Please check your connection.',
      }
      return Promise.reject(apiError)
    } else {
      const apiError: ErrorResponse = {
        detail: error.message || 'An unexpected error occurred',
      }
      return Promise.reject(apiError)
    }
  }
)

export default apiClient


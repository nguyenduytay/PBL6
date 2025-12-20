/**
 * Axios Client - Axios instance configuration
 * Theo chuẩn front-bks-system với interceptors, token handling, language support
 */
import axios, { AxiosError, AxiosInstance } from 'axios'
import { ErrorResponse } from './types'
import { API_BASE_URL, API_TIMEOUT } from '../constants'

const axiosClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: API_TIMEOUT,
})

// Request interceptor
axiosClient.interceptors.request.use(
  (config) => {
    // TODO: Thêm token nếu có authentication
    // const token = getAccessToken()
    // if (token && !isTokenExpired(token)) {
    //   config.headers.Authorization = `Bearer ${token}`
    // }

    // TODO: Thêm language header nếu có i18n
    // config.headers['Accept-Language'] = getLanguageStorage() || 'vi'

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
axiosClient.interceptors.response.use(
  (response) => {
    // Xử lý response theo format của backend
    // Nếu backend trả về { code: 401 }, redirect về login
    if (response.data?.code === 401) {
      // TODO: Handle logout và redirect nếu có authentication
      // if (useUserStore.getState().isAuthenticated) {
      //   useUserStore.getState().logout()
      //   window.location.href = ROUTERS.LOGIN
      // }
    }
    // Trả về data trực tiếp nếu backend wrap trong data field
    return response.data ?? response
  },
  (error: AxiosError<ErrorResponse>) => {
    // Handle common errors
    if (error.response?.data?.code === 401) {
      // TODO: Handle logout và redirect nếu có authentication
      // if (useUserStore.getState().isAuthenticated) {
      //   useUserStore.getState().logout()
      //   window.location.href = ROUTERS.LOGIN
      // }
    }

    if (error.response) {
      const apiError: ErrorResponse = {
        code: error.response.status,
        message: error.response.data?.message || error.response.data?.detail || 'An error occurred',
        detail: error.response.data?.detail || error.response.data?.message || 'An error occurred',
        status_code: error.response.status,
        errors: error.response.data?.errors,
      }
      return Promise.reject(apiError)
    } else if (error.request) {
      const apiError: ErrorResponse = {
        message: 'Network error. Please check your connection.',
        detail: 'Network error. Please check your connection.',
      }
      return Promise.reject(apiError)
    } else {
      const apiError: ErrorResponse = {
        message: error.message || 'An unexpected error occurred',
        detail: error.message || 'An unexpected error occurred',
      }
      return Promise.reject(apiError)
    }
  }
)

export default axiosClient


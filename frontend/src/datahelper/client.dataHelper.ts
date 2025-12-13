/**
 * Client DataHelper - Types cho API Client
 * Tương ứng với api/client.ts
 */

/**
 * Error response - Dùng chung cho tất cả API
 */
export interface ErrorResponse {
  detail: string
  status_code?: number
  errors?: Record<string, string[]>
}

/**
 * Paginated response wrapper - Dùng chung
 */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

/**
 * Standard API response wrapper - Dùng chung
 */
export interface ApiResponse<T> {
  success: boolean
  data?: T
  message?: string
  error?: string
}


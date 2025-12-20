/**
 * Client DataHelper - Types cho API Client
 * Tương ứng với api/client.ts
 * 
 * NOTE: ErrorResponse, ApiResponse, Paginator đã được di chuyển sang api/types.ts
 * Giữ lại file này để backward compatibility, nhưng nên import từ api/types.ts
 */

// Re-export từ api/types.ts để backward compatibility
export type { ErrorResponse, ApiResponse, Paginator } from '../api/types'

/**
 * Paginated response wrapper - Dùng chung (custom format nếu cần)
 */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}


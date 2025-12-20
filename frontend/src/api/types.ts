/**
 * API Types - Common types for all API responses
 * Theo chuẩn front-bks-system
 */

/**
 * Paginator - Laravel-style pagination response
 */
export interface Paginator<T> {
  current_page: number;
  data: T[];
  first_page_url?: string | null;
  from?: number | null;
  last_page?: number;
  last_page_url?: string | null;
  next_page_url?: string | null;
  path?: string;
  per_page?: number;
  prev_page_url?: string | null;
  to?: number | null;
  total: number;
}

/**
 * ApiResponse - Standard API response wrapper
 */
export interface ApiResponse<T> {
  status: string;
  message: string;
  data?: T;
  errors: {
    [key: string]: string[];
  };
}

/**
 * ErrorResponse - Standard error response
 */
export interface ErrorResponse {
  code?: number;
  message?: string;
  detail?: string;
  status_code?: number;
  errors?: {
    [key: string]: string[];
  };
}


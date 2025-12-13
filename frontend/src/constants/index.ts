/**
 * Application Constants
 * Centralized location for all constants used across the application
 */

// ==================== API Configuration ====================
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'
export const API_TIMEOUT = 30000 // 30 seconds

// ==================== File Upload Limits ====================
export const MAX_UPLOAD_SIZE_GB = 2
export const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_GB * 1024 * 1024 * 1024

// ==================== Pagination ====================
export const DEFAULT_PAGE_LIMIT = 20
export const DEFAULT_EXPORT_LIMIT = 1000
export const PAGE_LIMIT_OPTIONS = [1, 2, 3, 5, 10, 20, 50, 100]

// ==================== File Formats ====================
export const SUPPORTED_ARCHIVE_FORMATS = [
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.tar.gz',
  '.tar.bz2'
] as const

export const SUPPORTED_ARCHIVE_MIME_TYPES = [
  'application/zip',
  'application/x-tar',
  'application/gzip',
  'application/x-bzip2'
] as const

// ==================== Date & Time ====================
export const DATE_FORMAT = 'vi-VN' // Locale for date formatting
export const DATE_TIME_FORMAT = {
  date: 'dd/MM/yyyy',
  time: 'HH:mm:ss',
  datetime: 'dd/MM/yyyy HH:mm:ss'
} as const

// ==================== UI Configuration ====================
export const DEBOUNCE_DELAY = 300 // milliseconds
export const THROTTLE_DELAY = 1000 // milliseconds
export const ANIMATION_DURATION = 200 // milliseconds

// ==================== Rating System ====================
export const MIN_RATING = 1
export const MAX_RATING = 5
export const DEFAULT_RATING = 5

// ==================== Analysis Display ====================
export const MAX_SUSPICIOUS_STRINGS_DISPLAY = 50
export const MAX_FILENAME_LENGTH = 50
export const MAX_SHA256_DISPLAY_LENGTH = 16

// ==================== Storage Keys ====================
export const STORAGE_KEYS = {
  LANGUAGE: 'language',
  THEME: 'theme',
  SIDEBAR_COLLAPSED: 'sidebarCollapsed'
} as const

// ==================== Routes ====================
export const ROUTES = {
  DASHBOARD: '/',
  UPLOAD: '/upload',
  ANALYSES: '/analyses',
  ANALYSIS_DETAIL: (id: number | string) => `/analyses/${id}`,
  BATCH_SCAN: '/batch-scan',
  SEARCH: '/search'
} as const

// ==================== Export Formats ====================
export const EXPORT_FORMATS = {
  CSV: 'csv',
  JSON: 'json',
  EXCEL: 'xlsx'
} as const

// ==================== Badge Variants ====================
export const BADGE_VARIANTS = {
  SUCCESS: 'success',
  DANGER: 'danger',
  WARNING: 'warning',
  INFO: 'info'
} as const

// ==================== Button Variants ====================
export const BUTTON_VARIANTS = {
  PRIMARY: 'primary',
  SECONDARY: 'secondary',
  DANGER: 'danger',
  OUTLINE: 'outline'
} as const

// ==================== Status Types ====================
export const BATCH_STATUS = {
  PENDING: 'pending',
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  FAILED: 'failed'
} as const

export const ANALYSIS_STATUS = {
  CLEAN: 'clean',
  MALWARE: 'malware'
} as const


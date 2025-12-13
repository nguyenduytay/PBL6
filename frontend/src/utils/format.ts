/**
 * Formatting utility functions
 */
import { MAX_FILENAME_LENGTH, MAX_SHA256_DISPLAY_LENGTH } from '../constants'

/**
 * Truncate string to specified length with ellipsis
 * @param str - String to truncate
 * @param maxLength - Maximum length (default: 50)
 * @param suffix - Suffix to add when truncated (default: "...")
 * @returns Truncated string
 */
export const truncateString = (
  str: string | null | undefined,
  maxLength: number = MAX_FILENAME_LENGTH,
  suffix: string = '...'
): string => {
  if (!str) return '-'
  if (str.length <= maxLength) return str
  return str.substring(0, maxLength - suffix.length) + suffix
}

/**
 * Truncate hash (SHA256, MD5) for display
 * @param hash - Hash string
 * @param startLength - Length of characters to show at start (default: 8)
 * @param endLength - Length of characters to show at end (default: 8)
 * @returns Truncated hash (e.g., "abc12345...xyz67890")
 */
export const truncateHash = (
  hash: string | null | undefined,
  startLength: number = MAX_SHA256_DISPLAY_LENGTH,
  endLength: number = MAX_SHA256_DISPLAY_LENGTH
): string => {
  if (!hash) return '-'
  if (hash.length <= startLength + endLength) return hash
  return `${hash.substring(0, startLength)}...${hash.substring(hash.length - endLength)}`
}

/**
 * Format number with thousand separators
 * @param num - Number to format
 * @param decimals - Number of decimal places (default: 0)
 * @returns Formatted number string (e.g., "1,234.56")
 */
export const formatNumber = (num: number | null | undefined, decimals: number = 0): string => {
  if (num === null || num === undefined || isNaN(num)) return '-'
  return num.toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  })
}

/**
 * Format percentage
 * @param value - Value to format as percentage
 * @param decimals - Number of decimal places (default: 1)
 * @returns Formatted percentage string (e.g., "45.5%")
 */
export const formatPercentage = (value: number | null | undefined, decimals: number = 1): string => {
  if (value === null || value === undefined || isNaN(value)) return '-'
  return `${value.toFixed(decimals)}%`
}

/**
 * Format analysis time in seconds
 * @param seconds - Time in seconds
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted time string (e.g., "1.23s")
 */
export const formatAnalysisTime = (seconds: number | null | undefined, decimals: number = 2): string => {
  if (seconds === null || seconds === undefined || isNaN(seconds)) return '-'
  return `${seconds.toFixed(decimals)}s`
}

/**
 * Capitalize first letter of string
 * @param str - String to capitalize
 * @returns Capitalized string
 */
export const capitalize = (str: string | null | undefined): string => {
  if (!str) return ''
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase()
}

/**
 * Convert string to title case
 * @param str - String to convert
 * @returns Title case string (e.g., "hello world" -> "Hello World")
 */
export const toTitleCase = (str: string | null | undefined): string => {
  if (!str) return ''
  return str.replace(/\w\S*/g, (txt) => {
    return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
  })
}


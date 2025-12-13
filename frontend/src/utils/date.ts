/**
 * Date and time utility functions
 */
import { DATE_FORMAT } from '../constants'

/**
 * Format date to locale string
 * @param date - Date object or date string
 * @param options - Intl.DateTimeFormatOptions
 * @returns Formatted date string
 */
export const formatDate = (
  date: Date | string | null | undefined,
  options?: Intl.DateTimeFormatOptions
): string => {
  if (!date) return '-'
  
  const dateObj = typeof date === 'string' ? new Date(date) : date
  
  if (isNaN(dateObj.getTime())) return '-'
  
  const defaultOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...options
  }
  
  return dateObj.toLocaleDateString(DATE_FORMAT, defaultOptions)
}

/**
 * Format date and time to locale string
 * @param date - Date object or date string
 * @param includeSeconds - Whether to include seconds (default: true)
 * @returns Formatted date-time string
 */
export const formatDateTime = (
  date: Date | string | null | undefined,
  includeSeconds: boolean = true
): string => {
  if (!date) return '-'
  
  const dateObj = typeof date === 'string' ? new Date(date) : date
  
  if (isNaN(dateObj.getTime())) return '-'
  
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: includeSeconds ? '2-digit' : undefined
  }
  
  return dateObj.toLocaleString(DATE_FORMAT, options)
}

/**
 * Format time elapsed (e.g., "2 hours ago", "5 minutes ago")
 * @param date - Date object or date string
 * @returns Formatted relative time string
 */
export const formatTimeAgo = (date: Date | string | null | undefined): string => {
  if (!date) return '-'
  
  const dateObj = typeof date === 'string' ? new Date(date) : date
  
  if (isNaN(dateObj.getTime())) return '-'
  
  const now = new Date()
  const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000)
  
  if (diffInSeconds < 60) return 'Just now'
  if (diffInSeconds < 3600) {
    const minutes = Math.floor(diffInSeconds / 60)
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`
  }
  if (diffInSeconds < 86400) {
    const hours = Math.floor(diffInSeconds / 3600)
    return `${hours} hour${hours > 1 ? 's' : ''} ago`
  }
  if (diffInSeconds < 604800) {
    const days = Math.floor(diffInSeconds / 86400)
    return `${days} day${days > 1 ? 's' : ''} ago`
  }
  
  return formatDate(dateObj)
}

/**
 * Check if date is today
 * @param date - Date object or date string
 * @returns Boolean indicating if date is today
 */
export const isToday = (date: Date | string | null | undefined): boolean => {
  if (!date) return false
  
  const dateObj = typeof date === 'string' ? new Date(date) : date
  const today = new Date()
  
  return (
    dateObj.getDate() === today.getDate() &&
    dateObj.getMonth() === today.getMonth() &&
    dateObj.getFullYear() === today.getFullYear()
  )
}

/**
 * Check if date is within last N days
 * @param date - Date object or date string
 * @param days - Number of days (default: 1)
 * @returns Boolean indicating if date is within last N days
 */
export const isWithinLastDays = (date: Date | string | null | undefined, days: number = 1): boolean => {
  if (!date) return false
  
  const dateObj = typeof date === 'string' ? new Date(date) : date
  const now = new Date()
  const diffInMs = now.getTime() - dateObj.getTime()
  const diffInDays = diffInMs / (1000 * 60 * 60 * 24)
  
  return diffInDays >= 0 && diffInDays <= days
}


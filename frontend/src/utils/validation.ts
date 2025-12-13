/**
 * Validation utility functions
 */
import { MIN_RATING, MAX_RATING } from '../constants'

/**
 * Validate email format
 * @param email - Email string to validate
 * @returns Boolean indicating if email is valid
 */
export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/**
 * Validate SHA256 hash format
 * @param hash - Hash string to validate
 * @returns Boolean indicating if hash is valid SHA256
 */
export const isValidSHA256 = (hash: string): boolean => {
  const sha256Regex = /^[a-f0-9]{64}$/i
  return sha256Regex.test(hash)
}

/**
 * Validate MD5 hash format
 * @param hash - Hash string to validate
 * @returns Boolean indicating if hash is valid MD5
 */
export const isValidMD5 = (hash: string): boolean => {
  const md5Regex = /^[a-f0-9]{32}$/i
  return md5Regex.test(hash)
}

/**
 * Validate rating value
 * @param rating - Rating value to validate
 * @returns Boolean indicating if rating is valid
 */
export const isValidRating = (rating: number): boolean => {
  return Number.isInteger(rating) && rating >= MIN_RATING && rating <= MAX_RATING
}

/**
 * Validate if string is not empty
 * @param str - String to validate
 * @param trim - Whether to trim the string before validation (default: true)
 * @returns Boolean indicating if string is not empty
 */
export const isNotEmpty = (str: string | null | undefined, trim: boolean = true): boolean => {
  if (!str) return false
  return trim ? str.trim().length > 0 : str.length > 0
}

/**
 * Validate if value is a valid number
 * @param value - Value to validate
 * @returns Boolean indicating if value is a valid number
 */
export const isValidNumber = (value: any): value is number => {
  return typeof value === 'number' && !isNaN(value) && isFinite(value)
}

/**
 * Validate if value is a positive number
 * @param value - Value to validate
 * @returns Boolean indicating if value is a positive number
 */
export const isPositiveNumber = (value: any): boolean => {
  return isValidNumber(value) && value > 0
}

/**
 * Validate if value is a non-negative number
 * @param value - Value to validate
 * @returns Boolean indicating if value is a non-negative number
 */
export const isNonNegativeNumber = (value: any): boolean => {
  return isValidNumber(value) && value >= 0
}


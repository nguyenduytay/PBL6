/**
 * File-related utility functions
 */
import { MAX_UPLOAD_SIZE_BYTES, MAX_UPLOAD_SIZE_GB } from '../constants'

/**
 * Format file size from bytes to human-readable format
 * @param bytes - File size in bytes
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted string (e.g., "1.5 MB", "2.0 GB")
 */
export const formatFileSize = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return '0 Bytes'

  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']

  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

/**
 * Format file size to GB (or appropriate unit if smaller)
 * @param bytes - File size in bytes
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted string in GB (e.g., "1.5 GB") or smaller unit if file is small
 */
export const formatFileSizeGB = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return '0 Bytes'
  
  const k = 1024
  const gb = bytes / (k * k * k)
  
  // If less than 1 GB, use appropriate smaller unit
  if (gb < 1) {
    const mb = bytes / (k * k)
    if (mb < 1) {
      const kb = bytes / k
      if (kb < 1) {
        return `${bytes} Bytes`
      }
      return `${parseFloat(kb.toFixed(decimals))} KB`
    }
    return `${parseFloat(mb.toFixed(decimals))} MB`
  }
  
  return `${gb.toFixed(decimals)} GB`
}

/**
 * Validate if file size is within allowed limit
 * @param fileSize - File size in bytes
 * @returns Object with isValid boolean and error message if invalid
 */
export const validateFileSize = (fileSize: number): { isValid: boolean; error?: string } => {
  if (fileSize > MAX_UPLOAD_SIZE_BYTES) {
    const sizeGB = formatFileSizeGB(fileSize)
    return {
      isValid: false,
      error: `File size (${sizeGB}) exceeds maximum allowed size (${MAX_UPLOAD_SIZE_GB} GB)`
    }
  }
  return { isValid: true }
}

/**
 * Validate if multiple files total size is within allowed limit
 * @param files - Array of File objects
 * @returns Object with isValid boolean and error message if invalid
 */
export const validateFilesTotalSize = (files: File[]): { isValid: boolean; error?: string; totalSize?: number } => {
  const totalSize = files.reduce((sum, file) => sum + file.size, 0)
  const validation = validateFileSize(totalSize)
  
  if (!validation.isValid) {
    return {
      ...validation,
      totalSize
    }
  }
  
  return {
    isValid: true,
    totalSize
  }
}

/**
 * Get file extension from filename
 * @param filename - File name
 * @returns File extension (e.g., "pdf", "zip") or empty string
 */
export const getFileExtension = (filename: string): string => {
  const parts = filename.split('.')
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : ''
}

/**
 * Check if file extension is in the allowed list
 * @param filename - File name
 * @param allowedExtensions - Array of allowed extensions (without dot)
 * @returns Boolean indicating if extension is allowed
 */
export const isFileExtensionAllowed = (filename: string, allowedExtensions: string[]): boolean => {
  const extension = getFileExtension(filename)
  return allowedExtensions.some(ext => ext.toLowerCase() === extension.toLowerCase())
}

/**
 * Filter files by extension
 * @param files - Array of File objects
 * @param extensions - Array of allowed extensions (e.g., ["pdf", "doc"])
 * @returns Filtered array of File objects
 */
export const filterFilesByExtension = (files: File[], extensions: string[]): File[] => {
  if (extensions.length === 0) return files
  
  const normalizedExtensions = extensions.map(ext => ext.trim().toLowerCase().replace(/^\./, ''))
  
  return files.filter(file => {
    const fileExt = getFileExtension(file.name)
    return normalizedExtensions.includes(fileExt)
  })
}

/**
 * Get folder name from file path (webkitRelativePath)
 * @param file - File object with webkitRelativePath
 * @returns Folder name or empty string
 */
export const getFolderNameFromFile = (file: File): string => {
  const path = (file as any).webkitRelativePath || file.name
  return path.split('/')[0] || ''
}


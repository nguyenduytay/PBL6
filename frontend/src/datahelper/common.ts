/**
 * Common Types - Các kiểu dữ liệu dùng chung
 */

/**
 * YARA match information
 */
export interface YaraMatch {
  rule_name: string
  tags?: string[]
  description?: string
}

/**
 * PE file information
 */
export interface PEInfo {
  [key: string]: any
  // Có thể định nghĩa chi tiết hơn:
  // machine?: string
  // timestamp?: string
  // sections?: PESection[]
  // imports?: string[]
  // exports?: string[]
}

/**
 * PE Section information
 */
export interface PESection {
  name: string
  virtual_address: number
  virtual_size: number
  raw_size: number
  characteristics: string[]
}

/**
 * File hash information
 */
export interface FileHash {
  md5: string
  sha1: string
  sha256: string
}

/**
 * Analysis status
 */
export type AnalysisStatus = 'pending' | 'processing' | 'completed' | 'failed'

/**
 * Malware detection result
 */
export interface MalwareDetection {
  detected: boolean
  confidence?: number
  threat_level?: 'low' | 'medium' | 'high' | 'critical'
  indicators?: string[]
}

/**
 * File metadata
 */
export interface FileMetadata {
  filename: string
  size: number
  mime_type?: string
  extension?: string
  created_at?: string
  modified_at?: string
}


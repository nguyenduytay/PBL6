/**
 * Scan DataHelper - Types cho Scan API
 * Tương ứng với api/scan.ts
 */

import { YaraMatch, PEInfo } from './common'

/**
 * Request Types cho Scan API
 */
export interface ScanFileRequest {
  file: File
}

/**
 * Response Types cho Scan API
 */

/**
 * Scan result item - Chi tiết từng phát hiện (Hash, YARA, EMBER)
 */
export interface ScanResultItem {
  type: string // 'hash', 'yara', 'model', 'ember_error', 'clean', etc.
  subtype?: string // 'ember', etc.
  message?: string
  score?: number
  threshold?: number
  error?: string
  error_detail?: string
  error_type?: string
  file_path?: string
  infoUrl?: string | null
  [key: string]: any
}

/**
 * Scan file response - POST /scan
 */
export interface ScanResponse {
  id?: number
  filename: string
  sha256: string
  md5?: string
  file_size?: number
  analysis_time: number
  malware_detected: boolean
  yara_matches?: YaraMatch[]
  pe_info?: PEInfo
  suspicious_strings?: string[]
  capabilities?: Record<string, any>
  results?: ScanResultItem[] // Chi tiết các phát hiện (Hash, YARA, EMBER)
}


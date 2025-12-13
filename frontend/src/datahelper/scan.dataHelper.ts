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
}


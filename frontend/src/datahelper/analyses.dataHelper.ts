/**
 * Analyses Data Helper - Type definitions for Analyses API
 */
import { YaraMatch } from './common'
import { ScanResultItem } from './scan.dataHelper'

/**
 * Analysis List Item Response
 */
export interface AnalysisListItemResponse {
  id: number
  filename: string
  sha256: string | null
  md5: string | null
  file_size: number | null
  analysis_time: number | null
  malware_detected: boolean
  created_at: string
  upload_time: string | null
  yara_matches: YaraMatch[]
  suspicious_strings: string[]
  capabilities: any[]
  pe_info: any | null
}

/**
 * Analysis Detail Response
 */
export interface AnalysisDetailResponse extends AnalysisListItemResponse {
  // Additional fields for detail view
  results?: ScanResultItem[] // Chi tiết các phát hiện (Hash, YARA, EMBER)
}

/**
 * Get Analyses Request
 */
export interface GetAnalysesRequest {
  limit?: number
  offset?: number
}

/**
 * Get Analyses Response with Pagination
 */
export interface GetAnalysesResponse {
  items: AnalysisListItemResponse[]
  total: number
  limit: number
  offset: number
}

/**
 * Analysis Stats Response
 */
export interface AnalysisStatsResponse {
  total_analyses: number
  malware_detected: number
  clean_files: number
  recent_24h: number
}

/**
 * Analyses DataHelper - Types cho Analyses API
 * Tương ứng với api/analyses.ts
 */

import { YaraMatch, PEInfo } from './common'

/**
 * Request Types cho Analyses API
 */
export interface GetAnalysesRequest {
  limit?: number
  offset?: number
}

export interface GetAnalysisByIdRequest {
  id: number
}

export interface GetAnalysisBySha256Request {
  sha256: string
}

export interface AnalysisFilterRequest {
  malware_detected?: boolean
  start_date?: string
  end_date?: string
  limit?: number
  offset?: number
}

/**
 * Response Types cho Analyses API
 */

/**
 * Analysis detail response (full) - GET /analyses/:id
 */
export interface AnalysisDetailResponse {
  id: number
  filename: string
  sha256: string | null
  md5: string | null
  file_size: number | null
  upload_time: string | null
  analysis_time: number
  malware_detected: boolean
  yara_matches: YaraMatch[] | null
  pe_info: PEInfo | null
  suspicious_strings: string[] | null
  capabilities: Record<string, any> | null
  created_at: string
}

/**
 * Analysis list item response (summary) - GET /analyses
 */
export interface AnalysisListItemResponse {
  id: number
  filename: string
  sha256: string | null
  md5: string | null
  file_size: number | null
  upload_time: string | null
  analysis_time: number
  malware_detected: boolean
  created_at: string
}

/**
 * Analysis stats response - GET /analyses/stats/summary
 */
export interface AnalysisStatsResponse {
  total_analyses: number
  malware_detected: number
  clean_files: number
  recent_24h: number
}


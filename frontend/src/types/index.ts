/**
 * Type definitions cho Malware Detector Application
 */

// Analysis Types
export interface Analysis {
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
  results?: Array<{
    type: string
    subtype?: string
    message?: string
    score?: number
    threshold?: number
    error?: string
    error_detail?: string
    error_type?: string
    file_path?: string
    infoUrl?: string | null
    [key: string]: any
  }>
  created_at: string
}

export interface YaraMatch {
  rule_name: string
  tags?: string[] | string
  description?: string
  author?: string
  reference?: string
  matched_strings?: MatchedString[]
}

export interface MatchedString {
  identifier?: string
  offset?: number
  data?: string
  data_preview?: string
}

export interface PEInfo {
  [key: string]: any
}

// API Response Types
export interface ScanResult {
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

export interface AnalysisResponse {
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

export interface AnalysisStats {
  total_analyses: number
  malware_detected: number
  clean_files: number
  recent_24h: number
}

export interface HealthCheck {
  status: 'healthy' | 'unhealthy'
  message?: string
  yara_rules_loaded?: boolean
  yara_rule_count?: number
}

// API Error Types
export interface ApiError {
  detail: string
  status_code?: number
}

// Pagination Types
export interface PaginationParams {
  limit?: number
  offset?: number
}

// File Upload Types
export interface FileUploadResponse {
  success: boolean
  message?: string
  data?: ScanResult
}


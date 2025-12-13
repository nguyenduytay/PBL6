/**
 * Batch Scan DataHelper - Types cho Batch Scan API
 * Tương ứng với api/scan/batch và api/scan/folder
 */

/**
 * Request Types cho Batch Scan API
 */
export interface BatchScanFolderRequest {
  folder_path?: string
  file_extensions?: string[]
  max_files?: number
}

/**
 * Response Types cho Batch Scan API
 */
export interface BatchScanResponse {
  batch_id: string
  total_files: number
  status: 'pending' | 'processing' | 'completed' | 'failed'
  processed: number
  completed: number
  failed: number
}

export interface BatchScanResult {
  batch_id: string
  status: string
  total_files: number
  processed: number
  completed: number
  failed: number
  results: Array<{
    filename: string
    sha256: string | null
    malware_detected: boolean
    analysis_id: number | null
  }>
  errors: Array<{
    filename: string
    error: string
  }>
}


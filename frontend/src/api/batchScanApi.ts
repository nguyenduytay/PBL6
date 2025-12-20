/**
 * Batch Scan API - Batch scanning endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'
import { BatchScanResponse, BatchScanResult, BatchScanFolderRequest } from '../datahelper/batchScan.dataHelper'

export const batchScanApi = {
  /**
   * Scan folder (server-side path)
   * @param request - BatchScanFolderRequest
   * @returns BatchScanResponse
   */
  scanFolder: async (request: BatchScanFolderRequest): Promise<BatchScanResponse> => {
    const response = await axiosClient.post<BatchScanResponse>('/scan/folder', request)
    return response as unknown as BatchScanResponse
  },

  /**
   * Scan folder upload (client-side folder selection)
   * @param files - Array of files from folder
   * @returns BatchScanResponse
   */
  scanFolderUpload: async (files: File[]): Promise<BatchScanResponse> => {
    const formData = new FormData()
    files.forEach((file) => {
      formData.append('files', file)
    })

    const response = await axiosClient.post<BatchScanResponse>('/scan/folder-upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response as unknown as BatchScanResponse
  },

  /**
   * Scan batch (upload archive)
   * @param file - Archive file (zip/tar)
   * @returns BatchScanResponse
   */
  scanBatch: async (file: File): Promise<BatchScanResponse> => {
    const formData = new FormData()
    formData.append('archive', file)

    const response = await axiosClient.post<BatchScanResponse>('/scan/batch', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response as unknown as BatchScanResponse
  },

  /**
   * Get batch scan result
   * @param batchId - Batch ID
   * @returns BatchScanResult
   */
  getBatchResult: async (batchId: string): Promise<BatchScanResult> => {
    const response = await axiosClient.get<BatchScanResult>(`/scan/batch/${batchId}`)
    return response as unknown as BatchScanResult
  },

  /**
   * Get batch scan status
   * @param batchId - Batch ID
   * @returns BatchScanResponse
   */
  getBatchStatus: async (batchId: string): Promise<BatchScanResponse> => {
    const response = await axiosClient.get<BatchScanResponse>(`/scan/batch/${batchId}/status`)
    return response as unknown as BatchScanResponse
  },
}


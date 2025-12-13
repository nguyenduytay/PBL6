/**
 * Batch Scan API - Batch scanning endpoints
 */
import apiClient from './client'
import { BatchScanResponse, BatchScanResult, BatchScanFolderRequest } from '../datahelper/batchScan.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Scan folder (server-side path)
 * @param request - BatchScanFolderRequest
 * @returns BatchScanResponse
 */
export const scanFolder = async (request: BatchScanFolderRequest): Promise<BatchScanResponse> => {
  try {
    const response = await apiClient.post<BatchScanResponse>('/scan/folder', request)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Scan folder upload (client-side folder selection)
 * @param files - Array of files from folder
 * @returns BatchScanResponse
 */
export const scanFolderUpload = async (files: File[]): Promise<BatchScanResponse> => {
  const formData = new FormData()
  files.forEach((file) => {
    formData.append('files', file)
  })

  try {
    const response = await apiClient.post<BatchScanResponse>('/scan/folder-upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Scan batch (upload archive)
 * @param file - Archive file (zip/tar)
 * @returns BatchScanResponse
 */
export const scanBatch = async (file: File): Promise<BatchScanResponse> => {
  const formData = new FormData()
  formData.append('archive', file)

  try {
    const response = await apiClient.post<BatchScanResponse>('/scan/batch', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Get batch scan result
 * @param batchId - Batch ID
 * @returns BatchScanResult
 */
export const getBatchResult = async (batchId: string): Promise<BatchScanResult> => {
  try {
    const response = await apiClient.get<BatchScanResult>(`/scan/batch/${batchId}`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Get batch scan status
 * @param batchId - Batch ID
 * @returns BatchScanResponse
 */
export const getBatchStatus = async (batchId: string): Promise<BatchScanResponse> => {
  try {
    const response = await apiClient.get<BatchScanResponse>(`/scan/batch/${batchId}/status`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


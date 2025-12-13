/**
 * Scan API - File scanning endpoints
 */
import apiClient from './client'
import { ScanResponse } from '../datahelper/scan.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Upload và scan file
 * @param file - File cần scan
 * @returns ScanResponse - Kết quả scan
 */
export const scanFile = async (file: File): Promise<ScanResponse> => {
  const formData = new FormData()
  formData.append('file', file)

  try {
    const response = await apiClient.post<ScanResponse>('/scan', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


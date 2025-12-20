/**
 * Scan API - File scanning endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'
import { ScanResponse } from '../datahelper/scan.dataHelper'

export const scanApi = {
  /**
   * Upload và scan file
   * @param file - File cần scan
   * @returns ScanResponse - Kết quả scan
   */
  scanFile: async (file: File): Promise<ScanResponse> => {
    const formData = new FormData()
    formData.append('file', file)

    const response = await axiosClient.post<ScanResponse>('/scan', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response as unknown as ScanResponse
  },

  /**
   * Scan file chỉ với YARA rules
   * @param file - File cần scan
   * @returns ScanResponse - Kết quả scan YARA
   */
  scanYara: async (file: File): Promise<ScanResponse> => {
    const formData = new FormData()
    formData.append('file', file)

    const response = await axiosClient.post<ScanResponse>('/scan/yara', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response as unknown as ScanResponse
  },

  /**
   * Scan file chỉ với EMBER model
   * @param file - File cần scan
   * @returns ScanResponse - Kết quả scan EMBER
   */
  scanEmber: async (file: File): Promise<ScanResponse> => {
    const formData = new FormData()
    formData.append('file', file)

    const response = await axiosClient.post<ScanResponse>('/scan/ember', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response as unknown as ScanResponse
  },
}


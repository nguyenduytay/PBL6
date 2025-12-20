/**
 * Export API - Export endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'

export const exportApi = {
  /**
   * Export analyses as CSV
   * @param limit - Limit (default: 1000)
   * @param offset - Offset (default: 0)
   * @returns Blob - CSV file
   */
  exportAnalysesCSV: async (limit: number = 1000, offset: number = 0): Promise<Blob> => {
    const params = new URLSearchParams()
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())

    const response = await axiosClient.get(`/export/analyses/csv?${params.toString()}`, {
      responseType: 'blob',
    })
    return response as unknown as Blob
  },

  /**
   * Export analyses as JSON
   * @param limit - Limit (default: 1000)
   * @param offset - Offset (default: 0)
   * @returns JSON data
   */
  exportAnalysesJSON: async (limit: number = 1000, offset: number = 0): Promise<any> => {
    const params = new URLSearchParams()
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())

    const response = await axiosClient.get(`/export/analyses/json?${params.toString()}`)
    return response as unknown as any
  },

  /**
   * Export analyses as Excel (XLSX)
   * @param limit - Limit (default: 1000)
   * @param offset - Offset (default: 0)
   * @returns Blob - Excel file
   */
  exportAnalysesExcel: async (limit: number = 1000, offset: number = 0): Promise<Blob> => {
    const params = new URLSearchParams()
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())

    const response = await axiosClient.get(`/export/analyses/excel?${params.toString()}`, {
      responseType: 'blob',
    })
    return response as unknown as Blob
  },
}


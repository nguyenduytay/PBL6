/**
 * Export API - Export endpoints
 */
import apiClient from './client'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Export analyses as CSV
 * @param limit - Limit
 * @param offset - Offset
 * @returns Blob
 */
export const exportAnalysesCSV = async (limit: number = 1000, offset: number = 0): Promise<Blob> => {
  try {
    const response = await apiClient.get(`/export/analyses/csv?limit=${limit}&offset=${offset}`, {
      responseType: 'blob',
    })
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Export analyses as JSON
 * @param limit - Limit
 * @param offset - Offset
 * @returns JSON data
 */
export const exportAnalysesJSON = async (limit: number = 1000, offset: number = 0): Promise<any> => {
  try {
    const response = await apiClient.get(`/export/analyses/json?limit=${limit}&offset=${offset}`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Export analyses as Excel (XLSX)
 * @param limit - Limit
 * @param offset - Offset
 * @returns Blob
 */
export const exportAnalysesExcel = async (limit: number = 1000, offset: number = 0): Promise<Blob> => {
  try {
    const response = await apiClient.get(`/export/analyses/excel?limit=${limit}&offset=${offset}`, {
      responseType: 'blob',
    })
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}



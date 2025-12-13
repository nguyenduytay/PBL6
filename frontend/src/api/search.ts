/**
 * Search API - Search endpoints
 */
import apiClient from './client'
import { AnalysisListItemResponse } from '../datahelper/analyses.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Search analyses
 * @param query - Search query
 * @param limit - Limit
 * @param offset - Offset
 * @returns AnalysisListItemResponse[]
 */
export const searchAnalyses = async (
  query: string,
  limit: number = 50,
  offset: number = 0
): Promise<AnalysisListItemResponse[]> => {
  try {
    const response = await apiClient.get<AnalysisListItemResponse[]>(
      `/search/analyses?q=${encodeURIComponent(query)}&limit=${limit}&offset=${offset}`
    )
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


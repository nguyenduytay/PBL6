/**
 * Search API - Search endpoints
 */
import apiClient from './client'
import { GetAnalysesResponse } from '../datahelper/analyses.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Search analyses with pagination
 * @param query - Search query
 * @param limit - Limit
 * @param offset - Offset
 * @returns GetAnalysesResponse (items, total, limit, offset)
 */
export const searchAnalyses = async (
  query: string,
  limit: number = 50,
  offset: number = 0
): Promise<GetAnalysesResponse> => {
  try {
    const response = await apiClient.get<GetAnalysesResponse>(
      `/search/analyses?q=${encodeURIComponent(query)}&limit=${limit}&offset=${offset}`
    )
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


/**
 * Search API - Search endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'
import { GetAnalysesResponse } from '../datahelper/analyses.dataHelper'

export const searchApi = {
  /**
   * Search analyses with pagination
   * @param query - Search query
   * @param limit - Limit (default: 50)
   * @param offset - Offset (default: 0)
   * @returns GetAnalysesResponse - Response với items, total, limit, offset
   */
  searchAnalyses: async (query: string, limit: number = 50, offset: number = 0): Promise<GetAnalysesResponse> => {
    const params = new URLSearchParams()
    params.append('q', query)
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())

    const response = await axiosClient.get<GetAnalysesResponse>(`/search/analyses?${params.toString()}`)
    return response as unknown as GetAnalysesResponse
  },
}


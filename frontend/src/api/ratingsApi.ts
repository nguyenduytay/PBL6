/**
 * Ratings API - Rating and review endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'
import {
  CreateRatingRequest,
  UpdateRatingRequest,
  RatingResponse,
  RatingStatsResponse,
} from '../datahelper/ratings.dataHelper'

export const ratingsApi = {
  /**
   * Create rating
   * @param request - CreateRatingRequest
   * @returns RatingResponse
   */
  createRating: async (request: CreateRatingRequest): Promise<RatingResponse> => {
    const response = await axiosClient.post<RatingResponse>('/ratings', request)
    return response as unknown as RatingResponse
  },

  /**
   * Get ratings for analysis
   * @param analysisId - Analysis ID
   * @param limit - Limit (default: 50)
   * @param offset - Offset (default: 0)
   * @returns RatingResponse[]
   */
  getRatings: async (analysisId: number, limit: number = 50, offset: number = 0): Promise<RatingResponse[]> => {
    const params = new URLSearchParams()
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())

    const response = await axiosClient.get<RatingResponse[]>(`/ratings/${analysisId}?${params.toString()}`)
    return response as unknown as RatingResponse[]
  },

  /**
   * Update rating
   * @param ratingId - Rating ID
   * @param request - UpdateRatingRequest
   * @returns RatingResponse
   */
  updateRating: async (ratingId: number, request: UpdateRatingRequest): Promise<RatingResponse> => {
    const response = await axiosClient.put<RatingResponse>(`/ratings/${ratingId}`, request)
    return response as unknown as RatingResponse
  },

  /**
   * Delete rating
   * @param ratingId - Rating ID
   * @returns Promise<void>
   */
  deleteRating: async (ratingId: number): Promise<void> => {
    await axiosClient.delete(`/ratings/${ratingId}`)
  },

  /**
   * Get rating statistics
   * @param analysisId - Analysis ID
   * @returns RatingStatsResponse
   */
  getRatingStats: async (analysisId: number): Promise<RatingStatsResponse> => {
    const response = await axiosClient.get<RatingStatsResponse>(`/ratings/stats/${analysisId}`)
    return response as unknown as RatingStatsResponse
  },
}


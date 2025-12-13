/**
 * Ratings API - Rating and review endpoints
 */
import apiClient from './client'
import {
  CreateRatingRequest,
  UpdateRatingRequest,
  RatingResponse,
  RatingStatsResponse,
} from '../datahelper/ratings.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Create rating
 * @param request - CreateRatingRequest
 * @returns RatingResponse
 */
export const createRating = async (request: CreateRatingRequest): Promise<RatingResponse> => {
  try {
    const response = await apiClient.post<RatingResponse>('/ratings', request)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Get ratings for analysis
 * @param analysisId - Analysis ID
 * @param limit - Limit
 * @param offset - Offset
 * @returns RatingResponse[]
 */
export const getRatings = async (
  analysisId: number,
  limit: number = 50,
  offset: number = 0
): Promise<RatingResponse[]> => {
  try {
    const response = await apiClient.get<RatingResponse[]>(
      `/ratings/${analysisId}?limit=${limit}&offset=${offset}`
    )
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Update rating
 * @param ratingId - Rating ID
 * @param request - UpdateRatingRequest
 * @returns RatingResponse
 */
export const updateRating = async (
  ratingId: number,
  request: UpdateRatingRequest
): Promise<RatingResponse> => {
  try {
    const response = await apiClient.put<RatingResponse>(`/ratings/${ratingId}`, request)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Delete rating
 * @param ratingId - Rating ID
 */
export const deleteRating = async (ratingId: number): Promise<void> => {
  try {
    await apiClient.delete(`/ratings/${ratingId}`)
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Get rating statistics
 * @param analysisId - Analysis ID
 * @returns RatingStatsResponse
 */
export const getRatingStats = async (analysisId: number): Promise<RatingStatsResponse> => {
  try {
    const response = await apiClient.get<RatingStatsResponse>(`/ratings/stats/${analysisId}`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


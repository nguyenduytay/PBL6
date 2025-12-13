/**
 * Ratings DataHelper - Types cho Ratings API
 * Tương ứng với api/ratings.ts
 */

/**
 * Request Types cho Ratings API
 */
export interface CreateRatingRequest {
  analysis_id: number
  rating: number // 1-5
  comment?: string
  reviewer_name?: string
  tags?: string[]
}

export interface UpdateRatingRequest {
  rating?: number
  comment?: string
  tags?: string[]
}

/**
 * Response Types cho Ratings API
 */
export interface RatingResponse {
  id: number
  analysis_id: number
  rating: number
  comment?: string | null
  reviewer_name?: string | null
  tags?: string[] | null
  created_at: string
  updated_at?: string | null
}

export interface RatingStatsResponse {
  analysis_id: number
  total_ratings: number
  average_rating: number
  rating_distribution: {
    [key: string]: number // "1": count, "2": count, etc.
  }
  total_comments: number
  common_tags: Array<{
    tag: string
    count: number
  }>
}


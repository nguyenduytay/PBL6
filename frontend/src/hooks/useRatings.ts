/**
 * useRatings Hook - Hook để xử lý ratings
 */
import { useState } from 'react'
import { ratingsApi } from '../api'
import {
  CreateRatingRequest,
  UpdateRatingRequest,
  RatingResponse,
  RatingStatsResponse,
} from '../datahelper/ratings.dataHelper'
import { ErrorResponse } from '../api/types'

interface UseRatingsReturn {
  create: (request: CreateRatingRequest) => Promise<void>
  getList: (analysisId: number, limit?: number, offset?: number) => Promise<void>
  update: (ratingId: number, request: UpdateRatingRequest) => Promise<void>
  remove: (ratingId: number) => Promise<void>
  getStats: (analysisId: number) => Promise<void>
  ratings: RatingResponse[]
  stats: RatingStatsResponse | null
  loading: boolean
  error: ErrorResponse | null
  reset: () => void
}

export const useRatings = (): UseRatingsReturn => {
  const [ratings, setRatings] = useState<RatingResponse[]>([])
  const [stats, setStats] = useState<RatingStatsResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const handleCreate = async (request: CreateRatingRequest): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      await ratingsApi.createRating(request)
      // Refresh ratings list
      if (request.analysis_id) {
        await handleGetList(request.analysis_id)
      }
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleGetList = async (
    analysisId: number,
    limit: number = 50,
    offset: number = 0
  ): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await ratingsApi.getRatings(analysisId, limit, offset)
      setRatings(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleUpdate = async (ratingId: number, request: UpdateRatingRequest): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      await ratingsApi.updateRating(ratingId, request)
      // Refresh ratings list
      const updatedRating = ratings.find((r) => r.id === ratingId)
      if (updatedRating) {
        await handleGetList(updatedRating.analysis_id)
      }
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleRemove = async (ratingId: number): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      await ratingsApi.deleteRating(ratingId)
      // Refresh ratings list
      const deletedRating = ratings.find((r) => r.id === ratingId)
      if (deletedRating) {
        await handleGetList(deletedRating.analysis_id)
      }
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleGetStats = async (analysisId: number): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await ratingsApi.getRatingStats(analysisId)
      setStats(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const reset = (): void => {
    setRatings([])
    setStats(null)
    setError(null)
    setLoading(false)
  }

  return {
    create: handleCreate,
    getList: handleGetList,
    update: handleUpdate,
    remove: handleRemove,
    getStats: handleGetStats,
    ratings,
    stats,
    loading,
    error,
    reset,
  }
}


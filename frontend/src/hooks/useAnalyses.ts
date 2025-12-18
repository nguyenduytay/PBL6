/**
 * useAnalyses Hook - Hook để xử lý analyses data
 */
import { useState, useEffect } from 'react'
import { getAnalyses, getAnalysisById, getAnalysisStats, deleteAnalysis } from '../api/analyses'
import {
  AnalysisDetailResponse,
  AnalysisListItemResponse,
  AnalysisStatsResponse,
} from '../datahelper/analyses.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

interface UseAnalysesReturn {
  analyses: AnalysisListItemResponse[]
  total: number
  loading: boolean
  error: ErrorResponse | null
  refetch: () => Promise<void>
  deleteAnalysisById: (id: number) => Promise<void>
  deleteAnalysisByIdWithoutRefetch: (id: number) => Promise<void>
}

export const useAnalyses = (limit: number = 100, offset: number = 0): UseAnalysesReturn => {
  const [analyses, setAnalyses] = useState<AnalysisListItemResponse[]>([])
  const [total, setTotal] = useState<number>(0)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const fetchAnalyses = async (): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await getAnalyses(limit, offset)
      setAnalyses(Array.isArray(data.items) ? data.items : [])
      setTotal(data.total || 0)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAnalyses()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [limit, offset])

  const deleteAnalysisById = async (id: number): Promise<void> => {
    try {
      await deleteAnalysis(id)
      // Refresh danh sách sau khi xóa
      await fetchAnalyses()
    } catch (err) {
      throw err as ErrorResponse
    }
  }

  const deleteAnalysisByIdWithoutRefetch = async (id: number): Promise<void> => {
    try {
      await deleteAnalysis(id)
      // Không tự động refetch, để component tự quyết định khi nào refetch
    } catch (err) {
      throw err as ErrorResponse
    }
  }

  return {
    analyses,
    total,
    loading,
    error,
    refetch: fetchAnalyses,
    deleteAnalysisById,
    deleteAnalysisByIdWithoutRefetch,
  }
}

interface UseAnalysisReturn {
  analysis: AnalysisDetailResponse | null
  loading: boolean
  error: ErrorResponse | null
  refetch: () => Promise<void>
}

export const useAnalysis = (id: number | undefined): UseAnalysisReturn => {
  const [analysis, setAnalysis] = useState<AnalysisDetailResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const fetchAnalysis = async (): Promise<void> => {
    if (!id) {
      setLoading(false)
      return
    }

    setLoading(true)
    setError(null)

    try {
      const data = await getAnalysisById(id)
      setAnalysis(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAnalysis()
  }, [id])

  return {
    analysis,
    loading,
    error,
    refetch: fetchAnalysis,
  }
}

interface UseAnalysisStatsReturn {
  stats: AnalysisStatsResponse | null
  loading: boolean
  error: ErrorResponse | null
  refetch: () => Promise<void>
}

export const useAnalysisStats = (): UseAnalysisStatsReturn => {
  const [stats, setStats] = useState<AnalysisStatsResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const fetchStats = async (): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await getAnalysisStats()
      setStats(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStats()
  }, [])

  return {
    stats,
    loading,
    error,
    refetch: fetchStats,
  }
}


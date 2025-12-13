/**
 * useAnalyses Hook - Hook để xử lý analyses data
 */
import { useState, useEffect } from 'react'
import { getAnalyses, getAnalysisById, getAnalysisStats } from '../api/analyses'
import {
  AnalysisDetailResponse,
  AnalysisListItemResponse,
  AnalysisStatsResponse,
} from '../datahelper/analyses.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

interface UseAnalysesReturn {
  analyses: AnalysisListItemResponse[]
  loading: boolean
  error: ErrorResponse | null
  refetch: () => Promise<void>
}

export const useAnalyses = (limit: number = 100, offset: number = 0): UseAnalysesReturn => {
  const [analyses, setAnalyses] = useState<AnalysisListItemResponse[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const fetchAnalyses = async (): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await getAnalyses(limit, offset)
      setAnalyses(Array.isArray(data) ? data : [])
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAnalyses()
  }, [limit, offset])

  return {
    analyses,
    loading,
    error,
    refetch: fetchAnalyses,
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


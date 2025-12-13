/**
 * useHealth Hook - Hook để check health status
 */
import { useState, useEffect } from 'react'
import { healthCheck } from '../api/health'
import { HealthCheckResponse } from '../datahelper/health.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

interface UseHealthReturn {
  health: HealthCheckResponse | null
  loading: boolean
  error: ErrorResponse | null
  refetch: () => Promise<void>
}

export const useHealth = (): UseHealthReturn => {
  const [health, setHealth] = useState<HealthCheckResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const fetchHealth = async (): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await healthCheck()
      setHealth(data)
    } catch (err) {
      setError(err as ErrorResponse)
      // Set default unhealthy state on error
      setHealth({
        status: 'unhealthy',
        message: (err as ErrorResponse).detail || 'Health check failed',
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHealth()
  }, [])

  return {
    health,
    loading,
    error,
    refetch: fetchHealth,
  }
}


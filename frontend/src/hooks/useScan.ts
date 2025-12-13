/**
 * useScan Hook - Hook để xử lý file scanning
 */
import { useState } from 'react'
import { scanFile } from '../api/scan'
import { ScanResponse } from '../datahelper/scan.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

interface UseScanReturn {
  scan: (file: File) => Promise<void>
  result: ScanResponse | null
  loading: boolean
  error: ErrorResponse | null
  reset: () => void
}

export const useScan = (): UseScanReturn => {
  const [result, setResult] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const scan = async (file: File): Promise<void> => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await scanFile(file)
      setResult(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const reset = (): void => {
    setResult(null)
    setError(null)
    setLoading(false)
  }

  return {
    scan,
    result,
    loading,
    error,
    reset,
  }
}


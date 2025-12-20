/**
 * useScan Hook - Hook để xử lý file scanning
 */
import { useState } from 'react'
import { scanApi } from '../api'
import { ScanResponse } from '../datahelper/scan.dataHelper'
import { ErrorResponse } from '../api/types'

export type ScanType = 'yara' | 'ember' | 'full'

interface UseScanReturn {
  scan: (file: File, scanType?: ScanType) => Promise<void>
  result: ScanResponse | null
  loading: boolean
  error: ErrorResponse | null
  reset: () => void
}

export const useScan = (): UseScanReturn => {
  const [result, setResult] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const scan = async (file: File, scanType: ScanType = 'full'): Promise<void> => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      let data: ScanResponse
      
      switch (scanType) {
        case 'yara':
          data = await scanApi.scanYara(file)
          break
        case 'ember':
          data = await scanApi.scanEmber(file)
          break
        case 'full':
        default:
          data = await scanApi.scanFile(file)
          break
      }
      
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


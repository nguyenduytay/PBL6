/**
 * useBatchScan Hook - Hook để xử lý batch scanning
 */
import { useState } from 'react'
import { scanFolder, scanFolderUpload, scanBatch, getBatchResult, getBatchStatus } from '../api/batchScan'
import { BatchScanResponse, BatchScanResult, BatchScanFolderRequest } from '../datahelper/batchScan.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

interface UseBatchScanReturn {
  scanFolder: (request: BatchScanFolderRequest) => Promise<void>
  scanFolderUpload: (files: File[]) => Promise<void>
  scanBatch: (file: File) => Promise<void>
  getResult: (batchId: string) => Promise<void>
  getStatus: (batchId: string) => Promise<void>
  result: BatchScanResult | null
  status: BatchScanResponse | null
  loading: boolean
  error: ErrorResponse | null
  reset: () => void
}

export const useBatchScan = (): UseBatchScanReturn => {
  const [result, setResult] = useState<BatchScanResult | null>(null)
  const [status, setStatus] = useState<BatchScanResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<ErrorResponse | null>(null)

  const handleScanFolder = async (request: BatchScanFolderRequest): Promise<void> => {
    setLoading(true)
    setError(null)
    setResult(null)
    setStatus(null)

    try {
      const data = await scanFolder(request)
      setStatus(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleScanFolderUpload = async (files: File[]): Promise<void> => {
    setLoading(true)
    setError(null)
    setResult(null)
    setStatus(null)

    try {
      const data = await scanFolderUpload(files)
      setStatus(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleScanBatch = async (file: File): Promise<void> => {
    setLoading(true)
    setError(null)
    setResult(null)
    setStatus(null)

    try {
      const data = await scanBatch(file)
      setStatus(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleGetResult = async (batchId: string): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await getBatchResult(batchId)
      setResult(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const handleGetStatus = async (batchId: string): Promise<void> => {
    setLoading(true)
    setError(null)

    try {
      const data = await getBatchStatus(batchId)
      setStatus(data)
    } catch (err) {
      setError(err as ErrorResponse)
    } finally {
      setLoading(false)
    }
  }

  const reset = (): void => {
    setResult(null)
    setStatus(null)
    setError(null)
    setLoading(false)
  }

  return {
    scanFolder: handleScanFolder,
    scanFolderUpload: handleScanFolderUpload,
    scanBatch: handleScanBatch,
    getResult: handleGetResult,
    getStatus: handleGetStatus,
    result,
    status,
    loading,
    error,
    reset,
  }
}


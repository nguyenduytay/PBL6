/**
 * Analyses API - Analysis history endpoints
 */
import apiClient from './client'
import {
  AnalysisDetailResponse,
  AnalysisListItemResponse,
  AnalysisStatsResponse,
  GetAnalysesRequest,
} from '../datahelper/analyses.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Lấy danh sách analyses với pagination
 * @param limit - Số lượng kết quả (mặc định: 100)
 * @param offset - Vị trí bắt đầu (mặc định: 0)
 * @returns Danh sách analyses
 */
export const getAnalyses = async (
  limit: number = 100,
  offset: number = 0
): Promise<AnalysisListItemResponse[]> => {
  try {
    const params: GetAnalysesRequest = { limit, offset }
    const response = await apiClient.get<AnalysisListItemResponse[]>('/analyses', {
      params,
    })
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Lấy chi tiết analysis theo ID
 * @param id - ID của analysis
 * @returns Chi tiết analysis
 */
export const getAnalysisById = async (id: number): Promise<AnalysisDetailResponse> => {
  try {
    const response = await apiClient.get<AnalysisDetailResponse>(`/analyses/${id}`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Lấy analysis theo SHA256 hash
 * @param sha256 - SHA256 hash của file
 * @returns Chi tiết analysis
 */
export const getAnalysisBySha256 = async (sha256: string): Promise<AnalysisDetailResponse> => {
  try {
    const response = await apiClient.get<AnalysisDetailResponse>(`/analyses/sha256/${sha256}`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}

/**
 * Lấy thống kê analyses
 * @returns Thống kê analyses
 */
export const getAnalysisStats = async (): Promise<AnalysisStatsResponse> => {
  try {
    const response = await apiClient.get<AnalysisStatsResponse>('/analyses/stats/summary')
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


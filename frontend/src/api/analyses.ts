/**
 * Analyses API - Analysis history endpoints
 */
import apiClient from './client'
import {
  AnalysisDetailResponse,
  AnalysisStatsResponse,
  GetAnalysesRequest,
  GetAnalysesResponse,
} from '../datahelper/analyses.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Lấy danh sách analyses với pagination
 * @param limit - Số lượng kết quả (mặc định: 100)
 * @param offset - Vị trí bắt đầu (mặc định: 0)
 * @returns Response với items, total, limit, offset
 */
export const getAnalyses = async (
  limit: number = 100,
  offset: number = 0
): Promise<GetAnalysesResponse> => {
  try {
    const params: GetAnalysesRequest = { limit, offset }
    const response = await apiClient.get<GetAnalysesResponse>('/analyses', {
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

/**
 * Xóa analysis theo ID
 * @param id - ID của analysis cần xóa
 * @returns Thông báo xóa thành công
 */
export const deleteAnalysis = async (id: number): Promise<{ message: string; id: number }> => {
  try {
    const response = await apiClient.delete<{ message: string; id: number }>(`/analyses/${id}`)
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


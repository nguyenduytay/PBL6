/**
 * Analyses API - Analysis history endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'
import {
  AnalysisDetailResponse,
  AnalysisStatsResponse,
  GetAnalysesRequest,
  GetAnalysesResponse,
} from '../datahelper/analyses.dataHelper'
import { ApiResponse } from './types'

export const analysesApi = {
  /**
   * Lấy danh sách analyses với pagination
   * @param params - GetAnalysesRequest (limit, offset)
   * @returns GetAnalysesResponse - Response với items, total, limit, offset
   */
  getAnalyses: async (params?: GetAnalysesRequest): Promise<GetAnalysesResponse> => {
    const response = await axiosClient.get<GetAnalysesResponse>('/analyses', { params })
    return response as unknown as GetAnalysesResponse
  },

  /**
   * Lấy chi tiết analysis theo ID
   * @param id - ID của analysis
   * @returns AnalysisDetailResponse - Chi tiết analysis
   */
  getAnalysisById: async (id: number): Promise<AnalysisDetailResponse> => {
    const response = await axiosClient.get<AnalysisDetailResponse>(`/analyses/${id}`)
    return response as unknown as AnalysisDetailResponse
  },

  /**
   * Lấy analysis theo SHA256 hash
   * @param sha256 - SHA256 hash của file
   * @returns AnalysisDetailResponse - Chi tiết analysis
   */
  getAnalysisBySha256: async (sha256: string): Promise<AnalysisDetailResponse> => {
    const response = await axiosClient.get<AnalysisDetailResponse>(`/analyses/sha256/${sha256}`)
    return response as unknown as AnalysisDetailResponse
  },

  /**
   * Lấy thống kê analyses
   * @returns AnalysisStatsResponse - Thống kê analyses
   */
  getAnalysisStats: async (): Promise<AnalysisStatsResponse> => {
    const response = await axiosClient.get<AnalysisStatsResponse>('/analyses/stats/summary')
    return response as unknown as AnalysisStatsResponse
  },

  /**
   * Xóa analysis theo ID
   * @param id - ID của analysis cần xóa
   * @returns Thông báo xóa thành công
   */
  deleteAnalysis: async (id: number): Promise<ApiResponse<{ message: string; id: number }>> => {
    const response = await axiosClient.delete<ApiResponse<{ message: string; id: number }>>(`/analyses/${id}`)
    return response as unknown as ApiResponse<{ message: string; id: number }>
  },
}


/**
 * Health API - Health check endpoints
 * Theo chuẩn front-bks-system với pattern object export
 */
import axiosClient from './axiosClient'
import { HealthCheckResponse } from '../datahelper/health.dataHelper'

export const healthApi = {
  /**
   * Health check endpoint
   * @returns HealthCheckResponse - Health check response
   */
  healthCheck: async (): Promise<HealthCheckResponse> => {
    const response = await axiosClient.get<HealthCheckResponse>('/health')
    return response as unknown as HealthCheckResponse
  },
}


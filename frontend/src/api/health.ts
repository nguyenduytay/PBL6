/**
 * Health API - Health check endpoints
 */
import apiClient from './client'
import { HealthCheckResponse } from '../datahelper/health.dataHelper'
import { ErrorResponse } from '../datahelper/client.dataHelper'

/**
 * Health check endpoint
 * @returns Health check response
 */
export const healthCheck = async (): Promise<HealthCheckResponse> => {
  try {
    const response = await apiClient.get<HealthCheckResponse>('/health')
    return response.data
  } catch (error) {
    throw error as ErrorResponse
  }
}


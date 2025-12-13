/**
 * Health DataHelper - Types cho Health API
 * Tương ứng với api/health.ts
 */

/**
 * Request Types cho Health API
 * Health check không có request params
 */

/**
 * Response Types cho Health API
 */

/**
 * Health check response - GET /health
 */
export interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy'
  message?: string
  yara_rules_loaded?: boolean
  yara_rule_count?: number
}


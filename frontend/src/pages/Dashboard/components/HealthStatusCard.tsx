import React from 'react'
import { Card } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'

interface HealthStatusCardProps {
  health: {
    status: string
    message?: string
    yara_rules_loaded?: boolean
    yara_rule_count?: number
  } | null
}

const HealthStatusCard: React.FC<HealthStatusCardProps> = ({ health }) => {
  const { t } = useTranslation()

  if (!health) return null

  return (
    <Card
      className={`${
        health.status === 'healthy'
          ? 'border-green-600 bg-green-900/20'
          : 'border-red-600 bg-red-900/20'
      }`}
    >
      <div className="flex items-center">
        <div className={`w-12 h-12 rounded-full flex items-center justify-center mr-4 ${
          health.status === 'healthy' ? 'bg-green-600' : 'bg-red-600'
        }`}>
          {health.status === 'healthy' ? (
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          ) : (
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          )}
        </div>
        <div>
          <h3 className="font-semibold text-white text-lg">
            {t('dashboard.apiStatus')}: {health.status === 'healthy' ? t('dashboard.healthy') : health.status}
          </h3>
          <p className="text-sm text-gray-400">
            {health.message || t('dashboard.apiRunningNormally')}
            {health.yara_rules_loaded && ` • ${health.yara_rule_count} ${t('dashboard.yaraRulesLoaded')}`}
          </p>
        </div>
      </div>
    </Card>
  )
}

export default HealthStatusCard


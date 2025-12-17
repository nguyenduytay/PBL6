import React from 'react'
import { Card } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'
import { HiOutlineCheckCircle, HiOutlineXCircle } from 'react-icons/hi'

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
      className={`${health.status === 'healthy'
          ? 'border-green-600 bg-green-900/20'
          : 'border-red-600 bg-red-900/20'
        }`}
    >
      <div className="flex items-center">
        <div className={`w-12 h-12 rounded-full flex items-center justify-center mr-4 ${health.status === 'healthy' ? 'bg-green-600' : 'bg-red-600'
          }`}>
          {health.status === 'healthy' ? (
            <HiOutlineCheckCircle className="w-6 h-6 text-white" />
          ) : (
            <HiOutlineXCircle className="w-6 h-6 text-white" />
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


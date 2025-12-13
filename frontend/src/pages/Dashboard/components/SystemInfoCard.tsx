import React from 'react'
import { Card } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'

interface SystemInfoCardProps {
  health: {
    yara_rule_count?: number
  } | null
}

const SystemInfoCard: React.FC<SystemInfoCardProps> = ({ health }) => {
  const { t } = useTranslation()

  return (
    <Card title={t('dashboard.systemInformation')} subtitle={t('dashboard.systemInformation')}>
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <span className="text-gray-400">{t('dashboard.version')}</span>
          <span className="text-white font-semibold">1.0.0</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400">{t('dashboard.status')}</span>
          <span className="text-green-400 font-semibold">{t('dashboard.online')}</span>
        </div>
        {health && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">{t('dashboard.yaraRules')}</span>
            <span className="text-white font-semibold">{health.yara_rule_count || 0}</span>
          </div>
        )}
      </div>
    </Card>
  )
}

export default SystemInfoCard


import React from 'react'
import { useAnalysisStats, useHealth } from '../../hooks'
import { StatCard, PageHeader, LoadingState } from '../../components/UI'
import { HealthStatusCard, QuickActionsCard, SystemInfoCard } from './components'
import { useTranslation } from '../../hooks/useTranslation'
import {
  HiOutlineChartBar,
  HiOutlineExclamation,
  HiOutlineCheckCircle,
  HiOutlineClock,
} from 'react-icons/hi'

const Dashboard: React.FC = () => {
  const { t } = useTranslation()
  const { stats, loading: statsLoading } = useAnalysisStats()
  const { health, loading: healthLoading } = useHealth()

  if (statsLoading || healthLoading) {
    return <LoadingState translationKey="common.loading" />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        translationKey={{ title: 'dashboard.title', subtitle: 'dashboard.subtitle' }}
      />

      <HealthStatusCard health={health} />

      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            title={t('dashboard.totalAnalyses')}
            value={stats.total_analyses || 0}
            icon={<HiOutlineChartBar className="w-6 h-6" />}
          />
          <StatCard
            title={t('dashboard.malwareDetected')}
            value={stats.malware_detected || 0}
            variant="danger"
            icon={<HiOutlineExclamation className="w-6 h-6" />}
          />
          <StatCard
            title={t('dashboard.cleanFiles')}
            value={stats.clean_files || 0}
            variant="success"
            icon={<HiOutlineCheckCircle className="w-6 h-6" />}
          />
          <StatCard
            title={t('dashboard.recent24h')}
            value={stats.recent_24h || 0}
            icon={<HiOutlineClock className="w-6 h-6" />}
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <QuickActionsCard />
        <SystemInfoCard health={health} />
      </div>
    </div>
  )
}

export default Dashboard


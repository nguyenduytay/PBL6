import React from 'react'
import { useAnalysisStats, useHealth } from '../../hooks'
import { StatCard, PageHeader, LoadingState } from '../../components/UI'
import { HealthStatusCard, QuickActionsCard, SystemInfoCard } from './components'
import { useTranslation } from '../../hooks/useTranslation'

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
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            }
          />
          <StatCard
            title={t('dashboard.malwareDetected')}
            value={stats.malware_detected || 0}
            variant="danger"
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            }
          />
          <StatCard
            title={t('dashboard.cleanFiles')}
            value={stats.clean_files || 0}
            variant="success"
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
          />
          <StatCard
            title={t('dashboard.recent24h')}
            value={stats.recent_24h || 0}
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
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


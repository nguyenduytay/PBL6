import React from 'react'
import { Link } from 'react-router-dom'
import { useAnalysisStats, useHealth } from '../hooks'
import { Card, StatCard, Button } from '../components/UI'

const Dashboard: React.FC = () => {
  const { stats, loading: statsLoading } = useAnalysisStats()
  const { health, loading: healthLoading } = useHealth()

  if (statsLoading || healthLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">Loading...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
        <p className="text-gray-400">Tổng quan hệ thống phát hiện malware</p>
      </div>

      {/* Health Status */}
      {health && (
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
                API Status: {health.status}
              </h3>
              <p className="text-sm text-gray-400">
                {health.message || 'API đang hoạt động bình thường'}
                {health.yara_rules_loaded && ` • ${health.yara_rule_count} YARA rules loaded`}
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            title="Total Analyses"
            value={stats.total_analyses || 0}
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            }
          />
          <StatCard
            title="Malware Detected"
            value={stats.malware_detected || 0}
            variant="danger"
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            }
          />
          <StatCard
            title="Clean Files"
            value={stats.clean_files || 0}
            variant="success"
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
          />
          <StatCard
            title="Recent 24h"
            value={stats.recent_24h || 0}
            icon={
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
          />
        </div>
      )}

      {/* Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Quick Actions" subtitle="Thao tác nhanh">
          <div className="flex flex-col space-y-3">
            <Link to="/upload">
              <Button className="w-full" size="lg">
                <svg className="w-5 h-5 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                Submit File for Analysis
              </Button>
            </Link>
            <Link to="/analyses">
              <Button variant="secondary" className="w-full" size="lg">
                <svg className="w-5 h-5 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                View All Analyses
              </Button>
            </Link>
          </div>
        </Card>

        <Card title="System Information" subtitle="Thông tin hệ thống">
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Version</span>
              <span className="text-white font-semibold">1.0.0</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Status</span>
              <span className="text-green-400 font-semibold">Online</span>
            </div>
            {health && (
              <div className="flex justify-between items-center">
                <span className="text-gray-400">YARA Rules</span>
                <span className="text-white font-semibold">{health.yara_rule_count || 0}</span>
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

export default Dashboard


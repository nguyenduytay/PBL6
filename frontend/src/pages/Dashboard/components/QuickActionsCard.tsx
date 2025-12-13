import React from 'react'
import { Link } from 'react-router-dom'
import { Card, Button } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'

const QuickActionsCard: React.FC = () => {
  const { t } = useTranslation()

  return (
    <Card title={t('dashboard.quickActions')} subtitle={t('dashboard.quickActions')}>
      <div className="flex flex-col space-y-3">
        <Link to="/upload">
          <Button className="w-full" size="lg">
            <svg className="w-5 h-5 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            {t('dashboard.submitFile')}
          </Button>
        </Link>
        <Link to="/analyses">
          <Button variant="secondary" className="w-full" size="lg">
            <svg className="w-5 h-5 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            {t('dashboard.viewAllAnalyses')}
          </Button>
        </Link>
      </div>
    </Card>
  )
}

export default QuickActionsCard


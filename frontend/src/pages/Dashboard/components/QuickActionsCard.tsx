import React from 'react'
import { Link } from 'react-router-dom'
import { Card, Button } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'
import { HiOutlineCloudUpload, HiOutlineDocumentText } from 'react-icons/hi'

const QuickActionsCard: React.FC = () => {
  const { t } = useTranslation()

  return (
    <Card title={t('dashboard.quickActions')}>
      <div className="flex flex-col space-y-3">
        <Link to="/upload">
          <Button className="w-full" size="lg">
            <HiOutlineCloudUpload className="w-5 h-5 inline mr-2" />
            {t('dashboard.submitFile')}
          </Button>
        </Link>
        <Link to="/analyses">
          <Button variant="secondary" className="w-full" size="lg">
            <HiOutlineDocumentText className="w-5 h-5 inline mr-2" />
            {t('dashboard.viewAllAnalyses')}
          </Button>
        </Link>
      </div>
    </Card>
  )
}

export default QuickActionsCard


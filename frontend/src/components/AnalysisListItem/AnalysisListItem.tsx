import React from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '../UI'
import { AnalysisListItemResponse } from '../../datahelper/analyses.dataHelper'
import { useTranslation } from '../../hooks/useTranslation'

interface AnalysisListItemProps {
  analysis: AnalysisListItemResponse
  showDetails?: boolean
  onClick?: (analysis: AnalysisListItemResponse) => void
}

const AnalysisListItem: React.FC<AnalysisListItemProps> = ({
  analysis,
  showDetails = true,
  onClick
}) => {
  const { t } = useTranslation()

  const content = (
    <div className="flex items-center justify-between">
      <div className="flex-1">
        <div className="flex items-center gap-3">
          <span className="text-white font-semibold">{analysis.filename}</span>
          <Badge variant={analysis.malware_detected ? 'danger' : 'success'}>
            {analysis.malware_detected ? t('analyses.malware') : t('analyses.clean')}
          </Badge>
        </div>
        {showDetails && (
          <>
            <div className="text-sm text-gray-400 mt-1">
              {analysis.sha256 && (
                <span className="mr-4">
                  {t('analysisDetail.sha256')}: {analysis.sha256.substring(0, 16)}...
                </span>
              )}
              {analysis.md5 && (
                <span>{t('analysisDetail.md5')}: {analysis.md5}</span>
              )}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {new Date(analysis.created_at).toLocaleString()}
            </div>
          </>
        )}
      </div>
    </div>
  )

  if (onClick) {
    return (
      <div
        onClick={() => onClick(analysis)}
        className="block p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors cursor-pointer"
      >
        {content}
      </div>
    )
  }

  return (
    <Link
      to={`/analyses/${analysis.id}`}
      className="block p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
    >
      {content}
    </Link>
  )
}

export default AnalysisListItem


import React from 'react'
import { Link } from 'react-router-dom'
import { Card, Badge } from '../../../components/UI'
import { AnalysisListItemResponse } from '../../../datahelper/analyses.dataHelper'
import { useTranslation } from '../../../hooks/useTranslation'

interface SearchResultsProps {
  results: AnalysisListItemResponse[]
  query: string
  loading: boolean
}

const SearchResults: React.FC<SearchResultsProps> = ({ results, query, loading }) => {
  const { t } = useTranslation()

  if (loading) {
    return (
      <Card>
        <div className="text-center text-gray-400 py-8">{t('search.searching')}</div>
      </Card>
    )
  }

  if (results.length > 0) {
    return (
      <Card title={t('search.resultsCount', { count: results.length })}>
        <div className="space-y-2">
          {results.map((analysis) => (
            <Link
              key={analysis.id}
              to={`/analyses/${analysis.id}`}
              className="block p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <span className="text-white font-semibold">{analysis.filename}</span>
                    <Badge variant={analysis.malware_detected ? 'danger' : 'success'}>
                      {analysis.malware_detected ? t('analyses.malware') : t('analyses.clean')}
                    </Badge>
                  </div>
                  <div className="text-sm text-gray-400 mt-1">
                    {analysis.sha256 && (
                      <span className="mr-4">{t('analysisDetail.sha256')}: {analysis.sha256.substring(0, 16)}...</span>
                    )}
                    {analysis.md5 && <span>{t('analysisDetail.md5')}: {analysis.md5}</span>}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {t('search.createdAt')}: {new Date(analysis.created_at).toLocaleString()}
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </Card>
    )
  }

  if (query && results.length === 0) {
    return (
      <Card>
        <div className="text-center py-8">
          <div className="text-gray-400 mb-2">{t('search.noResults', { query })}</div>
          <div className="text-sm text-gray-500">
            {t('search.trySearchingWith')}:
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>{t('search.exactFilename')}</li>
              <li>{t('search.sha256Hash')}</li>
              <li>{t('search.md5Hash')}</li>
            </ul>
          </div>
        </div>
      </Card>
    )
  }

  return null
}

export default SearchResults


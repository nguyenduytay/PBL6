import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAnalysis, useRatings } from '../../hooks'
import { Card, Badge, Button, ErrorState } from '../../components/UI'
import { LoadingStateRing } from '../../components/LoadingState'
import { useTranslation } from '../../hooks/useTranslation'

const AnalysisDetail: React.FC = () => {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const analysisId = id ? parseInt(id, 10) : undefined
  const { analysis, loading, error } = useAnalysis(analysisId)
  const { ratings, stats, getList, getStats, create, loading: ratingsLoading } = useRatings()
  const [rating, setRating] = useState(5)
  const [comment, setComment] = useState('')
  const [reviewerName, setReviewerName] = useState('')

  useEffect(() => {
    if (analysisId) {
      getList(analysisId)
      getStats(analysisId)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId])

  const handleCreateRating = async () => {
    if (!analysisId) return
    await create({
      analysis_id: analysisId,
      rating,
      comment: comment || undefined,
      reviewer_name: reviewerName || undefined,
    })
    setComment('')
    setReviewerName('')
  }

  if (loading) {
    return <LoadingStateRing translationKey="common.loading" />
  }

  if (error) {
    return <ErrorState error={error} backUrl="/analyses" backText={t('analysisDetail.backToAnalyses')} />
  }

  if (!analysis) {
    return (
      <Card className="border-yellow-600">
        <div className="text-yellow-400">
          <p className="font-semibold">{t('analysisDetail.analysisNotFound')}</p>
          <Link to="/analyses" className="mt-4 inline-block">
            <Button variant="secondary">{t('analysisDetail.backToAnalyses')}</Button>
          </Link>
        </div>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <div className="mb-6">
        <Link to="/analyses" className="inline-block mb-4">
          <Button variant="secondary" size="sm">
            {t('analysisDetail.backToAnalyses')}
          </Button>
        </Link>
        <h1 className="text-3xl font-bold text-white mb-2">
          {t('analysisDetail.title')} #{analysis.id}
        </h1>
      </div>

      {/* Basic Info */}
      <Card title={t('analysisDetail.basicInfo')} subtitle={t('analysisDetail.basicFileInfo')}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.filename')}</p>
            <p className="text-white font-medium">{analysis.filename}</p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.status')}</p>
            <Badge variant={analysis.malware_detected ? 'danger' : 'success'}>
              {analysis.malware_detected ? t('analysisDetail.malwareDetected') : t('analysisDetail.clean')}
            </Badge>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.sha256')}</p>
            <code className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded block break-all font-mono">
              {analysis.sha256}
            </code>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.md5')}</p>
            <code className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded block break-all font-mono">
              {analysis.md5 || t('analysisDetail.na')}
            </code>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.fileSize')}</p>
            <p className="text-white font-medium">
              {analysis.file_size
                ? `${(analysis.file_size / 1024 / 1024).toFixed(2)} MB`
                : t('analysisDetail.na')}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.analysisTime')}</p>
            <p className="text-white font-medium">
              {analysis.analysis_time?.toFixed(2)}s
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.createdAt')}</p>
            <p className="text-white font-medium">
              {analysis.created_at
                ? new Date(analysis.created_at).toLocaleString()
                : t('analysisDetail.na')}
            </p>
          </div>
        </div>
      </Card>

      {/* YARA Matches */}
      {analysis.yara_matches && analysis.yara_matches.length > 0 && (
        <Card
          title={`${t('analysisDetail.yaraMatches')} (${analysis.yara_matches.length})`}
          subtitle={t('analysisDetail.yaraMatchInfo')}
        >
          <div className="space-y-3">
            {analysis.yara_matches.map((match, index) => (
              <div
                key={index}
                className="p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg"
              >
                <p className="font-medium text-yellow-400">{match.rule_name}</p>
                {match.description && (
                  <p className="text-sm text-gray-400 mt-1">{match.description}</p>
                )}
                {match.tags && match.tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {match.tags.map((tag: string, tagIndex: number) => (
                      <Badge key={tagIndex} variant="warning">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* PE Info */}
      {analysis.pe_info && (
        <Card title={t('analysisDetail.peInfo')} subtitle={t('analysisDetail.peFileInfo')}>
          <pre className="bg-gray-700 p-4 rounded-lg text-xs overflow-auto text-gray-300 font-mono">
            {JSON.stringify(analysis.pe_info, null, 2)}
          </pre>
        </Card>
      )}

      {/* Suspicious Strings */}
      {analysis.suspicious_strings &&
        analysis.suspicious_strings.length > 0 && (
          <Card
            title={`${t('analysisDetail.suspiciousStrings')} (${analysis.suspicious_strings.length})`}
            subtitle={t('analysisDetail.suspiciousStrings')}
          >
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {analysis.suspicious_strings.slice(0, 50).map((str, index) => (
                <code
                  key={index}
                  className="block text-xs bg-gray-700 text-gray-300 p-2 rounded break-all font-mono"
                >
                  {str}
                </code>
              ))}
              {analysis.suspicious_strings.length > 50 && (
                <p className="text-gray-400 text-sm text-center pt-2">
                  {t('analysisDetail.andMoreStrings', { count: analysis.suspicious_strings.length - 50 })}
                </p>
              )}
            </div>
          </Card>
        )}

      {/* Capabilities */}
      {analysis.capabilities && Object.keys(analysis.capabilities).length > 0 && (
        <Card title={t('analysisDetail.capabilities')} subtitle={t('analysisDetail.fileCapabilities')}>
          <pre className="bg-gray-700 p-4 rounded-lg text-xs overflow-auto text-gray-300 font-mono">
            {JSON.stringify(analysis.capabilities, null, 2)}
          </pre>
        </Card>
      )}

      {/* Ratings */}
      <Card title={t('analysisDetail.ratings')} subtitle={t('analysisDetail.analysisRatings')}>
        {stats && (
          <div className="mb-6 p-4 bg-gray-700 rounded-lg">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <div className="text-gray-400 text-sm">{t('analysisDetail.totalRatings')}</div>
                <div className="text-white text-xl font-bold">{stats.total_ratings}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">{t('analysisDetail.average')}</div>
                <div className="text-yellow-400 text-xl font-bold">
                  {stats.average_rating.toFixed(1)} ⭐
                </div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">{t('analysisDetail.comments')}</div>
                <div className="text-white text-xl font-bold">{stats.total_comments}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">{t('analysisDetail.distribution')}</div>
                <div className="text-xs text-gray-300">
                  {Object.entries(stats.rating_distribution)
                    .filter(([_, count]) => count > 0)
                    .map(([star, count]) => `${star}⭐:${count}`)
                    .join(', ')}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Create Rating */}
        <div className="mb-6 p-4 bg-gray-700 rounded-lg">
          <h3 className="text-white font-semibold mb-4">{t('analysisDetail.addRating')}</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-300 mb-2">{t('analysisDetail.ratingLabel')}</label>
              <div className="flex gap-2">
                {[1, 2, 3, 4, 5].map((star) => (
                  <button
                    key={star}
                    onClick={() => setRating(star)}
                    className={`w-10 h-10 rounded ${
                      rating >= star
                        ? 'bg-yellow-500 text-white'
                        : 'bg-gray-600 text-gray-400'
                    }`}
                  >
                    ⭐
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-2">{t('analysisDetail.commentOptional')}</label>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                className="w-full px-4 py-2 bg-gray-600 border border-gray-500 rounded-lg text-white"
                rows={3}
                placeholder={t('analysisDetail.yourComment')}
              />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-2">{t('analysisDetail.yourName')}</label>
              <input
                type="text"
                value={reviewerName}
                onChange={(e) => setReviewerName(e.target.value)}
                className="w-full px-4 py-2 bg-gray-600 border border-gray-500 rounded-lg text-white"
                placeholder={t('analysisDetail.yourNamePlaceholder')}
              />
            </div>
            <Button onClick={handleCreateRating} disabled={ratingsLoading}>
              {t('analysisDetail.submitRating')}
            </Button>
          </div>
        </div>

        {/* Ratings List */}
        {ratings.length > 0 && (
          <div className="space-y-3">
            <h3 className="text-white font-semibold">{t('analysisDetail.recentRatings')}</h3>
            {ratings.map((r) => (
              <div key={r.id} className="p-4 bg-gray-700 rounded-lg">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-yellow-400">{'⭐'.repeat(r.rating)}</span>
                    <span className="text-white font-semibold">{r.rating}/5</span>
                  </div>
                  {r.reviewer_name && (
                    <span className="text-gray-400 text-sm">{t('analysisDetail.by')} {r.reviewer_name}</span>
                  )}
                </div>
                {r.comment && <p className="text-gray-300 text-sm mt-2">{r.comment}</p>}
                <div className="text-xs text-gray-500 mt-2">
                  {new Date(r.created_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

export default AnalysisDetail


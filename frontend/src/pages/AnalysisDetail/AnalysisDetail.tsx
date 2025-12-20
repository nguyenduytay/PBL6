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

      {/* Scan Information */}
      {(analysis.yara_matches && Array.isArray(analysis.yara_matches) && analysis.yara_matches.length > 0) && (
        <Card title={t('analysisDetail.scanInfo')} subtitle={t('analysisDetail.yaraMatchInfo')}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.yaraVersion')}</p>
              <p className="text-white font-medium">4.5.4</p>
            </div>
            <div>
              <p className="text-sm text-gray-400 mb-1">{t('analysisDetail.ruleSetName')}</p>
              <p className="text-white font-medium">index.yar</p>
            </div>
          </div>
        </Card>
      )}

      {/* YARA Matches */}
      {analysis.yara_matches && Array.isArray(analysis.yara_matches) && analysis.yara_matches.length > 0 && (
        <>
          <Card
            title={`${t('analysisDetail.yaraMatches')} (${analysis.yara_matches.length})`}
            subtitle={t('analysisDetail.yaraMatchInfo')}
          >
            <div className="space-y-3">
              {analysis.yara_matches.map((match: any, index: number) => {
                // Defensive checks - ensure match is an object
                if (!match || typeof match !== 'object') {
                  return null
                }
                
                // Ensure rule_name exists - có thể là rule_name hoặc rule
                const ruleName = match.rule_name || match.rule || `Rule ${index + 1}`
                if (!ruleName) {
                  return null
                }
                
                // Handle tags - can be array or string
                let tags: string[] = []
                if (match.tags) {
                  if (Array.isArray(match.tags)) {
                    tags = match.tags as string[]
                  } else if (typeof match.tags === 'string') {
                    tags = (match.tags as string).split(',').map((t: string) => t.trim()).filter((t: string) => t.length > 0)
                  }
                }
                
                // Ensure matched_strings is an array
                const matchedStrings = Array.isArray(match.matched_strings) ? match.matched_strings : []
                
                return (
                  <div
                    key={match.id || index}
                    className="p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <p className="font-medium text-yellow-400">{ruleName}</p>
                        {match.description && (
                          <p className="text-sm text-gray-400 mt-1">{match.description}</p>
                        )}
                        <div className="mt-2 flex flex-wrap gap-2 items-center">
                          {match.author && (
                            <span className="text-xs text-gray-500">
                              {t('analysisDetail.author')}: {match.author}
                            </span>
                          )}
                          {match.reference && (
                            <a 
                              href={match.reference} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="text-xs text-blue-400 hover:text-blue-300"
                            >
                              {t('analysisDetail.reference')}
                            </a>
                          )}
                        </div>
                      </div>
                    </div>
                    {tags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {tags.map((tag: string, tagIndex: number) => (
                          <Badge key={tagIndex} variant="warning">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                    {matchedStrings.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-yellow-700/50">
                        <p className="text-xs font-semibold text-gray-400 mb-2">
                          {t('analysisDetail.matchedStrings')} ({matchedStrings.length}):
                        </p>
                        <div className="space-y-1 max-h-40 overflow-y-auto">
                          {matchedStrings.slice(0, 10).map((str: any, strIndex: number) => {
                            // Defensive check for string object
                            if (!str || typeof str !== 'object') {
                              return null
                            }
                            return (
                            <div key={strIndex} className="text-xs bg-gray-800/50 p-2 rounded">
                              {str.identifier && (
                                <span className="text-yellow-300 font-mono">{str.identifier}</span>
                              )}
                              {str.offset !== undefined && str.offset !== null && (
                                <span className="text-gray-500 ml-2">@0x{Number(str.offset).toString(16)}</span>
                              )}
                              {str.data_preview && (
                                <code className="block text-gray-300 mt-1 break-all">
                                  {str.data_preview}
                                </code>
                              )}
                            </div>
                            )
                          })}
                          {matchedStrings.length > 10 && (
                            <p className="text-xs text-gray-500 text-center">
                              {t('analysisDetail.andMoreMatchedStrings', { count: matchedStrings.length - 10 })}
                            </p>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </Card>

          {/* Severity Assessment */}
          <Card 
            title={t('analysisDetail.severityAssessment')}
            subtitle={t('analysisDetail.severityDescription')}
          >
            {(() => {
              const matchCount = analysis.yara_matches?.length || 0
              const highSeverityTags = ['AntiDebug', 'PECheck', 'PEiD', 'malware', 'trojan', 'virus', 'backdoor', 'ransomware']
              const hasHighSeverityTag = analysis.yara_matches?.some(m => {
                const tags = Array.isArray(m.tags) ? m.tags : (typeof m.tags === 'string' ? m.tags.split(',') : [])
                return tags.some((tag: string) => highSeverityTags.some(hst => tag.toLowerCase().includes(hst.toLowerCase())))
              })
              
              let severity: 'high' | 'medium' | 'low' | 'clean' = 'clean'
              let severityText = t('analysisDetail.severityClean')
              
              if (matchCount >= 5 || hasHighSeverityTag) {
                severity = 'high'
                severityText = t('analysisDetail.severityHigh')
              } else if (matchCount >= 3) {
                severity = 'medium'
                severityText = t('analysisDetail.severityMedium')
              } else if (matchCount >= 1) {
                severity = 'low'
                severityText = t('analysisDetail.severityLow')
              }
              
              // Classify potential malware type
              const malwareTypes: string[] = []
              analysis.yara_matches?.forEach(m => {
                const tags = Array.isArray(m.tags) ? m.tags : (typeof m.tags === 'string' ? m.tags.split(',') : [])
                if (tags.some((t: string) => t.toLowerCase().includes('trojan'))) malwareTypes.push(t('analysisDetail.malwareTypeTrojan'))
                if (tags.some((t: string) => t.toLowerCase().includes('stealer'))) malwareTypes.push(t('analysisDetail.malwareTypeInfoStealer'))
                if (tags.some((t: string) => t.toLowerCase().includes('backdoor'))) malwareTypes.push(t('analysisDetail.malwareTypeBackdoor'))
                if (tags.some((t: string) => t.toLowerCase().includes('ransomware'))) malwareTypes.push(t('analysisDetail.malwareTypeRansomware'))
                if (tags.some((t: string) => t.toLowerCase().includes('keylogger'))) malwareTypes.push(t('analysisDetail.malwareTypeKeylogger'))
              })
              const uniqueTypes = [...new Set(malwareTypes)]
              
              return (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <Badge variant={severity === 'high' ? 'danger' : severity === 'medium' ? 'warning' : 'success'}>
                      {severityText}
                    </Badge>
                    <span className="text-gray-400 text-sm">
                      {matchCount} {matchCount > 1 ? t('analysisDetail.rules') : t('analysisDetail.rule')} khớp
                    </span>
                  </div>
                  
                  {uniqueTypes.length > 0 && (
                    <div>
                      <p className="text-sm text-gray-400 mb-2">{t('analysisDetail.malwareClassification')}:</p>
                      <div className="flex flex-wrap gap-2">
                        {uniqueTypes.map((type, idx) => (
                          <Badge key={idx} variant="warning">{type}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {severity !== 'clean' && (
                    <div className="p-3 bg-gray-800/50 rounded border border-gray-700">
                      <p className="text-xs text-gray-400 mb-1">{t('analysisDetail.falsePositiveAnalysis')}:</p>
                      <p className="text-xs text-gray-500">{t('analysisDetail.falsePositiveNote')}</p>
                    </div>
                  )}
                </div>
              )
            })()}
          </Card>

          {/* Conclusion & Recommendations */}
          <Card 
            title={t('analysisDetail.conclusion')}
            subtitle={t('analysisDetail.recommendations')}
          >
            {(() => {
              const matchCount = analysis.yara_matches?.length || 0
              const hasHighSeverityTag = analysis.yara_matches?.some(m => {
                const tags = Array.isArray(m.tags) ? m.tags : (typeof m.tags === 'string' ? m.tags.split(',') : [])
                return tags.some((tag: string) => ['AntiDebug', 'PECheck', 'malware', 'trojan'].some(hst => tag.toLowerCase().includes(hst.toLowerCase())))
              })
              
              let recommendation = ''
              if (matchCount >= 5 || hasHighSeverityTag) {
                recommendation = t('analysisDetail.recommendHigh')
              } else if (matchCount >= 3) {
                recommendation = t('analysisDetail.recommendMedium')
              } else if (matchCount >= 1) {
                recommendation = t('analysisDetail.recommendLow')
              } else {
                recommendation = t('analysisDetail.recommendClean')
              }
              
              return (
                <div className="space-y-3">
                  <div className="p-4 bg-gray-800/50 rounded border border-gray-700">
                    <p className="text-sm text-gray-300 leading-relaxed">{recommendation}</p>
                  </div>
                  <div className="text-xs text-gray-500 italic">
                    <p className="font-semibold mb-1">{t('analysisDetail.importantNote')}:</p>
                    <p>{t('analysisDetail.yaraLimitationNote')}</p>
                  </div>
                </div>
              )
            })()}
          </Card>
        </>
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
        Array.isArray(analysis.suspicious_strings) &&
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

      {/* Detailed Results (YARA, EMBER, Errors) */}
      {analysis.results && Array.isArray(analysis.results) && analysis.results.length > 0 && (
        <Card 
          title={t('upload.detailedResults')} 
          subtitle={t('upload.detailedResultsSubtitle')}
        >
          <div className="space-y-3">
            {analysis.results.map((item: any, index: number) => {
              // EMBER Error
              const isEmberError = item.type === 'ember_error' || 
                                 (item.type === 'model' && item.subtype === 'ember' && item.error) ||
                                 (item.error && item.error.toLowerCase().includes('ember'))
              
              if (isEmberError) {
                return (
                  <div
                    key={index}
                    className="p-4 bg-red-900/20 border border-red-600 rounded-lg"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="font-medium text-red-400 mb-1">
                          {t('upload.emberError')}
                        </p>
                        <p className="text-sm text-red-300 mb-2">{item.message || item.error}</p>
                        {item.error_detail && (
                          <p className="text-xs text-gray-400 mt-1">
                            <span className="font-semibold">{t('upload.errorDetail')}:</span> {item.error_detail}
                          </p>
                        )}
                        {item.error_type && (
                          <p className="text-xs text-gray-400 mt-1">
                            <span className="font-semibold">{t('upload.errorType')}:</span> {item.error_type}
                          </p>
                        )}
                        {item.file_path && (
                          <p className="text-xs text-gray-400 mt-1">
                            <span className="font-semibold">{t('upload.file')}:</span> {item.file_path}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                )
              }
              
              // EMBER Result (Success)
              const isEmberResult = (item.type === 'model' && item.subtype === 'ember') ||
                                  (item.type === 'model' && item.score !== undefined)
              
              if (isEmberResult && !item.error) {
                return (
                  <div
                    key={index}
                    className={`p-4 rounded-lg border ${
                      item.score && item.score > (item.threshold || 0.5)
                        ? 'bg-yellow-900/20 border-yellow-600'
                        : 'bg-green-900/20 border-green-600'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className={`font-medium mb-1 ${
                          item.score && item.score > (item.threshold || 0.5)
                            ? 'text-yellow-400'
                            : 'text-green-400'
                        }`}>
                          {t('upload.emberResult')}
                        </p>
                        <p className="text-sm text-gray-300 mb-2">{item.message}</p>
                        {item.score !== undefined && (
                          <div className="mt-2 space-y-1">
                            <p className="text-xs text-gray-400">
                              <span className="font-semibold">{t('upload.score')}:</span> {item.score.toFixed(4)}
                            </p>
                            {item.threshold !== undefined && (
                              <p className="text-xs text-gray-400">
                                <span className="font-semibold">{t('upload.threshold')}:</span> {item.threshold.toFixed(4)}
                              </p>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )
              }

              // YARA Matches
              if (item.type === 'yara') {
                return (
                  <div
                    key={index}
                    className="p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg"
                  >
                    <p className="font-medium text-yellow-400 mb-1">
                      {t('upload.yaraMatch')}
                    </p>
                    <p className="text-sm text-gray-300">{item.message || item.matches}</p>
                    {item.infoUrl && (
                      <a 
                        href={item.infoUrl} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:text-blue-300 mt-2 inline-block"
                      >
                        {t('upload.viewMore')}
                      </a>
                    )}
                  </div>
                )
              }

              // Hash results
              if (item.type === 'hash') {
                return (
                  <div
                    key={index}
                    className="p-4 bg-blue-900/20 border border-blue-600 rounded-lg"
                  >
                    <p className="font-medium text-blue-400 mb-1">{t('upload.hashMatch')}</p>
                    <p className="text-sm text-gray-300">{item.message}</p>
                    {item.infoUrl && (
                      <a 
                        href={item.infoUrl} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:text-blue-300 mt-2 inline-block"
                      >
                        {t('upload.viewMore')}
                      </a>
                    )}
                  </div>
                )
              }

              // Other results
              return (
                <div
                  key={index}
                  className="p-4 bg-gray-800/50 border border-gray-600 rounded-lg"
                >
                  <p className="font-medium text-gray-300 mb-1">
                    {t('upload.resultType')}: {item.type} {item.subtype ? `(${item.subtype})` : ''}
                  </p>
                  <p className="text-sm text-gray-400">{item.message || JSON.stringify(item)}</p>
                </div>
              )
            })}
          </div>
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


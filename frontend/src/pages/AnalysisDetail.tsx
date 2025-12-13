import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAnalysis } from '../hooks'
import { Card, Badge, Button } from '../components/UI'

const AnalysisDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const analysisId = id ? parseInt(id, 10) : undefined
  const { analysis, loading, error } = useAnalysis(analysisId)

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-400">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <Card className="border-red-600">
        <div className="text-red-400">
          <p className="font-semibold">Error: {error.detail}</p>
          <Link to="/analyses" className="mt-4 inline-block">
            <Button variant="secondary">← Back to Analyses</Button>
          </Link>
        </div>
      </Card>
    )
  }

  if (!analysis) {
    return (
      <Card className="border-yellow-600">
        <div className="text-yellow-400">
          <p className="font-semibold">Analysis not found</p>
          <Link to="/analyses" className="mt-4 inline-block">
            <Button variant="secondary">← Back to Analyses</Button>
          </Link>
        </div>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="mb-6">
        <Link to="/analyses" className="inline-block mb-4">
          <Button variant="secondary" size="sm">
            ← Back to Analyses
          </Button>
        </Link>
        <h1 className="text-3xl font-bold text-white mb-2">
          Analysis Detail #{analysis.id}
        </h1>
      </div>

      {/* Basic Info */}
      <Card title="Basic Information" subtitle="Thông tin cơ bản về file">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <p className="text-sm text-gray-400 mb-1">Filename</p>
            <p className="text-white font-medium">{analysis.filename}</p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">Status</p>
            <Badge variant={analysis.malware_detected ? 'danger' : 'success'}>
              {analysis.malware_detected ? '⚠️ Malware Detected' : '✅ Clean'}
            </Badge>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">SHA256</p>
            <code className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded block break-all font-mono">
              {analysis.sha256}
            </code>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">MD5</p>
            <code className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded block break-all font-mono">
              {analysis.md5 || 'N/A'}
            </code>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">File Size</p>
            <p className="text-white font-medium">
              {analysis.file_size
                ? `${(analysis.file_size / 1024 / 1024).toFixed(2)} MB`
                : 'N/A'}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">Analysis Time</p>
            <p className="text-white font-medium">
              {analysis.analysis_time?.toFixed(2)}s
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">Created At</p>
            <p className="text-white font-medium">
              {analysis.created_at
                ? new Date(analysis.created_at).toLocaleString('vi-VN')
                : 'N/A'}
            </p>
          </div>
        </div>
      </Card>

      {/* YARA Matches */}
      {analysis.yara_matches && analysis.yara_matches.length > 0 && (
        <Card
          title={`YARA Matches (${analysis.yara_matches.length})`}
          subtitle="Các YARA rules đã match"
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
                    {match.tags.map((tag, tagIndex) => (
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
        <Card title="PE Information" subtitle="Thông tin PE file">
          <pre className="bg-gray-700 p-4 rounded-lg text-xs overflow-auto text-gray-300 font-mono">
            {JSON.stringify(analysis.pe_info, null, 2)}
          </pre>
        </Card>
      )}

      {/* Suspicious Strings */}
      {analysis.suspicious_strings &&
        analysis.suspicious_strings.length > 0 && (
          <Card
            title={`Suspicious Strings (${analysis.suspicious_strings.length})`}
            subtitle="Các chuỗi đáng ngờ"
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
                  ... và {analysis.suspicious_strings.length - 50} chuỗi khác
                </p>
              )}
            </div>
          </Card>
        )}

      {/* Capabilities */}
      {analysis.capabilities && Object.keys(analysis.capabilities).length > 0 && (
        <Card title="Capabilities" subtitle="Khả năng của file">
          <pre className="bg-gray-700 p-4 rounded-lg text-xs overflow-auto text-gray-300 font-mono">
            {JSON.stringify(analysis.capabilities, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  )
}

export default AnalysisDetail


import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAnalyses } from '../hooks'
import { Card, Badge, Button, Table } from '../components/UI'
import { AnalysisListItemResponse } from '../datahelper/analyses.dataHelper'

const Analyses: React.FC = () => {
  const [limit, setLimit] = useState<number>(20)
  const { analyses, loading, error } = useAnalyses(limit, 0)

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
          <p className="font-semibold">Error:</p>
          <p>{error.detail}</p>
        </div>
      </Card>
    )
  }

  const headers = ['ID', 'Filename', 'Status', 'Analysis Time', 'Created At', 'Actions']

  const renderRow = (analysis: AnalysisListItemResponse, index: number): React.ReactNode => {
    return (
      <>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
          #{analysis.id}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-white font-medium">
          {analysis.filename}
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
          <Badge variant={analysis.malware_detected ? 'danger' : 'success'}>
            {analysis.malware_detected ? '⚠️ Malware' : '✅ Clean'}
          </Badge>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
          {analysis.analysis_time?.toFixed(2)}s
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
          {analysis.created_at
            ? new Date(analysis.created_at).toLocaleString('vi-VN')
            : '-'}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
          <Link
            to={`/analyses/${analysis.id}`}
            className="text-green-400 hover:text-green-300 transition-colors"
          >
            View Details
          </Link>
        </td>
      </>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Recent Analyses</h1>
        <p className="text-gray-400">Lịch sử phân tích malware</p>
      </div>

      {/* Show Options */}
      <Card
        title="Recent analyses"
        actions={
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">Show:</span>
            {[1, 2, 3, 5, 10, 20, 50].map((num) => (
              <button
                key={num}
                onClick={() => setLimit(num)}
                className={`px-2 py-1 text-sm rounded ${
                  limit === num
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {num}
              </button>
            ))}
          </div>
        }
      >
        {analyses.length === 0 ? (
          <div className="text-center py-12">
            <svg
              className="mx-auto h-12 w-12 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
              />
            </svg>
            <p className="mt-4 text-gray-400">Chưa có phân tích nào</p>
            <Link to="/upload" className="mt-4 inline-block">
              <Button>Upload File Ngay</Button>
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table headers={headers} data={analyses} renderRow={renderRow} />
          </div>
        )}
      </Card>
    </div>
  )
}

export default Analyses


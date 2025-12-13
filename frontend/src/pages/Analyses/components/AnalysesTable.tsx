import React from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '../../../components/UI'
import { AnalysisListItemResponse } from '../../../datahelper/analyses.dataHelper'
import { useTranslation } from '../../../hooks/useTranslation'

interface AnalysesTableProps {
  analyses: AnalysisListItemResponse[]
  headers: string[]
  selectedIds: Set<number>
  deleting: number | null
  onSelectAll: (checked: boolean) => void
  onSelectOne: (id: number, checked: boolean) => void
  onDeleteClick: (id: number) => void
  isAllSelected: boolean
  isIndeterminate: boolean
}

const AnalysesTable: React.FC<AnalysesTableProps> = ({
  analyses,
  headers,
  selectedIds,
  deleting,
  onSelectAll,
  onSelectOne,
  onDeleteClick,
  isAllSelected,
  isIndeterminate
}) => {
  const { t } = useTranslation()

  const renderRow = (analysis: AnalysisListItemResponse): React.ReactNode => {
    const isSelected = selectedIds.has(analysis.id)
    return (
      <>
        <td className="px-6 py-4 whitespace-nowrap w-12">
          <div className="flex items-center">
            <input
              type="checkbox"
              checked={isSelected}
              onChange={(e) => onSelectOne(analysis.id, e.target.checked)}
              className="w-5 h-5 text-green-600 bg-gray-700 border-gray-500 rounded focus:ring-green-500 focus:ring-2 cursor-pointer"
              title={isSelected ? t('analyses.deselect') : t('analyses.select')}
            />
          </div>
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
          #{analysis.id}
        </td>
        <td className="px-6 py-4 whitespace-nowrap text-sm text-white font-medium">
          {analysis.filename}
        </td>
        <td className="px-6 py-4 whitespace-nowrap">
          <Badge variant={analysis.malware_detected ? 'danger' : 'success'}>
            {analysis.malware_detected ? t('analyses.malware') : t('analyses.clean')}
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
          <div className="flex items-center space-x-3">
            <Link
              to={`/analyses/${analysis.id}`}
              className="text-green-400 hover:text-green-300 transition-colors"
            >
              {t('analyses.viewDetails')}
            </Link>
            <button
              onClick={() => onDeleteClick(analysis.id)}
              disabled={deleting === analysis.id}
              className="text-red-400 hover:text-red-300 transition-colors disabled:opacity-50"
              title={t('analyses.delete')}
            >
              {deleting === analysis.id ? t('analyses.deleting') : t('analyses.delete')}
            </button>
          </div>
        </td>
      </>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-700">
        <thead className="bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider w-12">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  checked={isAllSelected}
                  ref={(input) => {
                    if (input) input.indeterminate = isIndeterminate
                  }}
                  onChange={(e) => onSelectAll(e.target.checked)}
                  className="w-5 h-5 text-green-600 bg-gray-700 border-gray-500 rounded focus:ring-green-500 focus:ring-2 cursor-pointer"
                  title={isAllSelected ? t('analyses.deselectAll') : t('analyses.selectAll')}
                />
              </div>
            </th>
            {headers.map((header, index) => (
              <th
                key={index}
                className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider"
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="bg-gray-800 divide-y divide-gray-700">
          {analyses.map((analysis, index) => (
            <tr key={analysis.id || index} className="hover:bg-gray-750 transition-colors">
              {renderRow(analysis)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default AnalysesTable


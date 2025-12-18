import React from 'react'
import { Button, ExportButtons } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'

interface AnalysesToolbarProps {
  limit: number
  onLimitChange: (limit: number) => void
  selectedCount: number
  onDeleteSelected: () => void
  deletingMultiple: boolean
}

const AnalysesToolbar: React.FC<AnalysesToolbarProps> = ({
  limit,
  onLimitChange,
  selectedCount,
  onDeleteSelected,
  deletingMultiple
}) => {
  const { t } = useTranslation()

  return (
    <div className="flex items-center space-x-4">
      <div className="flex items-center space-x-2">
        <span className="text-sm text-gray-400">{t('analyses.show')}:</span>
        {[10, 20, 50, 100].map((num) => (
          <button
            key={num}
            onClick={() => onLimitChange(num)}
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
      {selectedCount > 0 && (
        <Button
          variant="danger"
          size="sm"
          onClick={onDeleteSelected}
          disabled={deletingMultiple}
        >
          {t('analyses.deleteSelected', { count: selectedCount })}
        </Button>
      )}
      <ExportButtons limit={1000} offset={0} />
    </div>
  )
}

export default AnalysesToolbar


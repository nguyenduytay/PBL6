import React from 'react'
import { Button } from '../../../components/UI'
import { useTranslation } from '../../../hooks/useTranslation'

interface SearchInputProps {
  query: string
  loading: boolean
  onQueryChange: (query: string) => void
  onSearch: () => void
  onKeyPress: (e: React.KeyboardEvent) => void
}

const SearchInput: React.FC<SearchInputProps> = ({
  query,
  loading,
  onQueryChange,
  onSearch,
  onKeyPress
}) => {
  const { t } = useTranslation()

  return (
    <div className="space-y-4">
      <div className="flex gap-4">
        <input
          type="text"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyPress={onKeyPress}
          placeholder={t('search.placeholder')}
          className="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-green-500"
        />
        <Button onClick={onSearch} disabled={loading || !query.trim()}>
          {loading ? t('search.searching') : t('common.search')}
        </Button>
      </div>
      
      <div className="text-sm text-gray-400 bg-gray-800 p-3 rounded-lg">
        <p className="font-medium mb-1">{t('search.searchTips')}:</p>
        <ul className="list-disc list-inside space-y-1 text-xs">
          <li>{t('search.searchByFilename')}</li>
          <li>{t('search.searchBySHA256')}</li>
          <li>{t('search.searchByMD5')}</li>
          <li>{t('search.caseInsensitive')}</li>
        </ul>
      </div>
    </div>
  )
}

export default SearchInput


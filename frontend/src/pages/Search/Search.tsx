import React, { useState } from 'react'
import { searchAnalyses } from '../../api/search'
import { Card, PageHeader, ErrorState } from '../../components/UI'
import { SearchInput, SearchResults } from './components'
import { AnalysisListItemResponse } from '../../datahelper/analyses.dataHelper'
import { useTranslation } from '../../hooks/useTranslation'

const Search: React.FC = () => {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<AnalysisListItemResponse[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = async () => {
    if (!query.trim()) return

    setLoading(true)
    setError(null)

    try {
      const data = await searchAnalyses(query)
      if (Array.isArray(data)) {
        setResults(data)
      } else {
        setResults([])
      }
    } catch (err: any) {
      setError(err.detail || err.message || t('common.error'))
      setResults([])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch()
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        translationKey={{ title: 'search.title', subtitle: 'search.subtitle' }}
      />

      <Card title={t('search.cardTitle')} subtitle={t('search.cardSubtitle')}>
        <SearchInput
          query={query}
          loading={loading}
          onQueryChange={setQuery}
          onSearch={handleSearch}
          onKeyPress={handleKeyPress}
        />
      </Card>

      {error && (
        <ErrorState error={error} />
      )}

      <SearchResults results={results} query={query} loading={loading} />
    </div>
  )
}

export default Search


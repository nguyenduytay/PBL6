import React, { useState, useEffect, useRef, useCallback } from 'react'
import { searchAnalyses } from '../../api/search'
import { Card, PageHeader, ErrorState, LoadingState } from '../../components/UI'
import { SearchInput, SearchResults } from './components'
import { AnalysisListItemResponse } from '../../datahelper/analyses.dataHelper'
import { useTranslation } from '../../hooks/useTranslation'

const SEARCH_LIMIT = 20 // Number of results per load

const Search: React.FC = () => {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<AnalysisListItemResponse[]>([])
  const [total, setTotal] = useState<number>(0)
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const observerTarget = useRef<HTMLDivElement>(null)
  const currentQuery = useRef<string>('')
  const currentOffset = useRef<number>(0)

  const handleSearch = async (reset: boolean = true) => {
    if (!query.trim()) {
      setResults([])
      setTotal(0)
      setHasMore(false)
      return
    }

    if (reset) {
      setLoading(true)
      setError(null)
      currentOffset.current = 0
      setResults([])
    } else {
      setLoadingMore(true)
    }

    currentQuery.current = query.trim()

    try {
      const data = await searchAnalyses(currentQuery.current, SEARCH_LIMIT, currentOffset.current)
      
      if (data && data.items) {
        if (reset) {
          setResults(data.items)
        } else {
          setResults(prev => [...prev, ...data.items])
        }
        setTotal(data.total)
        setHasMore(data.items.length === SEARCH_LIMIT && results.length + data.items.length < data.total)
        currentOffset.current += data.items.length
      } else {
        if (reset) {
          setResults([])
          setTotal(0)
        }
        setHasMore(false)
      }
    } catch (err: any) {
      setError(err.detail || err.message || t('common.error'))
      if (reset) {
        setResults([])
        setTotal(0)
      }
      setHasMore(false)
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }

  const loadMore = useCallback(() => {
    if (!loadingMore && hasMore && query.trim() === currentQuery.current) {
      handleSearch(false)
    }
  }, [loadingMore, hasMore, query])

  // Intersection Observer for infinite scroll
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMore && !loadingMore) {
          loadMore()
        }
      },
      { threshold: 0.1 }
    )

    const currentTarget = observerTarget.current
    if (currentTarget) {
      observer.observe(currentTarget)
    }

    return () => {
      if (currentTarget) {
        observer.unobserve(currentTarget)
      }
    }
  }, [hasMore, loadingMore, loadMore])

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch(true)
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
          onSearch={() => handleSearch(true)}
          onKeyPress={handleKeyPress}
        />
      </Card>

      {error && (
        <ErrorState error={error} />
      )}

      {loading && results.length === 0 ? (
        <LoadingState translationKey="search.searching" />
      ) : (
        <SearchResults 
          results={results} 
          query={query} 
          loading={loadingMore}
          total={total}
        />
      )}

      {/* Infinite scroll trigger */}
      {hasMore && (
        <div ref={observerTarget} className="h-10 flex items-center justify-center">
          {loadingMore && (
            <div className="text-gray-400">{t('search.loadingMore')}</div>
          )}
        </div>
      )}
    </div>
  )
}

export default Search


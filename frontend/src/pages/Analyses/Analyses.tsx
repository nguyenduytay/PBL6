import React, { useState, useEffect } from 'react'
import { useAnalyses } from '../../hooks'
import { Card, PageHeader, LoadingState, ErrorState, EmptyState, ConfirmationModal, Pagination } from '../../components/UI'
import { AnalysesTable, AnalysesToolbar } from './components'
import { useTranslation } from '../../hooks/useTranslation'
import { DEFAULT_PAGE_LIMIT } from '../../constants'

const Analyses: React.FC = () => {
  const { t } = useTranslation()
  const [limit, setLimit] = useState<number>(DEFAULT_PAGE_LIMIT)
  const [currentPage, setCurrentPage] = useState<number>(1)
  const offset = (currentPage - 1) * limit
  const { analyses, total, loading, error, deleteAnalysisById, refetch } = useAnalyses(limit, offset)
  const [deleting, setDeleting] = useState<number | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [deleteMultipleConfirm, setDeleteMultipleConfirm] = useState<boolean>(false)
  const [deletingMultiple, setDeletingMultiple] = useState<boolean>(false)

  // Clear selection when analyses change (e.g., after refetch, page change)
  useEffect(() => {
    // Remove selected IDs that no longer exist in current analyses
    const currentAnalysisIds = new Set(analyses.map(a => a.id))
    const validSelectedIds = new Set(
      Array.from(selectedIds).filter(id => currentAnalysisIds.has(id))
    )
    if (validSelectedIds.size !== selectedIds.size) {
      setSelectedIds(validSelectedIds)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analyses])

  const handleDelete = async (id: number) => {
    setDeleting(id)
    try {
      await deleteAnalysisById(id)
      setDeleteConfirm(null)
      setSelectedIds(new Set())
      // Nếu xóa item cuối cùng của trang và không phải trang đầu, quay về trang trước
      if (analyses.length === 1 && currentPage > 1) {
        setCurrentPage(currentPage - 1)
      } else {
        await refetch()
      }
    } catch (err: any) {
      alert(err.detail || t('analyses.deleteError'))
    } finally {
      setDeleting(null)
    }
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(new Set(analyses.map(a => a.id)))
    } else {
      setSelectedIds(new Set())
    }
  }

  const handleSelectOne = (id: number, checked: boolean) => {
    const newSelected = new Set(selectedIds)
    if (checked) {
      newSelected.add(id)
    } else {
      newSelected.delete(id)
    }
    setSelectedIds(newSelected)
  }

  const handleDeleteMultiple = async () => {
    if (selectedIds.size === 0) return

    setDeletingMultiple(true)
    const idsArray = Array.from(selectedIds)
    const originalCount = idsArray.length
    
    try {
      for (const id of idsArray) {
        try {
          await deleteAnalysisById(id)
        } catch (err: any) {
          // Continue deleting others even if one fails
        }
      }
      setDeleteMultipleConfirm(false)
      setSelectedIds(new Set())
      
      // Nếu xóa hết items của trang và không phải trang đầu, quay về trang trước
      if (analyses.length <= originalCount && currentPage > 1) {
        setCurrentPage(currentPage - 1)
      } else {
        await refetch()
      }
    } catch (err: any) {
      alert(err.detail || t('analyses.deleteMultipleError'))
    } finally {
      setDeletingMultiple(false)
    }
  }

  const handlePageChange = (page: number) => {
    setCurrentPage(page)
    setSelectedIds(new Set()) // Clear selection when changing page
  }

  const handleLimitChange = (newLimit: number) => {
    setLimit(newLimit)
    setCurrentPage(1) // Reset to first page when changing limit
    setSelectedIds(new Set())
  }

  const totalPages = Math.ceil(total / limit)

  const isAllSelected = analyses.length > 0 && selectedIds.size === analyses.length
  const isIndeterminate = selectedIds.size > 0 && selectedIds.size < analyses.length

  if (loading) {
    return <LoadingState translationKey="common.loading" />
  }

  if (error) {
    return <ErrorState error={error} />
  }

  const headers = [t('analyses.id'), t('analyses.filename'), t('analyses.status'), t('analyses.analysisTime'), t('analyses.createdAt'), t('analyses.actions')]

  return (
    <div className="space-y-6">
      <PageHeader
        translationKey={{ title: 'analyses.title', subtitle: 'analyses.subtitle' }}
      />

      <Card
        title={t('analyses.cardTitle')}
        actions={
          <AnalysesToolbar
            limit={limit}
            onLimitChange={handleLimitChange}
            selectedCount={selectedIds.size}
            onDeleteSelected={() => setDeleteMultipleConfirm(true)}
            deletingMultiple={deletingMultiple}
          />
        }
      >
        {analyses.length === 0 ? (
          <EmptyState
            translationKey="analyses.noAnalyses"
            actionUrl="/upload"
            actionTranslationKey="analyses.uploadFileNow"
          />
        ) : (
          <AnalysesTable
            analyses={analyses}
            headers={headers}
            selectedIds={selectedIds}
            deleting={deleting}
            onSelectAll={handleSelectAll}
            onSelectOne={handleSelectOne}
            onDeleteClick={(id) => setDeleteConfirm(id)}
            isAllSelected={isAllSelected}
            isIndeterminate={isIndeterminate}
          />
        )}

        {analyses.length > 0 && (
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            totalItems={total}
            itemsPerPage={limit}
            currentItemsCount={analyses.length}
            onPageChange={handlePageChange}
            onItemsPerPageChange={handleLimitChange}
            itemsPerPageOptions={[10, 20, 50, 100]}
          />
        )}
      </Card>

      <ConfirmationModal
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={() => deleteConfirm && handleDelete(deleteConfirm)}
        title={t('analyses.deleteConfirm')}
        titleTranslationKey="analyses.deleteConfirm"
        description={t('analyses.deleteConfirmDescription')}
        descriptionTranslationKey="analyses.deleteConfirmDescription"
        confirmTranslationKey="analyses.delete"
        loading={deleting === deleteConfirm}
        loadingTranslationKey="analyses.deleting"
        variant="danger"
      />

      <ConfirmationModal
        isOpen={deleteMultipleConfirm}
        onClose={() => setDeleteMultipleConfirm(false)}
        onConfirm={handleDeleteMultiple}
        title={t('analyses.deleteMultipleConfirm', { count: selectedIds.size })}
        titleTranslationKey="analyses.deleteMultipleConfirm"
        titleTranslationParams={{ count: selectedIds.size }}
        description={t('analyses.deleteMultipleConfirmDescription', { count: selectedIds.size })}
        descriptionTranslationKey="analyses.deleteMultipleConfirmDescription"
        descriptionTranslationParams={{ count: selectedIds.size }}
        confirmTranslationKey="analyses.deleteSelected"
        confirmTranslationParams={{ count: selectedIds.size }}
        loading={deletingMultiple}
        loadingTranslationKey="analyses.deleting"
        variant="danger"
      />
    </div>
  )
}

export default Analyses


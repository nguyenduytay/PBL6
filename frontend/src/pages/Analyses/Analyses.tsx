import React, { useState, useEffect } from 'react'
import { useAnalyses } from '../../hooks'
import { Card, PageHeader, ErrorState, EmptyState, ConfirmationModal, Pagination } from '../../components/UI'
import { AnalysesTable, AnalysesToolbar } from './components'
import { useTranslation } from '../../hooks/useTranslation'
import { DEFAULT_PAGE_LIMIT } from '../../constants'
import { LoadingStateRing } from '@/components/LoadingState'

const Analyses: React.FC = () => {
  const { t } = useTranslation()
  const [limit, setLimit] = useState<number>(DEFAULT_PAGE_LIMIT)
  const [currentPage, setCurrentPage] = useState<number>(1)
  const offset = (currentPage - 1) * limit
  const { analyses, total, loading, error, deleteAnalysisById, deleteAnalysisByIdWithoutRefetch, refetch } = useAnalyses(limit, offset)
  const [deleting, setDeleting] = useState<number | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [deleteMultipleConfirm, setDeleteMultipleConfirm] = useState<boolean>(false)
  const [deletingMultiple, setDeletingMultiple] = useState<boolean>(false)
  const [deletingCount, setDeletingCount] = useState<number>(0)

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
      // Optimistic update: Xóa ngay trên UI
      const remainingAnalyses = analyses.filter(a => a.id !== id)
      
      await deleteAnalysisById(id)
      setDeleteConfirm(null)
      setSelectedIds(prev => {
        const newSet = new Set(prev)
        newSet.delete(id)
        return newSet
      })
      
      // Nếu xóa item cuối cùng của trang và không phải trang đầu, quay về trang trước
      if (remainingAnalyses.length === 0 && currentPage > 1) {
        setCurrentPage(currentPage - 1)
      } else {
        await refetch()
      }
    } catch (err: any) {
      alert(err.detail || t('analyses.deleteError'))
      // Nếu lỗi, refetch để đồng bộ lại
      await refetch()
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

    const idsArray = Array.from(selectedIds)
    const idsToDelete = new Set(idsArray)
    const countToDelete = idsArray.length
    
    setDeletingMultiple(true)
    setDeletingCount(countToDelete)
    
    // Optimistic update: Xóa ngay trên UI trước
    const remainingAnalyses = analyses.filter(a => !idsToDelete.has(a.id))
    
    try {
      // Xóa tất cả cùng lúc (parallel) thay vì tuần tự
      // Dùng deleteAnalysisByIdWithoutRefetch để tránh refetch nhiều lần
      const deletePromises = idsArray.map(id => 
        deleteAnalysisByIdWithoutRefetch(id).catch(() => {
          // Continue deleting others even if one fails
          return null
        })
      )
      
      await Promise.all(deletePromises)
      
      setDeleteMultipleConfirm(false)
      setSelectedIds(new Set())
      
      // Chỉ refetch 1 lần sau khi xóa xong tất cả
      // Nếu xóa hết items của trang và không phải trang đầu, quay về trang trước
      if (remainingAnalyses.length === 0 && currentPage > 1) {
        setCurrentPage(currentPage - 1)
      } else {
        await refetch()
      }
    } catch (err: any) {
      alert(err.detail || t('analyses.deleteMultipleError'))
      // Nếu lỗi, refetch để đồng bộ lại với server
      await refetch()
    } finally {
      setDeletingMultiple(false)
      setDeletingCount(0)
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

  const headers = [t('analyses.id'), t('analyses.filename'), t('analyses.status'), t('analyses.analysisTime'), t('analyses.createdAt'), t('analyses.actions')]

  return (
    <>
    {error && <ErrorState error={error} />}
    {(loading || deletingMultiple) && (
      <LoadingStateRing 
        translationKey={deletingMultiple ? 'analyses.deleting' : 'common.loading'}
        message={deletingMultiple ? t('analyses.deletingMultiple', { count: deletingCount }) : undefined}
      />
    )}
    {!loading && !deletingMultiple && (
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
    )}
    </>
  )
}

export default Analyses


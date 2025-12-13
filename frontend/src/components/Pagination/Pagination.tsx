import React from 'react'
import { Button } from '../UI'
import { useTranslation } from '../../hooks/useTranslation'

interface PaginationProps {
  currentPage: number
  totalPages: number
  totalItems: number
  itemsPerPage: number
  currentItemsCount?: number // Số items thực tế trong trang hiện tại
  onPageChange: (page: number) => void
  onItemsPerPageChange?: (itemsPerPage: number) => void
  itemsPerPageOptions?: number[]
}

const Pagination: React.FC<PaginationProps> = ({
  currentPage,
  totalPages,
  totalItems,
  itemsPerPage,
  currentItemsCount,
  onPageChange,
  onItemsPerPageChange,
  itemsPerPageOptions = [10, 20, 50, 100]
}) => {
  const { t } = useTranslation()

  const handlePrevious = () => {
    if (currentPage > 1) {
      onPageChange(currentPage - 1)
    }
  }

  const handleNext = () => {
    if (currentPage < totalPages) {
      onPageChange(currentPage + 1)
    }
  }

  const handlePageClick = (page: number) => {
    if (page >= 1 && page <= totalPages) {
      onPageChange(page)
    }
  }

  const getPageNumbers = (): number[] => {
    const pages: number[] = []
    const maxPagesToShow = 5

    if (totalPages <= maxPagesToShow) {
      // Show all pages if total pages is less than max
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i)
      }
    } else {
      // Show pages around current page
      let startPage = Math.max(1, currentPage - 2)
      let endPage = Math.min(totalPages, currentPage + 2)

      if (currentPage <= 3) {
        startPage = 1
        endPage = maxPagesToShow
      } else if (currentPage >= totalPages - 2) {
        startPage = totalPages - maxPagesToShow + 1
        endPage = totalPages
      }

      for (let i = startPage; i <= endPage; i++) {
        pages.push(i)
      }
    }

    return pages
  }

  // Calculate start and end items for current page
  const startItem = totalItems === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1
  
  // Use currentItemsCount if provided, otherwise calculate from totalItems
  let endItem: number
  if (totalItems === 0) {
    endItem = 0
  } else if (currentItemsCount !== undefined) {
    // Use actual count of items in current page
    endItem = startItem + currentItemsCount - 1
  } else {
    // Fallback: calculate from totalItems
    endItem = Math.min(currentPage * itemsPerPage, totalItems)
  }
  
  // Ensure endItem is valid
  const finalEndItem = totalItems > 0 && endItem < startItem ? startItem : Math.max(startItem, endItem)

  if (totalPages <= 1 && !onItemsPerPageChange) {
    return null
  }

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mt-6">
      {/* Items per page selector */}
      {onItemsPerPageChange && (
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">{t('pagination.itemsPerPage')}:</span>
          <select
            value={itemsPerPage}
            onChange={(e) => onItemsPerPageChange(Number(e.target.value))}
            className="px-3 py-1 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
          >
            {itemsPerPageOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Page info */}
      <div className="text-sm text-gray-400">
        {totalItems === 0 
          ? t('pagination.noResults')
          : t('pagination.showing', { start: startItem, end: finalEndItem, total: totalItems })
        }
      </div>

      {/* Pagination controls */}
      {totalPages > 1 && (
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handlePrevious}
            disabled={currentPage === 1}
          >
                    {t('common.previous')}
          </Button>

          <div className="flex items-center gap-1">
            {currentPage > 3 && totalPages > 5 && (
              <>
                <button
                  onClick={() => handlePageClick(1)}
                  className="px-3 py-1 text-sm bg-gray-700 text-white rounded hover:bg-gray-600 transition-colors"
                >
                  1
                </button>
                {currentPage > 4 && (
                  <span className="px-2 text-gray-500">...</span>
                )}
              </>
            )}

            {getPageNumbers().map((page) => (
              <button
                key={page}
                onClick={() => handlePageClick(page)}
                className={`px-3 py-1 text-sm rounded transition-colors ${
                  page === currentPage
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-700 text-white hover:bg-gray-600'
                }`}
              >
                {page}
              </button>
            ))}

            {currentPage < totalPages - 2 && totalPages > 5 && (
              <>
                {currentPage < totalPages - 3 && (
                  <span className="px-2 text-gray-500">...</span>
                )}
                <button
                  onClick={() => handlePageClick(totalPages)}
                  className="px-3 py-1 text-sm bg-gray-700 text-white rounded hover:bg-gray-600 transition-colors"
                >
                  {totalPages}
                </button>
              </>
            )}
          </div>

          <Button
            variant="secondary"
            size="sm"
            onClick={handleNext}
            disabled={currentPage === totalPages}
          >
                    {t('common.next')}
          </Button>
        </div>
      )}
    </div>
  )
}

export default Pagination


import React from 'react'
import { Button } from '../UI'
import { useTranslation } from '../../hooks/useTranslation'

interface ConfirmationModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  titleTranslationKey?: string
  titleTranslationParams?: Record<string, any>
  description: string
  descriptionTranslationKey?: string
  descriptionTranslationParams?: Record<string, any>
  confirmText?: string
  confirmTranslationKey?: string
  confirmTranslationParams?: Record<string, any>
  cancelText?: string
  cancelTranslationKey?: string
  variant?: 'danger' | 'primary'
  loading?: boolean
  loadingText?: string
  loadingTranslationKey?: string
}

const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  titleTranslationKey,
  titleTranslationParams,
  description,
  descriptionTranslationKey,
  descriptionTranslationParams,
  confirmText,
  confirmTranslationKey,
  confirmTranslationParams,
  cancelText,
  cancelTranslationKey,
  variant = 'danger',
  loading = false,
  loadingText,
  loadingTranslationKey
}) => {
  const { t } = useTranslation()

  if (!isOpen) return null

  const displayTitle = titleTranslationKey 
    ? t(titleTranslationKey, titleTranslationParams) 
    : title
  const displayDescription = descriptionTranslationKey 
    ? t(descriptionTranslationKey, descriptionTranslationParams) 
    : description
  const displayConfirmText = confirmTranslationKey 
    ? t(confirmTranslationKey, confirmTranslationParams) 
    : confirmText || t('common.delete')
  const displayCancelText = cancelTranslationKey ? t(cancelTranslationKey) : cancelText || t('common.cancel')
  const displayLoadingText = loadingTranslationKey ? t(loadingTranslationKey) : loadingText || t('common.loading')

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-xl font-bold text-white mb-4">{displayTitle}</h3>
        <p className="text-gray-400 mb-6">{displayDescription}</p>
        <div className="flex justify-end space-x-3">
          <Button
            variant="secondary"
            onClick={onClose}
            disabled={loading}
          >
            {displayCancelText}
          </Button>
          <Button
            variant={variant}
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? displayLoadingText : displayConfirmText}
          </Button>
        </div>
      </div>
    </div>
  )
}

export default ConfirmationModal


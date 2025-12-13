import React from 'react'
import { useTranslation } from '../../hooks/useTranslation'

interface LoadingStateProps {
  message?: string
  translationKey?: string
}

const LoadingState: React.FC<LoadingStateProps> = ({ message, translationKey }) => {
  const { t } = useTranslation()
  const displayMessage = translationKey ? t(translationKey) : message || t('common.loading')

  return (
    <div className="flex justify-center items-center h-64">
      <div className="text-gray-400">{displayMessage}</div>
    </div>
  )
}

export default LoadingState


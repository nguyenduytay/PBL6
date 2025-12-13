import React from 'react'
import { Button } from '../UI'
import { Link } from 'react-router-dom'
import { useTranslation } from '../../hooks/useTranslation'

interface EmptyStateProps {
  message?: string
  translationKey?: string
  actionUrl?: string
  actionText?: string
  actionTranslationKey?: string
  icon?: React.ReactNode
}

const EmptyState: React.FC<EmptyStateProps> = ({
  message,
  translationKey,
  actionUrl,
  actionText,
  actionTranslationKey,
  icon
}) => {
  const { t } = useTranslation()
  const displayMessage = translationKey ? t(translationKey) : (message || '')
  const displayActionText = actionTranslationKey 
    ? t(actionTranslationKey) 
    : actionText

  const defaultIcon = (
    <svg
      className="mx-auto h-12 w-12 text-gray-400"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
      />
    </svg>
  )

  return (
    <div className="text-center py-12">
      {icon || defaultIcon}
      <p className="mt-4 text-gray-400">{displayMessage}</p>
      {actionUrl && displayActionText && (
        <Link to={actionUrl} className="mt-4 inline-block">
          <Button>{displayActionText}</Button>
        </Link>
      )}
    </div>
  )
}

export default EmptyState


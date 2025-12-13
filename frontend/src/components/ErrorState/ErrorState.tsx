import React from 'react'
import { Card, Button } from '../UI'
import { useTranslation } from '../../hooks/useTranslation'
import { Link } from 'react-router-dom'

interface ErrorStateProps {
  error: { detail?: string } | string | null
  title?: string
  backUrl?: string
  backText?: string
}

const ErrorState: React.FC<ErrorStateProps> = ({ error, title, backUrl, backText }) => {
  const { t } = useTranslation()
  
  const errorMessage = typeof error === 'string' 
    ? error 
    : error?.detail || t('common.error')

  return (
    <Card className="border-red-600">
      <div className="text-red-400">
        {title && <p className="font-semibold mb-2">{title}</p>}
        <p>{errorMessage}</p>
        {backUrl && (
          <Link to={backUrl} className="mt-4 inline-block">
            <Button variant="secondary">{backText || t('common.back')}</Button>
          </Link>
        )}
      </div>
    </Card>
  )
}

export default ErrorState


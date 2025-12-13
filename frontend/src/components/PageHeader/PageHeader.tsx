import React from 'react'
import { useTranslation } from '../../hooks/useTranslation'

interface PageHeaderProps {
  title?: string
  subtitle?: string
  translationKey?: {
    title: string
    subtitle?: string
  }
}

const PageHeader: React.FC<PageHeaderProps> = ({ title, subtitle, translationKey }) => {
  const { t } = useTranslation()

  const displayTitle = translationKey ? t(translationKey.title) : title
  const displaySubtitle = translationKey?.subtitle ? t(translationKey.subtitle) : subtitle

  return (
    <div className="mb-8">
      <h1 className="text-3xl font-bold text-white mb-2">{displayTitle}</h1>
      {displaySubtitle && <p className="text-gray-400">{displaySubtitle}</p>}
    </div>
  )
}

export default PageHeader


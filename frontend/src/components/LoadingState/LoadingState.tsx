import React from 'react'
import { useTranslation } from '../../hooks/useTranslation'
import { RingLoader } from 'react-spinners'

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
interface LoadingStateRingProps {
  message?: string
  translationKey?: string
}

const LoadingStateRing: React.FC<LoadingStateRingProps> = ({ message, translationKey }) => {
  const { t } = useTranslation()
  const displayMessage = translationKey ? t(translationKey) : message || t('common.loading')

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex flex-col justify-center items-center z-50">
      <RingLoader color="#fff" size={50} />
      {displayMessage && (
        <p className="mt-4 text-white text-lg font-medium">{displayMessage}</p>
      )}
    </div>
  )
}
export { LoadingStateRing }
export { LoadingState }


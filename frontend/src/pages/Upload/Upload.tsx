import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { HiOutlineCloudUpload, HiOutlineX } from 'react-icons/hi'
import { useScan } from '../../hooks'
import { Card, Button, Badge, PageHeader } from '../../components/UI'
import { useTranslation } from '../../hooks/useTranslation'
import { formatFileSize } from '../../utils'

const Upload: React.FC = () => {
  const { t } = useTranslation()
  const [file, setFile] = useState<File | null>(null)
  const [dragActive, setDragActive] = useState<boolean>(false)
  const navigate = useNavigate()
  const { scan, result, loading, error, reset } = useScan()

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      reset()
    }
  }

  const handleDrag = (e: React.DragEvent<HTMLDivElement>): void => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>): void => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0])
      reset()
    }
  }

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault()
    if (!file) {
      return
    }

    await scan(file)

    // Navigate to analysis detail if we have an ID
    if (result?.id) {
      setTimeout(() => {
        navigate(`/analyses/${result.id}`)
      }, 2000)
    }
  }

  // Navigate when result changes
  React.useEffect(() => {
    if (result?.id) {
      setTimeout(() => {
        navigate(`/analyses/${result.id}`)
      }, 2000)
    }
  }, [result, navigate])

  return (
    <div className="space-y-6">
      <PageHeader
        translationKey={{ title: 'upload.title', subtitle: 'upload.subtitle' }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Form */}
        <div className="lg:col-span-2">
          <Card title={t('upload.cardTitle')} subtitle={t('upload.cardSubtitle')}>
            <form onSubmit={handleSubmit}>
              {/* Drag & Drop Area */}
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${dragActive
                  ? 'border-green-500 bg-green-900/20'
                  : 'border-gray-600 hover:border-gray-500'
                  }`}
              >
                <input
                  type="file"
                  id="file-upload"
                  onChange={handleFileChange}
                  className="hidden"
                  disabled={loading}
                />
                <label
                  htmlFor="file-upload"
                  className="cursor-pointer flex flex-col items-center"
                >
                  <HiOutlineCloudUpload className="w-16 h-16 text-gray-400 mb-4" />
                  <p className="text-white font-medium mb-2">
                    {t('upload.dragDrop')}
                  </p>
                  <p className="text-gray-400 text-sm">
                    {t('upload.supportedFormats')}
                  </p>
                </label>
              </div>

              {file && (
                <div className="mt-4 p-4 bg-gray-700 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium truncate">{file.name}</p>
                      <p className="text-gray-400 text-sm mt-1">
                        {t('upload.fileSize')}: <span className="text-gray-300 font-medium">{formatFileSize(file.size || 0)}</span>
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setFile(null)
                        reset()
                      }}
                      className="text-red-400 hover:text-red-300"
                    >
                      <HiOutlineX className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              )}

              {error && (
                <div className="mt-4 p-4 bg-red-900/20 border border-red-600 rounded-lg">
                  <p className="text-red-400">{error.detail}</p>
                </div>
              )}

              <div className="mt-6">
                <Button
                  type="submit"
                  disabled={loading || !file}
                  className="w-full"
                  size="lg"
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white inline" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      {t('upload.analyzing')}
                    </>
                  ) : (
                    t('common.submit')
                  )}
                </Button>
              </div>
            </form>

            {result && (
              <div className="mt-6 p-4 bg-gray-700 rounded-lg border border-gray-600">
                <h3 className="font-semibold text-white mb-4">{t('upload.analysisResult')}:</h3>
                <div className="space-y-3">
                  <div>
                    <span className="text-gray-400 text-sm">{t('upload.file')}:</span>
                    <p className="text-white font-medium">{result.filename}</p>
                  </div>
                  <div>
                    <span className="text-gray-400 text-sm">{t('analysisDetail.sha256')}:</span>
                    <p className="text-gray-300 text-xs font-mono break-all mt-1">
                      {result.sha256}
                    </p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-gray-400 text-sm">{t('upload.status')}:</span>
                    <Badge variant={result.malware_detected ? 'danger' : 'success'}>
                      {result.malware_detected ? t('upload.malwareDetected') : t('upload.clean')}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-gray-400 text-sm">{t('upload.analysisTime')}:</span>
                    <p className="text-white">{result.analysis_time?.toFixed(2)}s</p>
                  </div>
                  {result.id && (
                    <p className="text-sm text-green-400 mt-2">
                      {t('upload.redirecting')}
                    </p>
                  )}
                </div>
              </div>
            )}
          </Card>
        </div>

        {/* System Info Sidebar */}
        <div className="space-y-6">
          <Card title={t('common.systemInfo')} subtitle={t('upload.systemInformation')}>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-gray-400 text-sm">{t('upload.freeDiskSpace')}</span>
                  <span className="text-white text-sm">75%</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div className="bg-green-600 h-2 rounded-full" style={{ width: '75%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-gray-400 text-sm">{t('upload.cpuLoad')}</span>
                  <span className="text-white text-sm">45%</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div className="bg-blue-600 h-2 rounded-full" style={{ width: '45%' }}></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-gray-400 text-sm">{t('upload.memoryUsage')}</span>
                  <span className="text-white text-sm">62%</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div className="bg-yellow-600 h-2 rounded-full" style={{ width: '62%' }}></div>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}

export default Upload


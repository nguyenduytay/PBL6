import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { HiOutlineCloudUpload, HiOutlineX } from 'react-icons/hi'
import { ImSpinner2 } from 'react-icons/im'
import { useScan } from '../../hooks'
import type { ScanType } from '../../hooks'
import { Card, Button, Badge, PageHeader } from '../../components/UI'
import { useTranslation } from '../../hooks/useTranslation'
import { formatFileSize, isPEFile, validateFileForEmber } from '../../utils'

const Upload: React.FC = () => {
  const { t } = useTranslation()
  const [file, setFile] = useState<File | null>(null)
  const [scanType, setScanType] = useState<ScanType>('yara')
  const [dragActive, setDragActive] = useState<boolean>(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const navigate = useNavigate()
  const { scan, result, loading, error, reset } = useScan()

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0]
      setFile(selectedFile)
      reset()
      setValidationError(null)

      // Validate file if EMBER is selected
      if (scanType === 'ember') {
        const validation = validateFileForEmber(selectedFile, t)
        if (!validation.isValid) {
          setValidationError(validation.error || '')
        }
      }
    }
  }

  const handleScanTypeChange = (newScanType: ScanType): void => {
    setScanType(newScanType)
    setValidationError(null)

    // Validate file if EMBER is selected and file exists
    if (newScanType === 'ember' && file) {
      const validation = validateFileForEmber(file, t)
      if (!validation.isValid) {
        setValidationError(validation.error || '')
      }
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
      const droppedFile = e.dataTransfer.files[0]
      setFile(droppedFile)
      reset()
      setValidationError(null)

      // Validate file if EMBER is selected
      if (scanType === 'ember') {
        const validation = validateFileForEmber(droppedFile, t)
        if (!validation.isValid) {
          setValidationError(validation.error || '')
        }
      }
    }
  }

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault()
    if (!file) {
      return
    }

    // Validate file for EMBER scan
    if (scanType === 'ember') {
      const validation = validateFileForEmber(file, t)
      if (!validation.isValid) {
        setValidationError(validation.error || '')
        return
      }
    }

    await scan(file, scanType)

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

      <div className="w-full mx-auto">
        <Card title={t('upload.cardTitle')} subtitle={t('upload.cardSubtitle')}>
            <form onSubmit={handleSubmit}>
              {/* Scan Type Selection */}
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-300 mb-3">
                  {t('upload.scanType')}
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* YARA Option */}
                  <div
                    onClick={() => handleScanTypeChange('yara')}
                    className={`relative flex items-start p-4 border-2 rounded-lg cursor-pointer transition-all ${
                      scanType === 'yara'
                        ? 'border-green-500 bg-green-900/20'
                        : 'border-gray-600 hover:border-gray-500 bg-gray-800/50'
                    }`}
                  >
                    <div className="flex items-center h-5">
                      <input
                        type="radio"
                        name="scanType"
                        value="yara"
                        checked={scanType === 'yara'}
                        onChange={() => handleScanTypeChange('yara')}
                        className="w-4 h-4 text-green-600 bg-gray-700 border-gray-600 focus:ring-green-500 focus:ring-2"
                      />
                    </div>
                    <div className="ml-3 flex-1">
                      <label className="text-white font-medium cursor-pointer">
                        {t('upload.scanTypeYara')}
                      </label>
                      <p className="text-gray-400 text-sm mt-1">
                        {t('upload.scanTypeYaraDesc')}
                      </p>
                    </div>
                  </div>

                  {/* EMBER Option */}
                  <div
                    onClick={() => handleScanTypeChange('ember')}
                    className={`relative flex items-start p-4 border-2 rounded-lg cursor-pointer transition-all ${
                      scanType === 'ember'
                        ? 'border-green-500 bg-green-900/20'
                        : 'border-gray-600 hover:border-gray-500 bg-gray-800/50'
                    }`}
                  >
                    <div className="flex items-center h-5">
                      <input
                        type="radio"
                        name="scanType"
                        value="ember"
                        checked={scanType === 'ember'}
                        onChange={() => handleScanTypeChange('ember')}
                        className="w-4 h-4 text-green-600 bg-gray-700 border-gray-600 focus:ring-green-500 focus:ring-2"
                      />
                    </div>
                    <div className="ml-3 flex-1">
                      <label className="text-white font-medium cursor-pointer">
                        {t('upload.scanTypeEmber')}
                      </label>
                      <p className="text-gray-400 text-sm mt-1">
                        {t('upload.scanTypeEmberDesc')}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

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
                  accept={scanType === 'ember' ? '.exe,.dll,.sys,.scr,.drv,.ocx,.cpl,.efi,.com,.msi,.bin' : undefined}
                />
                <label
                  htmlFor="file-upload"
                  className="cursor-pointer flex flex-col items-center"
                >
                  <HiOutlineCloudUpload className="w-16 h-16 text-gray-400 mb-4" />
                  <p className="text-white font-medium mb-2">
                    {t('upload.dragDrop')}
                  </p>
                  <span className="text-gray-400 mb-2">{t('upload.or')}</span>
                  <button
                    type="button"
                    disabled={loading}
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    onClick={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      document.getElementById('file-upload')?.click()
                    }}
                  >
                    {t('upload.chooseFile')}
                  </button>
                  <p className="text-gray-400 text-sm mt-2">
                    {scanType === 'ember' 
                      ? t('upload.scanTypeEmberDesc')
                      : t('upload.supportedFormats')
                    }
                  </p>
                </label>
              </div>

              {file && (
                <div className="mt-4 p-4 bg-gray-700 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2">
                        <p className="text-white font-medium truncate">{file.name}</p>
                        {scanType === 'ember' && isPEFile(file) && (
                          <Badge variant="success" className="text-xs">{t('upload.peFile')}</Badge>
                        )}
                        {scanType === 'ember' && !isPEFile(file) && (
                          <Badge variant="danger" className="text-xs">{t('upload.notPeFile')}</Badge>
                        )}
                      </div>
                      <p className="text-gray-400 text-sm mt-1">
                        {t('upload.fileSize')}: <span className="text-gray-300 font-medium">{formatFileSize(file.size || 0)}</span>
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setFile(null)
                        reset()
                        setValidationError(null)
                      }}
                      className="text-red-400 hover:text-red-300"
                    >
                      <HiOutlineX className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              )}

              {validationError && (
                <div className="mt-4 p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg">
                  <p className="text-yellow-400 text-sm">{validationError}</p>
                </div>
              )}

              {error && (
                <div className="mt-4 p-4 bg-red-900/20 border border-red-600 rounded-lg">
                  <p className="text-red-400">{error.detail || error.message}</p>
                </div>
              )}

              <div className="mt-6">
                <Button
                  type="submit"
                  disabled={loading || !file || (scanType === 'ember' && validationError !== null)}
                  className="w-full"
                  size="lg"
                >
                  {loading ? (
                    <>
                      <ImSpinner2 className="animate-spin -ml-1 mr-3 h-5 w-5 text-white inline" />
                      {t('upload.analyzing')}
                    </>
                  ) : (
                    t('common.submit')
                  )}
                </Button>
              </div>
            </form>

            {result && (
              <div className="mt-6 space-y-4">
                {/* Basic Result Info */}
                <div className="p-4 bg-gray-700 rounded-lg border border-gray-600">
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

                {/* Detailed Results (YARA, EMBER, Errors) */}
                {result.results && Array.isArray(result.results) && result.results.length > 0 && (
                  <div className="p-4 bg-gray-700 rounded-lg border border-gray-600">
                    <h3 className="font-semibold text-white mb-4">{t('upload.detailedResults')}:</h3>
                    <div className="space-y-3">
                      {result.results.map((item, index) => {
                        // EMBER Error
                        if (item.type === 'ember_error' || (item.type === 'model' && item.subtype === 'ember' && item.error)) {
                          return (
                            <div
                              key={index}
                              className="p-4 bg-red-900/20 border border-red-600 rounded-lg"
                            >
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <p className="font-medium text-red-400 mb-1">
                                    {t('upload.emberError')}
                                  </p>
                                  <p className="text-sm text-red-300 mb-2">{item.message || item.error}</p>
                                  {item.error_detail && (
                                    <p className="text-xs text-gray-400 mt-1">
                                      <span className="font-semibold">{t('upload.errorDetail')}:</span> {item.error_detail}
                                    </p>
                                  )}
                                  {item.error_type && (
                                    <p className="text-xs text-gray-400 mt-1">
                                      <span className="font-semibold">{t('upload.errorType')}:</span> {item.error_type}
                                    </p>
                                  )}
                                  {item.file_path && (
                                    <p className="text-xs text-gray-400 mt-1">
                                      <span className="font-semibold">{t('upload.file')}:</span> {item.file_path}
                                    </p>
                                  )}
                                </div>
                              </div>
                            </div>
                          )
                        }
                        
                        // EMBER Result (Success) - Hiển thị cả khi không có error
                        const isEmberResult = (item.type === 'model' && item.subtype === 'ember') ||
                                            (item.type === 'model' && item.score !== undefined)
                        
                        if (isEmberResult && !item.error) {
                          return (
                            <div
                              key={index}
                              className={`p-4 rounded-lg border ${
                                item.score && item.score > (item.threshold || 0.5)
                                  ? 'bg-yellow-900/20 border-yellow-600'
                                  : 'bg-green-900/20 border-green-600'
                              }`}
                            >
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <p className={`font-medium mb-1 ${
                                    item.score && item.score > (item.threshold || 0.5)
                                      ? 'text-yellow-400'
                                      : 'text-green-400'
                                  }`}>
                                    {t('upload.emberResult')}
                                  </p>
                                  <p className="text-sm text-gray-300 mb-2">{item.message}</p>
                                  {item.score !== undefined && (
                                    <div className="mt-2 space-y-1">
                                      <p className="text-xs text-gray-400">
                                        <span className="font-semibold">{t('upload.score')}:</span> {
                                          item.score < 0.0001 
                                            ? item.score.toExponential(2) 
                                            : item.score.toFixed(6)
                                        }
                                      </p>
                                      {item.threshold !== undefined && (
                                        <p className="text-xs text-gray-400">
                                          <span className="font-semibold">{t('upload.threshold')}:</span> {item.threshold.toFixed(4)}
                                        </p>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          )
                        }

                        // YARA Matches (already displayed separately, but show in results too)
                        if (item.type === 'yara') {
                          return (
                            <div
                              key={index}
                              className="p-4 bg-yellow-900/20 border border-yellow-600 rounded-lg"
                            >
                              <p className="font-medium text-yellow-400 mb-1">
                                {t('upload.yaraMatch')}
                              </p>
                              <p className="text-sm text-gray-300">{item.message || item.matches}</p>
                            </div>
                          )
                        }

                        // Other results
                        return (
                          <div
                            key={index}
                            className="p-4 bg-gray-800/50 border border-gray-600 rounded-lg"
                          >
                            <p className="font-medium text-gray-300 mb-1">
                              {t('upload.resultType')}: {item.type} {item.subtype ? `(${item.subtype})` : ''}
                            </p>
                            <p className="text-sm text-gray-400">{item.message || JSON.stringify(item)}</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </Card>
      </div>
    </div>
  )
}

export default Upload

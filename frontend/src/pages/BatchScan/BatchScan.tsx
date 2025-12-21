import React, { useState, useRef } from 'react'
import { useBatchScan } from '../../hooks/useBatchScan'
import { Card, Button, Badge, PageHeader, ErrorState } from '../../components/UI'
import { useTranslation } from '../../hooks/useTranslation'
import { MAX_UPLOAD_SIZE_GB, MAX_UPLOAD_SIZE_BYTES } from '../../constants'
import { validateFilesTotalSize, formatFileSizeGB, filterFilesByExtension, getFolderNameFromFile } from '../../utils'

const BatchScan: React.FC = () => {
  const { t } = useTranslation()
  const { scanFolderUpload, getStatus, status, result, loading, error } = useBatchScan()
  const [fileExtensions, setFileExtensions] = useState('')
  const [batchId, setBatchId] = useState('')
  const [selectedFolder, setSelectedFolder] = useState<FileList | null>(null)
  const [selectedFolderName, setSelectedFolderName] = useState<string>('')
  const [totalSize, setTotalSize] = useState<number>(0)
  const [sizeError, setSizeError] = useState<string>('')
  const folderInputRef = useRef<HTMLInputElement>(null)

  const handleFolderSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (files && files.length > 0) {
      const filesArray = Array.from(files)
      
      // Calculate total size manually to ensure it's correct
      const calculatedTotalSize = filesArray.reduce((sum, file) => {
        return sum + (file.size || 0)
      }, 0)
      
      const validation = validateFilesTotalSize(filesArray)
      
      // Use calculated total size instead of validation.totalSize
      setTotalSize(calculatedTotalSize)
      
      if (!validation.isValid) {
        const sizeGB = formatFileSizeGB(calculatedTotalSize)
        setSizeError(t('batchScan.totalSizeExceeds', { sizeGB, maxGB: MAX_UPLOAD_SIZE_GB }))
        setSelectedFolder(null)
        setSelectedFolderName('')
        setTotalSize(0)
        return
      } else {
        setSizeError('')
      }
      
      setSelectedFolder(files)
      const folderName = getFolderNameFromFile(files[0])
      setSelectedFolderName(folderName)
    } else {
      // Reset when no files selected
      setTotalSize(0)
      setSelectedFolder(null)
      setSelectedFolderName('')
      setSizeError('')
    }
  }

  const handleScanFolder = async () => {
    if (!selectedFolder || selectedFolder.length === 0) {
      alert(t('batchScan.pleaseSelectFolder'))
      return
    }

    const filesArray = Array.from(selectedFolder)
    const validation = validateFilesTotalSize(filesArray)

    if (!validation.isValid) {
      const sizeGB = formatFileSizeGB(validation.totalSize || 0)
      alert(t('batchScan.totalSizeExceeds', { sizeGB, maxGB: MAX_UPLOAD_SIZE_GB }))
      return
    }

    let filesToUpload = filesArray
    if (fileExtensions.trim()) {
      const extensions = fileExtensions.split(',').map(ext => ext.trim())
      filesToUpload = filterFilesByExtension(filesArray, extensions)
    }

    if (filesToUpload.length === 0) {
      alert(t('batchScan.noFilesMatching'))
      return
    }

    await scanFolderUpload(filesToUpload)
    if (status) {
      setBatchId(status.batch_id)
    }
  }

  const handleCheckStatus = async () => {
    if (!batchId) return
    await getStatus(batchId)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        translationKey={{ title: 'batchScan.title', subtitle: 'batchScan.subtitle' }}
      />

      <div className="grid grid-cols-1 gap-6">
        {/* Scan Folder */}
        <Card title={t('batchScan.scanFolder')} subtitle={t('batchScan.scanFolderSubtitle')}>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                {t('batchScan.selectFolder')}
              </label>
              <input
                ref={folderInputRef}
                type="file"
                id="folder-upload"
                {...({ webkitdirectory: '', directory: '' } as any)}
                multiple
                onChange={handleFolderSelect}
                className="hidden"
              />
              <div className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg flex items-center">
                <button
                  type="button"
                  onClick={() => folderInputRef.current?.click()}
                  disabled={loading}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {t('batchScan.chooseFolderButton')}
                </button>
                <span className="ml-4 text-gray-400 text-sm">
                  {selectedFolderName || t('common.noFolderSelected')}
                </span>
              </div>
              {!selectedFolderName && (
                <p className="mt-2 text-sm text-gray-500">{t('common.noFolderSelected')}</p>
              )}
              {selectedFolderName && (
                <div className="mt-2 space-y-1">
                  <p className="text-sm text-green-400">
                    {t('batchScan.selected')}: {selectedFolderName} ({selectedFolder?.length || 0} {t('batchScan.files')})
                  </p>
                  <p className="text-sm text-gray-400">
                    {t('batchScan.totalSize')}: {formatFileSizeGB(totalSize)} / {MAX_UPLOAD_SIZE_GB} {t('batchScan.unitGB')}
                  </p>
                </div>
              )}
              {sizeError && (
                <p className="mt-2 text-sm text-red-400">{sizeError}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                {t('batchScan.fileExtensions')} ({t('batchScan.fileExtensionsHint')})
              </label>
              <input
                type="text"
                value={fileExtensions}
                onChange={(e) => setFileExtensions(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-green-500"
                placeholder={t('batchScan.fileExtensionsPlaceholder')}
              />
            </div>

            <div className="text-sm text-gray-400 bg-gray-800 p-3 rounded-lg">
              <p className="font-medium mb-1">{t('batchScan.uploadLimits')}:</p>
              <p>{t('batchScan.maxSize')}: {MAX_UPLOAD_SIZE_GB} {t('batchScan.unitGB')} {t('batchScan.perUpload')}</p>
              <p className="text-xs mt-1 text-gray-500">{t('batchScan.filesExceedingLimit')}</p>
            </div>

            <Button 
              onClick={handleScanFolder} 
              disabled={loading || !selectedFolder || selectedFolder.length === 0 || !!sizeError} 
              className="w-full"
            >
              {loading ? t('batchScan.scanning') : t('batchScan.scanFolder')}
            </Button>
          </div>
        </Card>
      </div>

      {/* Status */}
      {status && (
        <Card title={t('batchScan.batchStatus')}>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">{t('batchScan.batchId')}:</span>
              <code className="text-green-400">{status.batch_id}</code>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">{t('batchScan.status')}:</span>
              <Badge
                variant={
                  status.status === 'completed'
                    ? 'success'
                    : status.status === 'failed'
                    ? 'danger'
                    : 'warning'
                }
              >
                {status.status}
              </Badge>
            </div>
            <div className="grid grid-cols-4 gap-4">
              <div>
                <div className="text-gray-400 text-sm">{t('batchScan.total')}</div>
                <div className="text-white text-xl font-bold">{status.total_files}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">{t('batchScan.processed')}</div>
                <div className="text-white text-xl font-bold">{status.processed}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">{t('batchScan.completed')}</div>
                <div className="text-green-400 text-xl font-bold">{status.completed}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">{t('batchScan.failed')}</div>
                <div className="text-red-400 text-xl font-bold">{status.failed}</div>
              </div>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={batchId}
                onChange={(e) => setBatchId(e.target.value)}
                placeholder={t('batchScan.batchIdPlaceholder')}
                className="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              />
              <Button onClick={handleCheckStatus} disabled={loading || !batchId}>
                {t('batchScan.checkStatus')}
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <Card title={t('batchScan.batchResults')}>
          <div className="space-y-4">
            <div className="text-sm text-gray-400">
              {t('batchScan.showingResults', { count: result.results.length })}
            </div>
            <div className="max-h-96 overflow-y-auto">
              <table className="w-full text-left">
                <thead className="bg-gray-700">
                  <tr>
                    <th className="px-4 py-2 text-gray-300">{t('batchScan.tableFilename')}</th>
                    <th className="px-4 py-2 text-gray-300">{t('batchScan.tableSha256')}</th>
                    <th className="px-4 py-2 text-gray-300">{t('batchScan.tableStatus')}</th>
                  </tr>
                </thead>
                <tbody>
                  {result.results.map((r, idx) => (
                    <tr key={idx} className="border-b border-gray-700">
                      <td className="px-4 py-2 text-white">{r.filename}</td>
                      <td className="px-4 py-2 text-gray-400 text-xs">{r.sha256 || t('analysisDetail.na')}</td>
                      <td className="px-4 py-2">
                        <Badge variant={r.malware_detected ? 'danger' : 'success'}>
                          {r.malware_detected ? t('batchScan.tableMalware') : t('batchScan.tableClean')}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Card>
      )}

      {error && (
        <ErrorState error={error} />
      )}
    </div>
  )
}

export default BatchScan


import React, { useState } from 'react'
import { Button } from '../UI'
import { useTranslation } from '../../hooks/useTranslation'
import { exportApi } from '../../api'

interface ExportButtonsProps {
  onExportCSV?: () => Promise<Blob>
  onExportJSON?: () => Promise<any>
  onExportExcel?: () => Promise<Blob>
  limit?: number
  offset?: number
}

const ExportButtons: React.FC<ExportButtonsProps> = ({
  onExportCSV,
  onExportJSON,
  onExportExcel,
  limit = 1000,
  offset = 0
}) => {
  const { t } = useTranslation()
  const [exporting, setExporting] = useState(false)

  const handleExportCSV = async () => {
    setExporting(true)
    try {
      const blob = onExportCSV 
        ? await onExportCSV()
        : await exportApi.exportAnalysesCSV(limit, offset)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analyses_${new Date().getTime()}.csv`
      link.click()
      
      // Cleanup after a short delay
      setTimeout(() => {
        document.body.removeChild(link)
        URL.revokeObjectURL(url)
      }, 100)
    } catch (err: any) {
      // Export failed silently
    } finally {
      setExporting(false)
    }
  }

  const handleExportJSON = async () => {
    setExporting(true)
    try {
      const data = onExportJSON
        ? await onExportJSON()
        : await exportApi.exportAnalysesJSON(limit, offset)
      const dataStr = JSON.stringify(data, null, 2)
      const blob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analyses_${new Date().getTime()}.json`
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      // Export failed silently
    } finally {
      setExporting(false)
    }
  }

  const handleExportExcel = async () => {
    setExporting(true)
    try {
      const blob = onExportExcel
        ? await onExportExcel()
        : await exportApi.exportAnalysesExcel(limit, offset)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analyses_${new Date().getTime()}.xlsx`
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      // Export failed silently
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="flex items-center space-x-2">
      <Button
        variant="secondary"
        size="sm"
        onClick={handleExportCSV}
        disabled={exporting}
      >
        {exporting ? t('analyses.exporting') : t('analyses.exportCSV')}
      </Button>
      <Button
        variant="secondary"
        size="sm"
        onClick={handleExportJSON}
        disabled={exporting}
      >
        {exporting ? t('analyses.exporting') : t('analyses.exportJSON')}
      </Button>
      <Button
        variant="secondary"
        size="sm"
        onClick={handleExportExcel}
        disabled={exporting}
      >
        {exporting ? t('analyses.exporting') : t('analyses.exportExcel')}
      </Button>
    </div>
  )
}

export default ExportButtons


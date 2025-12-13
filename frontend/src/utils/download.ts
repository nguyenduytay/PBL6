/**
 * Download utility functions
 */

/**
 * Download file from blob
 * @param blob - Blob object to download
 * @param filename - Name of the file to download
 */
export const downloadBlob = (blob: Blob, filename: string): void => {
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

/**
 * Download JSON data as file
 * @param data - Data object to download
 * @param filename - Name of the file (default: "data.json")
 */
export const downloadJSON = (data: any, filename: string = 'data.json'): void => {
  const jsonString = JSON.stringify(data, null, 2)
  const blob = new Blob([jsonString], { type: 'application/json' })
  downloadBlob(blob, filename)
}

/**
 * Download text as file
 * @param text - Text content to download
 * @param filename - Name of the file
 * @param mimeType - MIME type (default: "text/plain")
 */
export const downloadText = (
  text: string,
  filename: string,
  mimeType: string = 'text/plain'
): void => {
  const blob = new Blob([text], { type: mimeType })
  downloadBlob(blob, filename)
}

/**
 * Download CSV data
 * @param csvContent - CSV content string
 * @param filename - Name of the file (default: "data.csv")
 */
export const downloadCSV = (csvContent: string, filename: string = 'data.csv'): void => {
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  downloadBlob(blob, filename)
}

/**
 * Convert array of objects to CSV string
 * @param data - Array of objects
 * @param headers - Optional array of header names (if not provided, uses object keys)
 * @returns CSV string
 */
export const arrayToCSV = (data: any[], headers?: string[]): string => {
  if (data.length === 0) return ''
  
  const csvHeaders = headers || Object.keys(data[0])
  const csvRows = [csvHeaders.join(',')]
  
  data.forEach(row => {
    const values = csvHeaders.map(header => {
      const value = row[header]
      // Escape commas and quotes in CSV
      if (value === null || value === undefined) return ''
      const stringValue = String(value)
      if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
        return `"${stringValue.replace(/"/g, '""')}"`
      }
      return stringValue
    })
    csvRows.push(values.join(','))
  })
  
  return csvRows.join('\n')
}


import React from 'react'

interface TableProps<T> {
  headers: string[]
  data: T[]
  renderRow: (row: T, index: number) => React.ReactNode
  className?: string
}

function Table<T>({ headers, data, renderRow, className = '' }: TableProps<T>): React.ReactElement {
  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="min-w-full divide-y divide-gray-700">
        <thead className="bg-gray-800">
          <tr>
            {headers.map((header, index) => (
              <th
                key={index}
                className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider"
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="bg-gray-800 divide-y divide-gray-700">
          {data.map((row, index) => (
            <tr key={index} className="hover:bg-gray-750 transition-colors">
              {renderRow(row, index)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default Table


import React from 'react'

type StatCardVariant = 'default' | 'danger' | 'success' | 'warning'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: React.ReactNode
  trend?: {
    value: string
    positive: boolean
  }
  variant?: StatCardVariant
  className?: string
}

const StatCard: React.FC<StatCardProps> = ({ 
  title, 
  value, 
  subtitle, 
  icon, 
  trend, 
  variant = 'default', 
  className = '' 
}) => {
  const variantClasses: Record<StatCardVariant, string> = {
    default: 'bg-gray-800 border-gray-700',
    danger: 'bg-red-900/20 border-red-600',
    success: 'bg-green-900/20 border-green-600',
    warning: 'bg-yellow-900/20 border-yellow-600',
  }

  return (
    <div className={`rounded-lg p-6 border ${variantClasses[variant] || variantClasses.default} ${className}`}>
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className="mt-2 text-3xl font-bold text-white">{value}</p>
          {subtitle && <p className="mt-1 text-sm text-gray-500">{subtitle}</p>}
          {trend && (
            <div className={`mt-2 flex items-center text-sm ${trend.positive ? 'text-green-400' : 'text-red-400'}`}>
              <svg
                className={`w-4 h-4 mr-1 ${trend.positive ? '' : 'rotate-180'}`}
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M5.293 7.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 5.414V17a1 1 0 11-2 0V5.414L6.707 7.707a1 1 0 01-1.414 0z"
                  clipRule="evenodd"
                />
              </svg>
              {trend.value}
            </div>
          )}
        </div>
        {icon && (
          <div className="flex-shrink-0 ml-4">
            <div className="w-12 h-12 bg-gray-700 rounded-lg flex items-center justify-center text-gray-300">
              {icon}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default StatCard


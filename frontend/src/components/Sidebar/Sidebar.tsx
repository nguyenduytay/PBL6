import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from '../../hooks/useTranslation'

interface MenuItem {
  icon: React.ReactNode
  label: string
  path: string
}

const Sidebar: React.FC = () => {
  const { t } = useTranslation()
  const location = useLocation()
  const [isCollapsed, setIsCollapsed] = useState<boolean>(false)

  const isActive = (path: string): boolean => location.pathname === path

  const menuItems: MenuItem[] = [
    {
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
        </svg>
      ),
      label: t('nav.dashboard'),
      path: '/',
    },
    {
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
        </svg>
      ),
      label: t('common.submit'),
      path: '/upload',
    },
    {
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
        </svg>
      ),
      label: t('nav.recent'),
      path: '/analyses',
    },
    {
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
      label: t('nav.search'),
      path: '/search',
    },
    {
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
      ),
      label: t('nav.batchScan'),
      path: '/batch-scan',
    },
  ]

  return (
    <aside
      className={`bg-gray-800 text-white transition-all duration-300 flex flex-col ${isCollapsed ? 'w-16' : 'w-64'
        } min-h-screen border-r border-gray-700`}
    >
      {/* Collapse Toggle */}
      <div className="flex justify-end p-4 border-b border-gray-700">
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="p-2 rounded-md hover:bg-gray-700 transition-colors"
          title={isCollapsed ? t('common.expandSidebar') : t('common.collapseSidebar')}
        >
          <svg
            className={`w-5 h-5 transition-transform ${isCollapsed ? '' : 'rotate-180'}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
          </svg>
        </button>
      </div>

      {/* Menu Items */}
      <nav className="p-4 space-y-2">
        {menuItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${isActive(item.path)
              ? 'bg-green-600 text-white'
              : 'text-gray-300 hover:bg-gray-700 hover:text-white'
              }`}
            title={isCollapsed ? item.label : ''}
          >
            <span className="flex-shrink-0">{item.icon}</span>
            {!isCollapsed && <span className="font-medium">{item.label}</span>}
          </Link>
        ))}
      </nav>

      {/* System Info Section */}
      {!isCollapsed && (
        <div className="mt-auto pt-4 border-t border-gray-700">
          <div className="text-xs text-gray-400 mb-2 px-4">{t('common.systemInfo')}</div>
          <div className="space-y-2 text-sm px-4 pb-4">
            <div className="flex justify-between">
              <span className="text-gray-400">{t('dashboard.status')}:</span>
              <span className="text-green-400 font-semibold">{t('dashboard.online')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">{t('dashboard.version')}:</span>
              <span className="text-gray-300">1.0.0</span>
            </div>
          </div>
        </div>
      )}
    </aside>
  )
}

export default Sidebar


import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from '../../hooks/useTranslation'
import {
  HiOutlineHome,
  HiOutlineCloudUpload,
  HiOutlineDocumentText,
  HiOutlineSearch,
  HiOutlineDownload,
} from "react-icons/hi";


interface MenuItem {
  icon: React.ReactNode
  label: string
  path: string
}

interface SidebarProps {
  onCollapseChange?: (isCollapsed: boolean) => void
}

const Sidebar: React.FC<SidebarProps> = ({ onCollapseChange }) => {
  const { t } = useTranslation()
  const location = useLocation()
  const [isCollapsed, setIsCollapsed] = useState<boolean>(false)

  const handleToggle = () => {
    const newState = !isCollapsed
    setIsCollapsed(newState)
    onCollapseChange?.(newState)
  }

  const isActive = (path: string): boolean => location.pathname === path

  const menuItems: MenuItem[] = [
    {
      icon: <HiOutlineHome className="w-5 h-5" />,
      label: t("nav.dashboard"),
      path: "/",
    },
    {
      icon: <HiOutlineCloudUpload className="w-5 h-5" />,
      label: t("common.submit"),
      path: "/upload",
    },
    {
      icon: <HiOutlineDocumentText className="w-5 h-5" />,
      label: t("nav.recent"),
      path: "/analyses",
    },
    {
      icon: <HiOutlineSearch className="w-5 h-5" />,
      label: t("nav.search"),
      path: "/search",
    },
    {
      icon: <HiOutlineDownload className="w-5 h-5" />,
      label: t("nav.batchScan"),
      path: "/batch-scan",
    },
  ];


  return (
    <aside
      className={`bg-gray-800 text-white transition-all duration-300 flex flex-col fixed top-[100px] left-0 bottom-0 z-40 ${isCollapsed ? 'w-20' : 'w-64'
        } border-r border-gray-700`}
    >
      {/* Collapse Toggle */}
      <div className="flex justify-end p-4 border-b border-gray-700">
        <button
          onClick={handleToggle}
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


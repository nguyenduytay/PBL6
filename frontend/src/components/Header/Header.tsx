import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import LanguageSwitcher from '../LanguageSwitcher'
import { useTranslation } from '../../hooks/useTranslation'
import Lottie from 'lottie-react'
import animationData from "../../assets/animations/Meditating Monkey.json"

const Header: React.FC = () => {
  const { t } = useTranslation()
  const location = useLocation()

  const isActive = (path: string): boolean => location.pathname === path

  return (
    <header className="bg-gray-900 text-white shadow-lg border-b border-gray-800 fixed top-0 left-0 right-0 z-50 h-[100px]">
      <div className="flex items-center justify-between px-6 h-full">
        {/* Logo & Title */}
        <div className="flex items-center space-x-4">
          <Link to="/" className="flex items-center space-x-3 hover:opacity-80 transition-opacity">
            <img src="/images/cyber-security.png" alt="Logo" className="h-[80px] w-[80px]" />
            <div className="hidden md:block">
              <h1 className="text-xl font-bold">Malware Detector</h1>
              <p className="text-xs text-gray-400">Security Analysis Platform</p>
            </div>
          </Link>
          <Lottie
            animationData={animationData}
            style={{ width: 100, height: 100 }}
            loop
            autoplay
          />
        </div>

        {/* Top Navigation */}
        <nav className="hidden md:flex items-center space-x-1">
          <Link
            to="/"
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${isActive('/')
              ? 'bg-green-600 text-white'
              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
          >
            {t('nav.dashboard')}
          </Link>
          <Link
            to="/upload"
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${isActive('/upload')
              ? 'bg-green-600 text-white'
              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
          >
            {t('common.submit')}
          </Link>
          <Link
            to="/analyses"
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${isActive('/analyses')
              ? 'bg-green-600 text-white'
              : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`}
          >
            {t('nav.analyses')}
          </Link>
        </nav>

        <div className="flex items-center space-x-4">
          <LanguageSwitcher />
        </div>
      </div>
    </header>
  )
}

export default Header


import React, { useState, useRef, useEffect } from 'react'
import { useTranslation } from '../../hooks/useTranslation'
import { languages } from '../../lang'

const LanguageSwitcher: React.FC = () => {
  const { language, changeLanguage } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Get current language object
  const currentLang = languages.find((lang) => lang.code === language) || languages[0]

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleLanguageChange = (langCode: string) => {
    changeLanguage(langCode)
    setIsOpen(false)
  }

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Dropdown Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="bg-gray-800 text-white px-3 py-2 rounded-md text-sm border border-gray-700 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 cursor-pointer flex items-center gap-2 min-w-[140px]"
      >
        <img src={currentLang.image} alt={currentLang.name} className="w-6 h-4 object-cover rounded" />
        <span>{currentLang.name}</span>
        <svg
          className={`w-4 h-4 ml-auto transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute top-full mt-1 w-full bg-gray-800 border border-gray-700 rounded-md shadow-lg z-50 overflow-hidden">
          {languages.map((lang) => (
            <button
              key={lang.code}
              onClick={() => handleLanguageChange(lang.code)}
              className={`w-full px-3 py-2 text-left text-sm flex items-center gap-2 hover:bg-gray-700 transition-colors ${lang.code === language ? 'bg-gray-700 text-green-400' : 'text-white'
                }`}
            >
              <img src={lang.image} alt={lang.name} className="w-6 h-4 object-cover rounded" />
              <span>{lang.name}</span>
              {lang.code === language && (
                <svg className="w-4 h-4 ml-auto text-green-400" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fillRule="evenodd"
                    d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                    clipRule="evenodd"
                  />
                </svg>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default LanguageSwitcher


import React from 'react'
import { useTranslation } from '../../hooks/useTranslation'
import { languages } from '../../lang'

const LanguageSwitcher: React.FC = () => {
  const { language, changeLanguage } = useTranslation()

  return (
    <div className="relative">
      <select
        value={language}
        onChange={(e) => changeLanguage(e.target.value)}
        className="bg-gray-800 text-white px-3 py-2 rounded-md text-sm border border-gray-700 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 cursor-pointer"
      >
        {languages.map((lang) => (
          <option key={lang.code} value={lang.code}>
            {lang.name}
          </option>
        ))}
      </select>
    </div>
  )
}

export default LanguageSwitcher


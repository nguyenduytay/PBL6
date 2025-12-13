/**
 * useTranslation Hook - Custom hook for translations
 * Wrapper around react-i18next's useTranslation
 */
import { useTranslation as useI18nTranslation } from 'react-i18next'

export const useTranslation = () => {
  const { t, i18n } = useI18nTranslation()

  return {
    t, // Translation function
    i18n, // i18n instance
    language: i18n.language, // Current language
    changeLanguage: (lang: string) => {
      i18n.changeLanguage(lang)
      localStorage.setItem('language', lang)
    },
  }
}

export default useTranslation


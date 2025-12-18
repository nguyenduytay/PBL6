/**
 * i18n Configuration and Language Setup
 */
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './en.json'
import vi from './vi.json'
import zh from './zh.json'

// Language resources
const resources = {
  en: {
    translation: en,
  },
  vi: {
    translation: vi,
  },
  zh: {
    translation: zh,
  },
}

// Initialize i18n
i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: localStorage.getItem('language') || 'en', // Default language from localStorage or 'en'
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false, // React already escapes values
    },
    react: {
      useSuspense: false, // Disable suspense for better compatibility
    },
  })

export default i18n

// Export language list
export const languages = [
  { code: 'en', name: 'English', image: '/images/en.png' },
  { code: 'vi', name: 'Tiếng Việt', image: '/images/vi.png' },
  { code: 'zh', name: '中文', image: '/images/china.png' },
]

// Helper function to change language
export const changeLanguage = (lang: string) => {
  i18n.changeLanguage(lang)
  localStorage.setItem('language', lang)
}


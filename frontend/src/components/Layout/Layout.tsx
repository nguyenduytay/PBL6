import React, { useState } from 'react'
import Header from '../Header'
import Sidebar from '../Sidebar'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false)

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header - Fixed at top */}
      <Header />

      {/* Main Layout */}
      <div className="flex pt-[100px]">
        {/* Sidebar - Fixed at left, below header */}
        <Sidebar onCollapseChange={setIsSidebarCollapsed} />

        {/* Main Content - With padding to account for sidebar */}
        <main 
          className={`flex-1 p-6 transition-all duration-300 ${
            isSidebarCollapsed ? 'ml-16' : 'ml-64'
          }`}
        >
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

export default Layout


import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard/Dashboard'
import Upload from './pages/Upload/Upload'
import Analyses from './pages/Analyses/Analyses'
import AnalysisDetail from './pages/AnalysisDetail/AnalysisDetail'
import BatchScan from './pages/BatchScan/BatchScan'
import Search from './pages/Search/Search'

const App: React.FC = () => {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/analyses" element={<Analyses />} />
          <Route path="/analyses/:id" element={<AnalysisDetail />} />
          <Route path="/batch-scan" element={<BatchScan />} />
          <Route path="/search" element={<Search />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App


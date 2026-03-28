import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import SentinelComplete from './SentinelComplete.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <SentinelComplete />
  </StrictMode>,
)

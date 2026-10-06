import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import LoginPage from '@/pages/LoginPage'
import DashboardLayout from '@/pages/DashboardLayout'
import OverviewPage from '@/pages/OverviewPage'
import SkinPage from '@/pages/SkinPage'
import CapePage from '@/pages/CapePage'
import SettingsPage from '@/pages/SettingsPage'
import AdminPage from '@/pages/AdminPage'
function Protected() { return localStorage.getItem('mc_access_token') ? <DashboardLayout /> : <Navigate to="/login" replace /> }
export default function App() { return <BrowserRouter><Routes><Route path="/login" element={<LoginPage />} /><Route element={<Protected />}><Route path="/" element={<Navigate to="/dashboard" replace />} /><Route path="/dashboard" element={<OverviewPage />} /><Route path="/skin" element={<SkinPage />} /><Route path="/cape" element={<CapePage />} /><Route path="/settings" element={<SettingsPage />} /><Route path="/admin" element={<AdminPage />} /></Route><Route path="*" element={<Navigate to="/dashboard" replace />} /></Routes></BrowserRouter> }

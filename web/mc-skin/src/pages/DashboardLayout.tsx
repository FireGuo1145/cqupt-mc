import { useEffect, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Flag, LayoutDashboard, LogOut, Palette, Settings, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import SiteFooter from '@/components/SiteFooter'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'

export default function DashboardLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const [isAdmin, setIsAdmin] = useState(false)

  useEffect(() => {
    const token = localStorage.getItem('mc_access_token')
    if (!token) return
    fetch('/api/admin/users', { headers: { Authorization: `Bearer ${token}` } })
      .then(response => { if (response.ok) setIsAdmin(true) })
      .catch(() => {})
  }, [])

  const logout = () => {
    localStorage.clear()
    navigate('/login')
  }
  const links = [
    { to: '/dashboard', label: '概览', icon: LayoutDashboard },
    { to: '/skin', label: '我的皮肤', icon: Palette },
    { to: '/cape', label: '我的披风', icon: Flag },
    { to: '/settings', label: '账号设置', icon: Settings },
    ...(isAdmin ? [{ to: '/admin', label: '管理员后台', icon: ShieldCheck }] : []),
  ]

  return (
    <SidebarProvider>
      <Sidebar variant="sidebar">
        <SidebarHeader>
          <div className="flex items-center gap-3 px-2 py-2">
            <span className="grid size-8 place-items-center rounded-md bg-sidebar-primary text-sm font-bold text-sidebar-primary-foreground">MC</span>
            <span className="text-sm font-semibold">SKIN / AUTH</span>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarMenu>
            {links.map(({ to, label, icon: Icon }) => {
              const active = location.pathname === to || location.pathname.startsWith(`${to}/`)
              return (
                <SidebarMenuItem key={to}>
                  <SidebarMenuButton
                    isActive={active}
                    className="data-[active=true]:bg-sidebar-accent data-[active=true]:text-sidebar-accent-foreground data-[active=true]:font-medium"
                    onPress={() => navigate(to)}
                  >
                    <Icon />
                    {label}
                  </SidebarMenuButton>
                </SidebarMenuItem>
              )
            })}
          </SidebarMenu>
        </SidebarContent>
        <SidebarFooter>
          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-sm">{localStorage.getItem('mc_username')}</span>
            <Button variant="ghost" size="icon" aria-label="退出登录" onPress={logout}>
              <LogOut size={17} />
            </Button>
          </div>
        </SidebarFooter>
      </Sidebar>
      <SidebarInset>
        <header className="flex h-14 items-center gap-2 border-b px-4">
          <SidebarTrigger />
          <span className="text-sm text-muted-foreground">玩家控制台</span>
        </header>
        <div className="w-full flex-1 p-6 md:p-10">
          <Outlet />
        </div>
        <SiteFooter />
      </SidebarInset>
    </SidebarProvider>
  )
}

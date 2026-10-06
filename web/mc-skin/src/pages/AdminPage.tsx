import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Check, ClipboardList, Pencil, Plus, ShieldAlert, Users, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

type ManagedUser = {
  id: number
  studentId: string
  username: string
  banned: boolean
  createdAt: string
  isAdmin: boolean
  isCurrent: boolean
}
type ManualApplication = { id: number; studentId: string; username: string; submittedAt: string }
type UserForm = { studentId: string; username: string; password: string; confirmPassword: string; banned: boolean }
const emptyUserForm: UserForm = { studentId: '', username: '', password: '', confirmPassword: '', banned: false }

async function readJSON<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => ({})) as { error?: string }
  if (!response.ok) throw new Error(data.error || `请求失败 (${response.status})`)
  return data as T
}

export default function AdminPage() {
  const token = localStorage.getItem('mc_access_token') || ''
  const [users, setUsers] = useState<ManagedUser[]>([])
  const [applications, setApplications] = useState<ManualApplication[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [userDialogOpen, setUserDialogOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<ManagedUser | null>(null)
  const [userForm, setUserForm] = useState<UserForm>(emptyUserForm)
  const [reviewDialogOpen, setReviewDialogOpen] = useState(false)
  const [reviewingApplication, setReviewingApplication] = useState<ManualApplication | null>(null)
  const [reviewAction, setReviewAction] = useState<'approve' | 'reject'>('approve')
  const [reviewNote, setReviewNote] = useState('')

  const api = useCallback((path: string, init: RequestInit = {}) => fetch(path, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.headers as Record<string, string> | undefined),
    },
  }), [token])

  const loadData = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [userResponse, applicationResponse] = await Promise.all([
        api('/api/admin/users'),
        api('/api/admin/applications'),
      ])
      const [userData, applicationData] = await Promise.all([
        readJSON<ManagedUser[]>(userResponse),
        readJSON<ManualApplication[]>(applicationResponse),
      ])
      setUsers(userData)
      setApplications(applicationData)
    } catch (err) {
      setError(err instanceof Error ? err.message : '无法加载管理员数据')
    } finally {
      setLoading(false)
    }
  }, [api])

  useEffect(() => {
    const timer = window.setTimeout(() => { void loadData() }, 0)
    return () => window.clearTimeout(timer)
  }, [loadData])

  function openCreateDialog() {
    setEditingUser(null)
    setUserForm(emptyUserForm)
    setError('')
    setUserDialogOpen(true)
  }

  function openEditDialog(user: ManagedUser) {
    setEditingUser(user)
    setUserForm({ studentId: user.studentId, username: user.username, password: '', confirmPassword: '', banned: user.banned })
    setError('')
    setUserDialogOpen(true)
  }

  async function saveUser(event: FormEvent) {
    event.preventDefault()
    setError('')
    setNotice('')
    if (userForm.password !== userForm.confirmPassword) {
      setError('两次输入的本站密码不一致')
      return
    }
    if (!editingUser && !userForm.password) {
      setError('新用户必须设置本站密码')
      return
    }
    setBusy(true)
    try {
      const response = await api('/api/admin/users/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: editingUser?.id || 0,
          studentId: userForm.studentId,
          username: userForm.username,
          password: userForm.password,
          confirmPassword: userForm.confirmPassword,
          banned: userForm.banned,
        }),
      })
      const result = await readJSON<{ username: string }>(response)
      setUserDialogOpen(false)
      if (editingUser?.isCurrent && userForm.password) {
        setNotice('管理员密码已更新，正在返回登录页重新登录…')
        window.setTimeout(() => {
          localStorage.clear()
          window.location.assign('/login')
        }, 900)
        return
      }
      if (editingUser?.isCurrent) localStorage.setItem('mc_username', result.username)
      setNotice(editingUser ? '用户信息已更新。' : '用户已添加。')
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : '保存用户失败')
    } finally {
      setBusy(false)
    }
  }

  function openReview(application: ManualApplication, action: 'approve' | 'reject') {
    setReviewingApplication(application)
    setReviewAction(action)
    setReviewNote('')
    setError('')
    setReviewDialogOpen(true)
  }

  async function reviewApplication(event: FormEvent) {
    event.preventDefault()
    if (!reviewingApplication) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const response = await api('/api/admin/applications/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: reviewingApplication.id, action: reviewAction, note: reviewNote }),
      })
      await readJSON<{ ok: boolean }>(response)
      setReviewDialogOpen(false)
      setNotice(reviewAction === 'approve' ? `${reviewingApplication.username} 已通过审核并创建账号。` : `${reviewingApplication.username} 的申请已拒绝。`)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : '审核失败')
    } finally {
      setBusy(false)
    }
  }

  const updateUserForm = (key: keyof UserForm, value: string | boolean) => setUserForm(previous => ({ ...previous, [key]: value }))

  return (
    <div className="mx-auto grid max-w-6xl gap-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-sm text-muted-foreground">账号管理</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight">管理员后台</h1>
          <p className="mt-2 text-sm text-muted-foreground">添加、修改用户，并审核离校生人工注册申请。</p>
        </div>
        <Button onPress={openCreateDialog}><Plus size={16} />添加用户</Button>
      </header>

      {error && <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm" role="alert">{error}</p>}
      {notice && <p className="rounded-md border bg-muted p-3 text-sm" role="status">{notice}</p>}

      <section className="grid gap-4">
        <div className="flex items-center gap-2">
          <ClipboardList size={18} />
          <h2 className="text-xl font-semibold">待审核人工注册</h2>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{applications.length}</span>
        </div>
        <div className="overflow-x-auto rounded-xl border bg-card">
          {loading ? <p className="p-6 text-sm text-muted-foreground">正在加载…</p> : applications.length === 0 ? (
            <div className="grid min-h-28 place-items-center p-6 text-center text-sm text-muted-foreground">目前没有待审核申请。</div>
          ) : <table className="w-full min-w-[620px] text-left text-sm">
            <thead className="border-b bg-muted/40 text-muted-foreground">
              <tr><th className="px-4 py-3 font-medium">统一账号</th><th className="px-4 py-3 font-medium">本站用户名</th><th className="px-4 py-3 font-medium">提交时间</th><th className="px-4 py-3 text-right font-medium">操作</th></tr>
            </thead>
            <tbody>
              {applications.map(application => <tr key={application.id} className="border-b last:border-0">
                <td className="px-4 py-3 font-mono">{application.studentId}</td>
                <td className="px-4 py-3 font-medium">{application.username}</td>
                <td className="px-4 py-3 text-muted-foreground">{new Date(application.submittedAt).toLocaleString('zh-CN')}</td>
                <td className="px-4 py-3"><div className="flex justify-end gap-2">
                  <Button size="sm" variant="outline" onPress={() => openReview(application, 'reject')}><X size={15} />拒绝</Button>
                  <Button size="sm" onPress={() => openReview(application, 'approve')}><Check size={15} />通过</Button>
                </div></td>
              </tr>)}
            </tbody>
          </table>}
        </div>
      </section>

      <section className="grid gap-4">
        <div className="flex items-center gap-2">
          <Users size={18} />
          <h2 className="text-xl font-semibold">本站用户</h2>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{users.length}</span>
        </div>
        <div className="overflow-x-auto rounded-xl border bg-card">
          {loading ? <p className="p-6 text-sm text-muted-foreground">正在加载…</p> : users.length === 0 ? (
            <p className="p-6 text-sm text-muted-foreground">没有可显示的用户。</p>
          ) : <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="border-b bg-muted/40 text-muted-foreground">
              <tr><th className="px-4 py-3 font-medium">统一账号</th><th className="px-4 py-3 font-medium">本站用户名</th><th className="px-4 py-3 font-medium">状态</th><th className="px-4 py-3 font-medium">注册时间</th><th className="px-4 py-3 text-right font-medium">操作</th></tr>
            </thead>
            <tbody>
              {users.map(user => <tr key={user.id} className="border-b last:border-0">
                <td className="px-4 py-3 font-mono">{user.studentId}{user.isAdmin && <span className="ml-2 rounded bg-primary/10 px-1.5 py-0.5 font-sans text-xs text-primary">管理员</span>}</td>
                <td className="px-4 py-3 font-medium">{user.username}</td>
                <td className="px-4 py-3">{user.banned ? <span className="inline-flex items-center gap-1 text-destructive"><ShieldAlert size={14} />已封禁</span> : <span className="text-muted-foreground">正常</span>}</td>
                <td className="px-4 py-3 text-muted-foreground">{user.createdAt ? new Date(user.createdAt).toLocaleDateString('zh-CN') : '—'}</td>
                <td className="px-4 py-3 text-right"><Button size="sm" variant="outline" onPress={() => openEditDialog(user)}><Pencil size={15} />编辑</Button></td>
              </tr>)}
            </tbody>
          </table>}
        </div>
      </section>

      <Dialog isOpen={userDialogOpen} onOpenChange={open => { if (!busy) setUserDialogOpen(open) }} isDismissable={!busy}>
        <DialogHeader>
          <DialogTitle>{editingUser ? '编辑用户' : '添加用户'}</DialogTitle>
          <DialogDescription>用户账号与本站密码保存在本地账号库中；密码只保存哈希。</DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={saveUser}>
          <div className="grid gap-2"><Label htmlFor="admin-student-id">统一账号</Label><Input id="admin-student-id" value={userForm.studentId} onChange={event => updateUserForm('studentId', event.target.value)} inputMode="numeric" pattern="[0-9]+" maxLength={64} required disabled={editingUser?.isAdmin} />{editingUser?.isAdmin && <p className="text-xs text-muted-foreground">环境变量指定的管理员统一账号不可修改。</p>}</div>
          <div className="grid gap-2"><Label htmlFor="admin-username">本站用户名</Label><Input id="admin-username" value={userForm.username} onChange={event => updateUserForm('username', event.target.value)} pattern="[A-Za-z0-9]+" minLength={3} maxLength={64} required /></div>
          <div className="grid gap-2"><Label htmlFor="admin-password">{editingUser ? '新本站密码（留空不修改）' : '本站密码'}</Label><Input id="admin-password" type="password" autoComplete="new-password" value={userForm.password} onChange={event => updateUserForm('password', event.target.value)} minLength={6} maxLength={256} required={!editingUser} /></div>
          <div className="grid gap-2"><Label htmlFor="admin-password-confirm">再次输入密码</Label><Input id="admin-password-confirm" type="password" autoComplete="new-password" value={userForm.confirmPassword} onChange={event => updateUserForm('confirmPassword', event.target.value)} minLength={6} maxLength={256} required={!editingUser || userForm.password !== ''} /></div>
          <label className={`flex items-center gap-2 text-sm ${editingUser?.isAdmin ? 'text-muted-foreground' : ''}`}>
            <input type="checkbox" className="size-4 accent-primary" checked={userForm.banned} disabled={editingUser?.isAdmin} onChange={event => updateUserForm('banned', event.target.checked)} />封禁该账号
            {editingUser?.isAdmin && <span className="text-xs">环境变量指定的管理员不可封禁</span>}
          </label>
          {error && <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm" role="alert">{error}</p>}
          <DialogFooter><Button type="button" variant="outline" onPress={() => setUserDialogOpen(false)} isDisabled={busy}>取消</Button><Button type="submit" isDisabled={busy}>{busy ? '保存中…' : '保存'}</Button></DialogFooter>
        </form>
      </Dialog>

      <Dialog isOpen={reviewDialogOpen} onOpenChange={open => { if (!busy) setReviewDialogOpen(open) }} isDismissable={!busy}>
        <DialogHeader>
          <DialogTitle>{reviewAction === 'approve' ? '通过人工注册申请' : '拒绝人工注册申请'}</DialogTitle>
          <DialogDescription>{reviewingApplication ? `${reviewingApplication.studentId} · ${reviewingApplication.username}` : ''}{reviewAction === 'approve' ? '：通过后将立即创建可登录的本站账号。' : '：拒绝后会清除申请中存储的密码哈希。'}</DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={reviewApplication}>
          <div className="grid gap-2"><Label htmlFor="review-note">审核备注（可选）</Label><Input id="review-note" value={reviewNote} onChange={event => setReviewNote(event.target.value)} maxLength={500} placeholder="仅供管理员查看" /></div>
          {error && <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm" role="alert">{error}</p>}
          <DialogFooter><Button type="button" variant="outline" onPress={() => setReviewDialogOpen(false)} isDisabled={busy}>取消</Button><Button type="submit" variant={reviewAction === 'reject' ? 'destructive' : 'default'} isDisabled={busy}>{busy ? '处理中…' : reviewAction === 'approve' ? '确认通过' : '确认拒绝'}</Button></DialogFooter>
        </form>
      </Dialog>
    </div>
  )
}

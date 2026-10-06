import { useEffect, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Dialog, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import SiteFooter from '@/components/SiteFooter'

type Mode = 'login' | 'register' | 'manual' | 'recover'
type CasAction = 'register' | 'recover'
type Form = {
  studentId: string
  studentPassword: string
  username: string
  password: string
  confirmPassword: string
}
type CaptchaChallenge = { captchaToken: string; captchaImage: string }
const empty: Form = { studentId: '', studentPassword: '', username: '', password: '', confirmPassword: '' }
const modeLabels: Record<Mode, string> = {
  login: '本站登录',
  register: '在校生注册',
  manual: '离校生人工注册',
  recover: '找回账号/密码',
}

export default function LoginPage() {
  const navigate = useNavigate()
  const [siteName, setSiteName] = useState('CQUPT Minecraft')
  const [legal, setLegal] = useState({ tos: false, privacy: false })
  const [mode, setMode] = useState<Mode>('login')
  const [form, setForm] = useState<Form>(empty)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [challenge, setChallenge] = useState<CaptchaChallenge | null>(null)
  const [captchaAction, setCaptchaAction] = useState<CasAction | null>(null)
  const [captcha, setCaptcha] = useState('')

  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(d => {
      if (d.siteName) {
        setSiteName(d.siteName)
        document.title = d.siteName
      }
    }).catch(() => {})
    fetch('/api/legal').then(r => r.json()).then(setLegal).catch(() => {})
  }, [])

  const update = (key: keyof Form) => (e: ChangeEvent<HTMLInputElement>) =>
    setForm(previous => ({ ...previous, [key]: e.target.value }))

  function switchMode(next: Mode) {
    setMode(next)
    setMessage('')
    setChallenge(null)
    setCaptchaAction(null)
    setCaptcha('')
    setForm(previous => ({ ...previous, studentPassword: '', password: '', confirmPassword: '' }))
  }

  async function sendRegistration(captchaAnswer = '', captchaToken = '') {
    let response: Response
    let data: { code?: string; captchaToken?: string; captchaImage?: string; error?: string }
    try {
      response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          studentId: form.studentId,
          studentPassword: form.studentPassword,
          username: form.username,
          password: form.password,
          captcha: captchaAnswer,
          captchaToken,
        }),
      })
      data = await response.json()
    } catch (error) {
      setForm(previous => ({ ...previous, studentPassword: '' }))
      throw error
    }
    if (response.status === 428 && data.code === 'captcha-required' && data.captchaToken && data.captchaImage) {
      setCaptcha('')
      setCaptchaAction('register')
      setChallenge({ captchaToken: data.captchaToken, captchaImage: data.captchaImage })
      return
    }
    if (!response.ok) {
      setForm(previous => ({ ...previous, studentPassword: '' }))
      throw new Error(data.error || '注册失败')
    }
    setForm(empty)
    setChallenge(null)
    setCaptchaAction(null)
    setMode('login')
    setMessage('注册成功，请使用本站用户名和密码登录。')
  }

  async function sendRecovery(captchaAnswer = '', captchaToken = '') {
    let response: Response
    let data: { code?: string; captchaToken?: string; captchaImage?: string; error?: string; message?: string; username?: string }
    try {
      response = await fetch('/api/account/recover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          studentId: form.studentId,
          studentPassword: form.studentPassword,
          newPassword: form.password,
          confirmPassword: form.confirmPassword,
          captcha: captchaAnswer,
          captchaToken,
        }),
      })
      data = await response.json()
    } catch (error) {
      setForm(previous => ({ ...previous, studentPassword: '', password: '', confirmPassword: '' }))
      throw error
    }
    if (response.status === 428 && data.code === 'captcha-required' && data.captchaToken && data.captchaImage) {
      setCaptcha('')
      setCaptchaAction('recover')
      setChallenge({ captchaToken: data.captchaToken, captchaImage: data.captchaImage })
      return
    }
    if (!response.ok) {
      setForm(previous => ({ ...previous, studentPassword: '', password: '', confirmPassword: '' }))
      throw new Error(data.error || '找回失败')
    }
    setForm(empty)
    setChallenge(null)
    setCaptchaAction(null)
    setMessage(data.message || `找回成功，本站用户名为 ${data.username || '（未知）'}。请务必牢记新密码。`)
    setMode('login')
  }

  async function sendManualApplication() {
    if (form.password !== form.confirmPassword) throw new Error('两次输入的本站密码不一致')
    const response = await fetch('/api/manual-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // Do not send the CAS password in the alumni/manual channel.
      body: JSON.stringify({
        studentId: form.studentId,
        username: form.username,
        password: form.password,
        confirmPassword: form.confirmPassword,
      }),
    })
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || '申请提交失败')
    setForm(empty)
    setMode('login')
    setMessage(data.message || '人工注册申请已提交，审核通过后即可登录。')
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setMessage('')
    setBusy(true)
    try {
      if (mode === 'register') {
        await sendRegistration()
      } else if (mode === 'recover') {
        if (form.password !== form.confirmPassword) throw new Error('两次输入的新密码不一致')
        await sendRecovery()
      } else if (mode === 'manual') {
        await sendManualApplication()
      } else {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: form.username, password: form.password }),
        })
        const data = await response.json()
        if (!response.ok) throw new Error(data.error || '登录失败')
        localStorage.setItem('mc_access_token', data.accessToken)
        localStorage.setItem('mc_username', data.username)
        navigate('/dashboard')
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  async function submitCaptcha(e: FormEvent) {
    e.preventDefault()
    if (!challenge || !captcha.trim() || !captchaAction) return
    setBusy(true)
    setMessage('')
    try {
      if (captchaAction === 'register') await sendRegistration(captcha.trim(), challenge.captchaToken)
      else await sendRecovery(captcha.trim(), challenge.captchaToken)
    } catch (err) {
      setChallenge(null)
      setCaptchaAction(null)
      setMessage(err instanceof Error ? err.message : '验证失败，请重新验证')
    } finally {
      setBusy(false)
    }
  }

  const field = (text: string, key: keyof Form, props: React.ComponentProps<typeof Input> = {}) => (
    <div className="grid gap-2">
      <Label htmlFor={key}>{text}</Label>
      <Input id={key} value={form[key]} onChange={update(key)} {...props} />
    </div>
  )

  const submitLabel = mode === 'login' ? '登录启动器'
    : mode === 'register' ? '验证并注册'
      : mode === 'manual' ? '提交人工注册申请'
        : '验证并找回账号/重设密码'

  return (
    <div className="flex min-h-screen flex-col bg-muted/40">
      <main className="grid flex-1 place-items-center p-6">
        <div className="grid w-full max-w-5xl gap-10 lg:grid-cols-[1fr_440px] lg:items-center">
          <div className="space-y-6">
            <div className="grid size-12 place-items-center rounded-md bg-primary font-bold text-primary-foreground">MC</div>
            <p className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">{siteName}</p>
            <h1 className="text-5xl font-semibold tracking-tight md:text-7xl">方块世界，<em className="block not-italic">自由登录</em></h1>
            <p className="max-w-md text-lg text-muted-foreground">在校生使用重庆邮电大学统一身份认证注册；离校生可提交人工注册申请。</p>
          </div>
          <section className="rounded-xl border bg-card p-6 shadow-sm">
            <div className="mb-6 grid grid-cols-2 gap-2 border-b pb-4">
              {(Object.keys(modeLabels) as Mode[]).map(item => (
                <Button key={item} type="button" size="sm" variant={mode === item ? 'default' : 'ghost'} onPress={() => switchMode(item)}>
                  {modeLabels[item]}
                </Button>
              ))}
            </div>
            {mode === 'manual' && <p className="mb-4 rounded-md border bg-muted p-3 text-sm text-muted-foreground">离校生无需提交统一认证密码。申请经管理员审核通过后，方可使用本站账号登录。</p>}
            {mode === 'recover' && <div className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm"><p className="font-medium">每个统一认证账号每天只能找回一次密码。</p><p className="mt-1 text-muted-foreground">重设成功后，页面会显示本站用户名。请务必牢记刚设置的新密码；为保护账号，原有登录会话将失效。</p></div>}
            <form className="grid gap-4" onSubmit={submit}>
              {(mode === 'register' || mode === 'manual' || mode === 'recover') && field('重邮统一账号', 'studentId', { required: true, inputMode: 'numeric', pattern: '[0-9]+', maxLength: 64, placeholder: '统一验证号码，非学号' })}
              {(mode === 'register' || mode === 'recover') && field('统一账号密码', 'studentPassword', { required: true, type: 'password', autoComplete: 'off', maxLength: 256, placeholder: '仅用于统一认证验证，不会保存' })}
              {(mode === 'login' || mode === 'register' || mode === 'manual') && field('本站用户名', 'username', { required: true, pattern: '[A-Za-z0-9]+', minLength: 3, maxLength: 64, autoComplete: 'username', placeholder: '至少 3 位，仅限英文和数字' })}
              {(mode === 'login' || mode === 'register') && field('本站密码', 'password', { required: true, minLength: 6, maxLength: 256, type: 'password', autoComplete: mode === 'login' ? 'current-password' : 'new-password', placeholder: '至少 6 位' })}
              {(mode === 'manual' || mode === 'recover') && <>
                {field(mode === 'recover' ? '新本站密码' : '本站密码', 'password', { required: true, minLength: 6, maxLength: 256, type: 'password', autoComplete: 'new-password', placeholder: '至少 6 位' })}
                {field('再次输入本站密码', 'confirmPassword', { required: true, minLength: 6, maxLength: 256, type: 'password', autoComplete: 'new-password', placeholder: '请再次输入，确保两次一致' })}
              </>}
              <Button type="submit" className="w-full" isDisabled={busy}>{busy ? '正在处理…' : submitLabel}</Button>
            </form>
            {message && <p className="mt-4 rounded-md border bg-muted p-3 text-sm" role="status">{message}</p>}
            {(legal.tos || legal.privacy) && <p className="mt-4 text-center text-xs text-muted-foreground">继续即表示同意 {legal.tos && <a className="underline" href="/tos.html" target="_blank" rel="noreferrer">用户协议</a>}{legal.tos && legal.privacy ? ' 和 ' : ''}{legal.privacy && <a className="underline" href="/privacy.html" target="_blank" rel="noreferrer">隐私政策</a>}</p>}
          </section>
        </div>
        <Dialog
          isOpen={challenge !== null}
          onOpenChange={open => {
            if (!open && !busy) {
              setChallenge(null)
              setCaptchaAction(null)
              setForm(previous => ({ ...previous, studentPassword: '', password: '', confirmPassword: '' }))
            }
          }}
          isDismissable={!busy}
        >
          <DialogHeader><DialogTitle>统一认证验证码</DialogTitle></DialogHeader>
          <form className="grid gap-4" onSubmit={submitCaptcha}>
            <img src={challenge?.captchaImage} alt="统一认证验证码" className="h-20 w-full rounded-md border bg-white object-contain" />
            <div className="grid gap-2">
              <Label htmlFor="captcha">图片中的验证码</Label>
              <Input id="captcha" value={captcha} onChange={e => setCaptcha(e.target.value)} autoComplete="off" required autoFocus />
            </div>
            <Button type="submit" isDisabled={busy || !captcha.trim()}>{busy ? '正在验证…' : captchaAction === 'recover' ? '验证并找回' : '确认并注册'}</Button>
          </form>
        </Dialog>
      </main>
      <SiteFooter />
    </div>
  )
}

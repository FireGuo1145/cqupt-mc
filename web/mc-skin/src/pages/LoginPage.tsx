import { useEffect, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Dialog, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import SiteFooter from '@/components/SiteFooter'

type Mode = 'login' | 'register'
type Form = { studentId: string; studentPassword: string; username: string; password: string }
type CaptchaChallenge = { captchaToken: string; captchaImage: string }
const empty: Form = { studentId: '', studentPassword: '', username: '', password: '' }

export default function LoginPage() {
  const navigate = useNavigate()
  const [siteName, setSiteName] = useState('CQUPT Minecraft')
  const [legal, setLegal] = useState({ tos: false, privacy: false })
  const [mode, setMode] = useState<Mode>('login')
  const [form, setForm] = useState<Form>(empty)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [challenge, setChallenge] = useState<CaptchaChallenge | null>(null)
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

  async function sendRegistration(captchaAnswer = '', captchaToken = '') {
    let response: Response
    let data: { code?: string; captchaToken?: string; captchaImage?: string; error?: string }
    try {
      response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, captcha: captchaAnswer, captchaToken }),
      })
      data = await response.json()
    } catch (error) {
      setForm(previous => ({ ...previous, studentPassword: '' }))
      throw error
    }
    if (response.status === 428 && data.code === 'captcha-required' && data.captchaToken && data.captchaImage) {
      setCaptcha('')
      setChallenge({ captchaToken: data.captchaToken, captchaImage: data.captchaImage })
      return
    }
    if (!response.ok) {
      setForm(previous => ({ ...previous, studentPassword: '' }))
      throw new Error(data.error || '注册失败')
    }
    setForm(empty)
    setChallenge(null)
    setMode('login')
    setMessage('注册成功，请登录')
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setMessage('')
    setBusy(true)
    try {
      if (mode === 'register') {
        await sendRegistration()
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
    if (!challenge || !captcha.trim()) return
    setBusy(true)
    setMessage('')
    try {
      await sendRegistration(captcha.trim(), challenge.captchaToken)
    } catch (err) {
      setChallenge(null)
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

  return (
    <div className="flex min-h-screen flex-col bg-muted/40">
      <main className="grid flex-1 place-items-center p-6">
        <div className="grid w-full max-w-5xl gap-10 lg:grid-cols-[1fr_420px] lg:items-center">
          <div className="space-y-6">
            <div className="grid size-12 place-items-center rounded-md bg-primary font-bold text-primary-foreground">MC</div>
            <p className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">{siteName}</p>
            <h1 className="text-5xl font-semibold tracking-tight md:text-7xl">方块世界，<em className="block not-italic">自由登录</em></h1>
            <p className="max-w-md text-lg text-muted-foreground">使用重庆邮电大学统一身份认证完成注册，然后用本站账号登录启动器。</p>
          </div>
          <section className="rounded-xl border bg-card p-6 shadow-sm">
            <div className="mb-6 flex gap-2 border-b pb-4">
              <Button type="button" variant={mode === 'login' ? 'default' : 'ghost'} onPress={() => setMode('login')}>本站登录</Button>
              <Button type="button" variant={mode === 'register' ? 'default' : 'ghost'} onPress={() => setMode('register')}>注册账号</Button>
            </div>
            <form className="grid gap-4" onSubmit={submit}>
              {mode === 'register' && <>
                {field('重邮统一账号', 'studentId', { required: true, inputMode: 'numeric', pattern: '[0-9]+', placeholder: '统一验证号码，非学号' })}
                {field('统一账号密码', 'studentPassword', { required: true, type: 'password', autoComplete: 'off', placeholder: '统一身份认证密码，仅作验证，不会保存' })}
              </>}
              {field('本站用户名', 'username', { required: true, pattern: '[A-Za-z0-9]+', placeholder: '英文和数字' })}
              {field('本站密码', 'password', { required: true, minLength: 6, type: 'password', placeholder: '至少 6 位' })}
              <Button type="submit" className="w-full" isDisabled={busy}>{busy ? '正在验证…' : mode === 'login' ? '登录启动器' : '验证并注册'}</Button>
            </form>
            {message && <p className="mt-4 rounded-md border bg-muted p-3 text-sm">{message}</p>}
            {(legal.tos || legal.privacy) && <p className="mt-4 text-center text-xs text-muted-foreground">继续即表示同意 {legal.tos && <a className="underline" href="/tos.html" target="_blank">用户协议</a>}{legal.tos && legal.privacy ? ' 和 ' : ''}{legal.privacy && <a className="underline" href="/privacy.html" target="_blank">隐私政策</a>}</p>}
          </section>
        </div>
        <Dialog
          isOpen={challenge !== null}
          onOpenChange={open => {
            if (!open && !busy) {
              setChallenge(null)
              setForm(previous => ({ ...previous, studentPassword: '' }))
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
            <Button type="submit" isDisabled={busy || !captcha.trim()}>{busy ? '正在验证…' : '确认并注册'}</Button>
          </form>
        </Dialog>
      </main>
      <SiteFooter />
    </div>
  )
}

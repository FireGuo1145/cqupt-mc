import { useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import './index.css'

type Mode = 'login' | 'register'
const empty = { studentId: '', studentPassword: '', captcha: '', username: '', password: '' }

export default function App() {
  const [mode, setMode] = useState<Mode>('login')
  const [form, setForm] = useState(empty)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const update = (key: keyof typeof empty) => (e: ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: e.target.value })
  async function submit(e: FormEvent) {
    e.preventDefault(); setMessage(''); setBusy(true)
    const endpoint = mode === 'login' ? '/api/login' : '/api/register'
    try {
      let body: typeof form | { username: string; password: string } = mode === 'login' ? { username: form.username, password: form.password } : form
      let response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      let data = await response.json()
      if (!response.ok && data.code === 'captcha-required' && mode === 'register') {
        const captcha = window.prompt('统一认证需要验证码，请输入验证码：')
        if (!captcha?.trim()) throw new Error('未输入验证码，注册已取消')
        body = { ...form, captcha: captcha.trim() }
        response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); data = await response.json()
      }
      if (!response.ok) throw new Error(data.error || '操作失败')
      setMessage(mode === 'login' ? `登录成功，欢迎 ${data.username}` : '注册成功，现在可以使用本站账号登录启动器')
      if (mode === 'register') setMode('login')
    } catch (err) { setMessage(err instanceof Error ? err.message : '操作失败') } finally { setBusy(false) }
  }
  const field = (text: string, key: keyof typeof empty, props: React.ComponentProps<typeof Input> = {}) => <div className="field"><Label htmlFor={key}>{text}</Label><Input id={key} value={form[key]} onChange={update(key)} {...props} /></div>
  return <main className="shell"><section className="hero"><div className="brand-mark">MC</div><p className="eyebrow">AUTHLIB-INJECTOR READY</p><h1>方块世界，<em>自由登录</em></h1><p className="intro">使用重庆邮电大学统一身份认证完成注册，然后用本站账号登录启动器。</p><div className="status"><span /> 服务运行正常</div></section><section className="panel"><div className="tabs"><Button type="button" variant={mode === 'login' ? 'default' : 'ghost'} onPress={() => { setMode('login'); setMessage('') }}>本站登录</Button><Button type="button" variant={mode === 'register' ? 'default' : 'ghost'} onPress={() => { setMode('register'); setMessage('') }}>注册账号</Button></div><form onSubmit={submit}>{mode === 'register' && <>{field('重邮统一账号', 'studentId', { required: true, inputMode: 'numeric', pattern: '[0-9]+', placeholder: '学号 / 工号' })}{field('统一账号密码', 'studentPassword', { required: true, type: 'password', placeholder: '统一身份认证密码' })}</>}{field('本站用户名', 'username', { required: true, pattern: '[A-Za-z0-9]+', placeholder: '英文和数字' })}{field('本站密码', 'password', { required: true, minLength: 6, type: 'password', placeholder: '至少 6 位' })}<Button type="submit" className="submit" isDisabled={busy}>{busy ? '正在验证…' : mode === 'login' ? '登录启动器' : '验证并注册'}</Button></form>{message && <p className="message">{message}</p>}<p className="fine">本站登录凭据与统一账号密码分开保存。启动器只能使用本站用户名和密码。</p></section></main>
}

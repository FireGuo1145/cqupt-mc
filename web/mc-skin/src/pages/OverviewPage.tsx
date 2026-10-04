import { CheckCircle2 } from 'lucide-react'
import AuthlibInjectorDnd from '@/components/AuthlibInjectorDnd'

export default function OverviewPage() {
  const name = localStorage.getItem('mc_username') || '玩家'
  const authURL = `${window.location.origin}/api/yggdrasil/`
  const cards = [
    ['账号状态', '正常'],
    ['皮肤', '待设置'],
    ['认证地址', authURL],
  ]

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">PLAYER CONSOLE</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">你好，{name}</h1>
        </div>
        <span className="flex items-center gap-2 text-sm text-muted-foreground">
          <CheckCircle2 size={16} />已连接
        </span>
      </header>

      <section className="flex min-h-44 flex-col items-start justify-between gap-6 rounded-xl bg-primary p-8 text-primary-foreground md:flex-row md:items-center">
        <div>
          <p className="text-xs font-medium uppercase tracking-widest opacity-70">AUTHLIB-INJECTOR</p>
          <h2 className="mt-3 text-2xl font-semibold">你的启动器账号已就绪</h2>
          <p className="mt-2 text-sm opacity-70">使用本站用户名和密码登录支持 Yggdrasil 的启动器。</p>
        </div>
        <AuthlibInjectorDnd className="shrink-0" />
      </section>

      <p className="-mt-4 text-sm text-muted-foreground">
        将按钮拖入支持 authlib-injector DnD 规范的启动器，即可添加本站；启动器会在完成拖放后询问是否添加。
      </p>

      <div className="grid gap-4 sm:grid-cols-3">
        {cards.map(([label, value]) => (
          <div className="rounded-xl border bg-card p-5" key={label}>
            <p className="text-sm text-muted-foreground">{label}</p>
            <p className="mt-3 break-all font-medium">{value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

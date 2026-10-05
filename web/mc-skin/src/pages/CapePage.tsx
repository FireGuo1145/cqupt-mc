import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'

const MAX_CAPE_BYTES = 5 * 1024 * 1024

export default function CapePage() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [capeUrl, setCapeUrl] = useState('')
  const [message, setMessage] = useState('')
  const [uploading, setUploading] = useState(false)
  const username = localStorage.getItem('mc_username') || ''

  useEffect(() => {
    if (!username) return
    let cancelled = false
    const url = `/api/cape/${encodeURIComponent(username)}?t=${Date.now()}`
    fetch(url)
      .then((response) => {
        if (!cancelled && response.ok) setCapeUrl(url)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [username])

  const upload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const input = event.currentTarget
    const file = input.files?.[0]
    if (!file) return
    if (file.size > MAX_CAPE_BYTES) {
      setMessage('披风文件不能超过 5 MiB')
      input.value = ''
      return
    }

    setUploading(true)
    setMessage('')
    try {
      const response = await fetch('/api/cape', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('mc_access_token')}`,
          'Content-Type': 'image/png',
        },
        body: file,
      })
      const data = await response.json()
      if (!response.ok) {
        setMessage(data.error || '上传失败')
        return
      }
      setCapeUrl(`/api/cape/${encodeURIComponent(username)}?t=${Date.now()}`)
      setMessage('披风已更新；请重新登录游戏或刷新角色外观')
    } catch {
      setMessage('网络错误，披风上传失败')
    } finally {
      setUploading(false)
      input.value = ''
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">APPEARANCE</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">我的披风</h1>
      </header>
      <section className="grid gap-8 rounded-xl border bg-card p-6 md:grid-cols-[300px_1fr] md:p-8">
        <div className="flex min-h-48 items-center justify-center rounded-lg bg-muted p-6">
          {capeUrl ? (
            <img
              src={capeUrl}
              alt="当前 Minecraft 披风纹理预览"
              className="aspect-[2/1] w-full max-w-64 object-contain"
              style={{ imageRendering: 'pixelated' }}
            />
          ) : (
            <p className="text-sm text-muted-foreground">暂未上传披风</p>
          )}
        </div>
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">披风纹理</h2>
          <p className="text-sm text-muted-foreground">
            上传符合 Minecraft 规范的 PNG 披风纹理（64×32 系列或旧式 22×17 系列），文件最大 5 MiB；旧式尺寸会由服务端透明补齐。再次上传会替换当前披风。
            上传后，兼容本站 Yggdrasil 的启动器可在重新登录或刷新角色后显示披风。
          </p>
          <p className="text-sm font-medium">状态：{capeUrl ? '已上传' : '待上传'}</p>
          <input
            ref={inputRef}
            className="hidden"
            type="file"
            accept="image/png,.png"
            onChange={upload}
          />
          <Button type="button" isDisabled={uploading} onPress={() => inputRef.current?.click()}>
            {uploading ? '正在上传…' : '上传 PNG 披风'}
          </Button>
          {message && <p className="rounded-md border bg-muted p-3 text-sm">{message}</p>}
        </div>
      </section>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { SkinViewer } from 'skinview3d'

export default function SkinPage() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const viewerRef = useRef<SkinViewer | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const [message, setMessage] = useState('')
  const [skinURL, setSkinURL] = useState('')
  const [hasSkin, setHasSkin] = useState(false)
  const username = localStorage.getItem('mc_username') || ''

  useEffect(() => {
    const token = localStorage.getItem('mc_access_token')
    const url = `/api/skin/${encodeURIComponent(username)}?t=${Date.now()}`
    fetch(url, { headers: { Authorization: `Bearer ${token}` } }).then((response) => {
      if (response.ok) { setSkinURL(url); setHasSkin(true) }
    }).catch(() => {})
  }, [username])

  useEffect(() => {
    if (!canvasRef.current || !skinURL) return
    viewerRef.current?.dispose()
    const viewer = new SkinViewer({ canvas: canvasRef.current, width: 280, height: 360, skin: skinURL })
    viewer.controls.enableRotate = true
    viewer.controls.enableZoom = true
    viewer.animation = null
    viewerRef.current = viewer
    return () => { viewer.dispose(); viewerRef.current = null }
  }, [skinURL])

  const upload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return
    const response = await fetch('/api/skin', { method: 'POST', headers: { Authorization: `Bearer ${localStorage.getItem('mc_access_token')}`, 'Content-Type': 'image/png' }, body: file })
    const data = await response.json()
    if (!response.ok) { setMessage(data.error || '上传失败'); return }
    setMessage('皮肤已更新'); setHasSkin(true); setSkinURL(`/api/skin/${encodeURIComponent(username)}?t=${Date.now()}`)
  }

  return <div className="mx-auto max-w-4xl space-y-8"><header><p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">APPEARANCE</p><h1 className="mt-2 text-3xl font-semibold tracking-tight">我的皮肤</h1></header><section className="grid gap-8 rounded-xl border bg-card p-6 md:grid-cols-[300px_1fr] md:p-8"><div className="flex min-h-[360px] items-center justify-center rounded-lg bg-muted">{hasSkin ? <canvas ref={canvasRef} aria-label="当前 Minecraft 皮肤 3D 预览" /> : <p className="text-sm text-muted-foreground">暂未上传皮肤</p>}</div><div className="space-y-4"><h2 className="text-xl font-semibold">当前皮肤</h2><p className="text-sm text-muted-foreground">拖动角色可以旋转预览，滚轮可以缩放。</p><p className="text-sm font-medium">状态：{hasSkin ? '已上传' : '待上传'}</p><input ref={inputRef} className="hidden" type="file" accept="image/png" onChange={upload} /><Button type="button" onPress={() => inputRef.current?.click()}>上传 PNG 皮肤</Button>{message && <p className="rounded-md border bg-muted p-3 text-sm">{message}</p>}<p className="text-xs text-muted-foreground">每个账号只能保存一张皮肤，重新上传会覆盖当前文件。</p></div></section></div>
}

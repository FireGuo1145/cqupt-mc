import type { DragEvent } from 'react'

const API_ROOT_PATH = '/api/yggdrasil/'

function createAuthlibInjectorDnDPayload(apiRoot: string) {
  return `authlib-injector:yggdrasil-server:${encodeURIComponent(apiRoot)}`
}

type AuthlibInjectorDndProps = {
  compact?: boolean
  className?: string
}

export default function AuthlibInjectorDnd({ compact = false, className = '' }: AuthlibInjectorDndProps) {
  const apiRoot = `${window.location.origin}${API_ROOT_PATH}`

  const handleDragStart = (event: DragEvent<HTMLButtonElement>) => {
    event.dataTransfer.setData('text/plain', createAuthlibInjectorDnDPayload(apiRoot))
    event.dataTransfer.effectAllowed = 'copy'
    event.dataTransfer.dropEffect = 'copy'
  }

  return (
    <button
      type="button"
      draggable="true"
      onDragStart={handleDragStart}
      title={`API Root：${apiRoot}`}
      aria-label={`拖动到支持 authlib-injector 的启动器添加本站：${apiRoot}`}
      className={`inline-flex cursor-grab select-none items-center gap-2 rounded-md border border-current/40 px-3 py-2 text-sm font-medium transition-colors hover:bg-current/10 active:cursor-grabbing focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${className}`}
    >
      <span aria-hidden="true" className="text-base leading-none">⠿</span>
      <span>{compact ? '拖动添加本站' : '拖动到启动器添加本站'}</span>
    </button>
  )
}

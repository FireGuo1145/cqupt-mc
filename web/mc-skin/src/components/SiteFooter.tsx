import { Github } from 'lucide-react'

const REPOSITORY_URL = 'https://github.com/FireGuo1145/cqupt-mc'

export default function SiteFooter() {
  return (
    <footer className="border-t px-6 py-3 text-sm text-muted-foreground">
      <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-4">
        <span>CQUPT Minecraft</span>
        <a
          aria-label="在新标签页打开 GitHub 仓库"
          className="inline-flex items-center gap-2 rounded-md px-3 py-2 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          href={REPOSITORY_URL}
          rel="noopener noreferrer"
          target="_blank"
        >
          <Github aria-hidden="true" className="size-4" />
          <span>GitHub 仓库</span>
        </a>
      </div>
    </footer>
  )
}

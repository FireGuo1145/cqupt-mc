import type { ReactNode } from 'react'
import { Dialog as DialogPrimitive, Heading, Modal, ModalOverlay } from 'react-aria-components'
import { XIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'

type DialogProps = {
  isOpen: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
}

export function Dialog({ isOpen, onOpenChange, title, children }: DialogProps) {
  return (
    <ModalOverlay isOpen={isOpen} onOpenChange={onOpenChange} isDismissable className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4 backdrop-blur-sm">
      <Modal className="w-full max-w-sm rounded-lg border bg-popover p-6 text-popover-foreground shadow-xl outline-none">
        <DialogPrimitive className="outline-none">
          <div className="mb-5 flex items-center justify-between gap-3">
            <Heading slot="title" className="text-lg font-semibold">{title}</Heading>
            <Button slot="close" variant="ghost" size="icon-sm" aria-label="关闭弹窗"><XIcon /></Button>
          </div>
          {children}
        </DialogPrimitive>
      </Modal>
    </ModalOverlay>
  )
}

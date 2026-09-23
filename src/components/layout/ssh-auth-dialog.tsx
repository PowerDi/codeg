"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useTranslations } from "next-intl"
import { KeyRound, ShieldAlert } from "lucide-react"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { getCurrentWindowLabel } from "@/lib/browser/window-label"
import { getShellTransport, isDesktop } from "@/lib/transport"

export interface SshAuthPrompt {
  requestId: string
  ownerWindow: string
  host: string
  kind: "password" | "passphrase" | "hostKey"
  prompt: string
  expiresAt: number
}

interface DismissPayload {
  requestId: string
  ownerWindow: string
}

/** Always use the local shell transport, including inside remote workspaces.
 * An SSH password must never be sent to a codeg-server's HTTP API. */
export function SshAuthDialog() {
  const [pending, setPending] = useState<SshAuthPrompt[]>([])
  const dismissed = useRef(new Set<string>())
  const remove = useCallback((requestId: string) => {
    dismissed.current.add(requestId)
    if (dismissed.current.size > 256) {
      const oldest = dismissed.current.values().next().value
      if (oldest) dismissed.current.delete(oldest)
    }
    setPending((current) =>
      current.filter((request) => request.requestId !== requestId)
    )
  }, [])

  useEffect(() => {
    if (!isDesktop()) return
    let disposed = false
    const unsubscribe: (() => void)[] = []
    const owner = getCurrentWindowLabel()
    const shell = getShellTransport()
    const enqueue = (request: SshAuthPrompt) => {
      if (
        disposed ||
        request.ownerWindow !== owner ||
        request.expiresAt <= Date.now() ||
        dismissed.current.has(request.requestId)
      )
        return
      setPending((current) =>
        current.some((item) => item.requestId === request.requestId)
          ? current
          : [...current, request]
      )
    }
    void (async () => {
      const listen = async <T,>(
        event: string,
        handler: (payload: T) => void
      ) => {
        const off = await shell.subscribe(event, handler)
        if (disposed) off()
        else unsubscribe.push(off)
      }
      await listen<SshAuthPrompt>("ssh-auth://prompt", enqueue)
      await listen<DismissPayload>("ssh-auth://dismiss", (event) => {
        if (!disposed && event.ownerWindow === owner) remove(event.requestId)
      })
      if (disposed) return
      // Recover requests emitted before listeners mounted, e.g. after a reload.
      const requests = await shell.call<SshAuthPrompt[]>(
        "list_ssh_auth_prompts"
      )
      requests.forEach(enqueue)
    })().catch(() => {
      // No raw IPC errors here: authentication payloads must not reach logs.
      // The backend fails closed if the UI cannot answer.
    })
    const timer = setInterval(() => {
      setPending((current) => {
        const live = current.filter((request) => request.expiresAt > Date.now())
        return live.length === current.length ? current : live
      })
    }, 1000)
    return () => {
      disposed = true
      clearInterval(timer)
      unsubscribe.forEach((off) => off())
    }
  }, [remove])

  const answer = useCallback(
    async (requestId: string, value: string | null) => {
      await getShellTransport().call("answer_ssh_auth_prompt", {
        requestId,
        answer: value,
      })
      remove(requestId)
    },
    [remove]
  )

  const request = pending[0]
  return request ? (
    <SshPromptForm key={request.requestId} request={request} answer={answer} />
  ) : null
}

function SshPromptForm({
  request,
  answer,
}: {
  request: SshAuthPrompt
  answer: (requestId: string, value: string | null) => Promise<void>
}) {
  const t = useTranslations("RemoteWorkspace.auth")
  const password = useRef<HTMLInputElement>(null)
  const submitting = useRef(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(false)
  const hostKey = request.kind === "hostKey"
  const title = hostKey
    ? "hostKeyTitle"
    : request.kind === "passphrase"
      ? "passphraseTitle"
      : "passwordTitle"

  const submit = async (value: string | null) => {
    if (submitting.current) return
    submitting.current = true
    setBusy(true)
    setError(false)
    // Clear the DOM immediately, even if IPC fails. Never persist in drafts,
    // React context, local/sessionStorage, a toast or a connection profile.
    if (password.current) password.current.value = ""
    try {
      await answer(request.requestId, value)
    } catch {
      setError(true)
    } finally {
      submitting.current = false
      setBusy(false)
    }
  }

  return (
    <AlertDialog
      open
      onOpenChange={(open) => {
        if (!open) void submit(null)
      }}
    >
      <AlertDialogContent
        onOpenAutoFocus={(event) => {
          if (!hostKey) {
            event.preventDefault()
            password.current?.focus()
          }
          // Host-key confirmation keeps the safe default focus on Cancel.
        }}
      >
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            {hostKey ? (
              <ShieldAlert className="size-4" />
            ) : (
              <KeyRound className="size-4" />
            )}
            {t(title)}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {t("target", { host: request.host })}{" "}
            {hostKey ? t("verifyHost") : t("sessionOnly")}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            void submit(hostKey ? "yes" : (password.current?.value ?? ""))
          }}
        >
          {/* Full OpenSSH text, including hostname and SHA256 fingerprint.
              Plain text only: never interpret remote banners as markup. */}
          <pre
            className="max-h-52 overflow-auto rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap break-words"
            dir="ltr"
          >
            {request.prompt}
          </pre>
          {!hostKey && (
            <div className="space-y-2">
              <Label htmlFor="ssh-auth-password">
                {t(
                  request.kind === "passphrase"
                    ? "passphraseLabel"
                    : "passwordLabel"
                )}
              </Label>
              <Input
                ref={password}
                id="ssh-auth-password"
                type="password"
                autoComplete="off"
                spellCheck={false}
                maxLength={4096}
                disabled={busy}
                required
              />
            </div>
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {t("failed")}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel
              type="button"
              disabled={busy}
              onClick={(event) => {
                event.preventDefault()
                void submit(null)
              }}
            >
              {t("cancel")}
            </AlertDialogCancel>
            <Button type="submit" disabled={busy}>
              {t(hostKey ? "trust" : "connect")}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

"use client"

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent,
  type ReactNode,
} from "react"
import {
  ChevronRight,
  GripVertical,
  Loader2,
  Plus,
  Save,
  Trash2,
} from "lucide-react"
import { Reorder, useDragControls } from "motion/react"
import { useTranslations } from "next-intl"
import {
  clearSshFormCredentials,
  createRemoteWorkspaceConnection,
  deleteRemoteWorkspaceConnection,
  listRemoteWorkspaceConnections,
  reorderRemoteWorkspaceConnections,
  subscribeSshConnectionProgress,
  updateRemoteWorkspaceConnection,
  testRemoteWorkspaceConnection,
} from "@/lib/remote-workspace"
import {
  EMPTY_REMOTE_WORKSPACE_DRAFT as EMPTY_DRAFT,
  remoteWorkspaceAddress,
  remoteWorkspaceDraft,
  remoteWorkspaceInput,
  type RemoteWorkspaceDraft as Draft,
} from "@/lib/remote-workspace-form"
import { toErrorMessage } from "@/lib/app-error"
import type {
  RemoteWorkspaceConnection,
  RemoteWorkspaceHeader,
} from "@/lib/types"
import { Button } from "@/components/ui/button"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { cn, randomUUID } from "@/lib/utils"

const LEFT_MIN_WIDTH = 260
const RIGHT_MIN_WIDTH = 380

interface RemoteWorkspaceManageDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onChanged: () => void
}

interface RemoteWorkspaceReorderItemProps {
  connection: RemoteWorkspaceConnection
  selected: boolean
  disabled: boolean
  onSelect: (id: number) => void
  onDragEnd: () => void
  children: (
    startDrag: (event: PointerEvent<HTMLButtonElement>) => void
  ) => ReactNode
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

function toPercent(pixels: number, totalPixels: number): number {
  if (totalPixels <= 0) return 0
  return (pixels / totalPixels) * 100
}

function RemoteWorkspaceReorderItem({
  connection,
  selected,
  disabled,
  onSelect,
  onDragEnd,
  children,
}: RemoteWorkspaceReorderItemProps) {
  const dragControls = useDragControls()

  const startDrag = useCallback(
    (event: PointerEvent<HTMLButtonElement>) => {
      event.preventDefault()
      event.stopPropagation()
      if (!disabled) {
        dragControls.start(event)
      }
    },
    [disabled, dragControls]
  )

  return (
    <Reorder.Item
      as="section"
      value={connection}
      data-remote-workspace-id={connection.id}
      drag={disabled ? false : "y"}
      dragListener={false}
      dragControls={dragControls}
      dragMomentum={false}
      layout="position"
      className={cn(
        "cursor-pointer rounded-lg border bg-card p-2.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40",
        selected && "border-primary/60 bg-primary/5"
      )}
      tabIndex={0}
      onDragEnd={onDragEnd}
      onClick={() => onSelect(connection.id)}
      onKeyDown={(event) => {
        if (event.target !== event.currentTarget) return
        if (event.key !== "Enter" && event.key !== " ") return
        event.preventDefault()
        onSelect(connection.id)
      }}
    >
      {children(startDrag)}
    </Reorder.Item>
  )
}

export function RemoteWorkspaceManageDialog({
  open,
  onOpenChange,
  onChanged,
}: RemoteWorkspaceManageDialogProps) {
  const t = useTranslations("RemoteWorkspace")
  const [connections, setConnections] = useState<RemoteWorkspaceConnection[]>(
    []
  )
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT)
  const [searchQuery, setSearchQuery] = useState("")
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testSucceeded, setTestSucceeded] = useState(false)
  const [saveSucceeded, setSaveSucceeded] = useState(false)
  const [sshLogs, setSshLogs] = useState<string[]>([])
  const sshProgressTaskRef = useRef<string | null>(null)
  const sshProgressUnsubscribeRef = useRef<(() => void) | null>(null)
  const sshLogEndRef = useRef<HTMLDivElement | null>(null)
  const busy = saving || testing || deleting
  const [deleteTargetId, setDeleteTargetId] = useState<number | null>(null)
  const [reordering, setReordering] = useState(false)
  const [headersOpen, setHeadersOpen] = useState(false)
  const pendingOrderRef = useRef<number[] | null>(null)
  const panelContainerRef = useRef<HTMLDivElement | null>(null)
  const [panelContainerWidth, setPanelContainerWidth] = useState(0)

  const stopSshProgress = useCallback(() => {
    sshProgressUnsubscribeRef.current?.()
    sshProgressUnsubscribeRef.current = null
    sshProgressTaskRef.current = null
  }, [])

  const resetSshProgress = useCallback(() => {
    stopSshProgress()
    setSshLogs([])
  }, [stopSshProgress])

  const startSshProgress = useCallback(
    async (taskId: string) => {
      stopSshProgress()
      sshProgressTaskRef.current = taskId
      setSshLogs([t("sshConnecting")])
      let unsubscribe: () => void
      try {
        unsubscribe = await subscribeSshConnectionProgress((event) => {
          if (
            event.task_id !== taskId ||
            sshProgressTaskRef.current !== taskId
          ) {
            return
          }
          setSshLogs((current) => {
            if (current[current.length - 1] === event.message) return current
            return [...current, event.message].slice(-100)
          })
        })
      } catch (err) {
        console.error("[RemoteWorkspace] SSH progress unavailable:", err)
        return
      }
      if (sshProgressTaskRef.current !== taskId) {
        unsubscribe()
        return
      }
      sshProgressUnsubscribeRef.current = unsubscribe
    },
    [stopSshProgress, t]
  )

  useEffect(
    () => () => {
      stopSshProgress()
      void clearSshFormCredentials().catch(() => {})
    },
    [stopSshProgress]
  )

  useEffect(() => {
    const container = sshLogEndRef.current?.parentElement
    if (container) container.scrollTop = container.scrollHeight
  }, [sshLogs])

  const refresh = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const list = await listRemoteWorkspaceConnections()
      setConnections(list)
      setSelectedId((prev) => {
        if (prev === null) {
          return list[0]?.id ?? null
        }
        if (list.some((item) => item.id === prev)) {
          return prev
        }
        return list[0]?.id ?? null
      })
    } catch (err) {
      setLoadError(toErrorMessage(err))
      setConnections([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (open) {
      setFormError(null)
      void refresh()
    }
  }, [open, refresh])

  useEffect(() => {
    const container = panelContainerRef.current
    if (!container) return
    const updateWidth = (next: number) => {
      setPanelContainerWidth((prev) =>
        Math.abs(prev - next) < 1 ? prev : next
      )
    }
    updateWidth(container.getBoundingClientRect().width)
    const observer = new ResizeObserver((entries) => {
      updateWidth(
        entries[0]?.contentRect.width ?? container.getBoundingClientRect().width
      )
    })
    observer.observe(container)
    return () => {
      observer.disconnect()
    }
  }, [open])

  const selected = useMemo(
    () => connections.find((item) => item.id === selectedId) ?? null,
    [connections, selectedId]
  )
  const deleteTarget = useMemo(
    () =>
      deleteTargetId === null
        ? null
        : (connections.find((item) => item.id === deleteTargetId) ?? null),
    [connections, deleteTargetId]
  )

  useEffect(() => {
    setFormError(null)
    setHeadersOpen((selected?.headers?.length ?? 0) > 0)
    if (!selected) {
      setDraft(EMPTY_DRAFT)
      return
    }
    setTestSucceeded(false)
    setDraft(remoteWorkspaceDraft(selected))
  }, [selected])

  const filteredConnections = useMemo(() => {
    const query = searchQuery.trim().toLowerCase()
    if (!query) return connections
    return connections.filter(
      (connection) =>
        connection.name.toLowerCase().includes(query) ||
        remoteWorkspaceAddress(connection).toLowerCase().includes(query)
    )
  }, [connections, searchQuery])

  const searchActive = searchQuery.trim().length > 0
  const safeContainerWidth = panelContainerWidth > 0 ? panelContainerWidth : 900
  const leftMinSize = clamp(
    toPercent(LEFT_MIN_WIDTH, safeContainerWidth),
    5,
    95
  )
  const rightMinSize = clamp(
    toPercent(RIGHT_MIN_WIDTH, safeContainerWidth),
    5,
    95
  )
  const leftMaxSize = Math.max(leftMinSize, 100 - rightMinSize)

  const updateDraft = useCallback(
    (patch: Partial<Draft>) => {
      resetSshProgress()
      if (
        "mode" in patch ||
        "sshHost" in patch ||
        "sshUsername" in patch ||
        "sshPort" in patch ||
        "sshIdentityFile" in patch ||
        "sshRememberPassword" in patch
      ) {
        void clearSshFormCredentials().catch(() => {})
      }
      setTestSucceeded(false)
      setSaveSucceeded(false)
      setFormError(null)
      setDraft((prev) => {
        const locatorChanged =
          "sshHost" in patch ||
          "sshUsername" in patch ||
          "sshPort" in patch ||
          "sshIdentityFile" in patch
        return {
          ...prev,
          ...patch,
          ...(locatorChanged && prev.sshRememberPassword
            ? { sshCredentialId: randomUUID() }
            : {}),
        }
      })
    },
    [resetSshProgress]
  )

  const startNew = useCallback(() => {
    resetSshProgress()
    void clearSshFormCredentials().catch(() => {})
    setSelectedId(null)
    setFormError(null)
    setDraft(EMPTY_DRAFT)
    setTestSucceeded(false)
    setSaveSucceeded(false)
    setHeadersOpen(false)
  }, [resetSshProgress])

  const updateHeader = useCallback(
    (index: number, patch: Partial<RemoteWorkspaceHeader>) => {
      setFormError(null)
      setTestSucceeded(false)
      setSaveSucceeded(false)
      setDraft((prev) => ({
        ...prev,
        headers: prev.headers.map((header, position) =>
          position === index ? { ...header, ...patch } : header
        ),
      }))
    },
    []
  )

  const addHeader = useCallback(() => {
    setFormError(null)
    setTestSucceeded(false)
    setSaveSucceeded(false)
    setDraft((prev) => ({
      ...prev,
      headers: [...prev.headers, { name: "", value: "" }],
    }))
  }, [])

  const removeHeader = useCallback((index: number) => {
    setFormError(null)
    setTestSucceeded(false)
    setSaveSucceeded(false)
    setDraft((prev) => ({
      ...prev,
      headers: prev.headers.filter((_, position) => position !== index),
    }))
  }, [])

  const persistReorder = useCallback(
    async (ids: number[]) => {
      if (ids.length === 0) return
      setReordering(true)
      setFormError(null)
      try {
        await reorderRemoteWorkspaceConnections(ids)
        onChanged()
      } catch (err) {
        setFormError(`${t("orderFailed")}: ${toErrorMessage(err)}`)
        await refresh()
      } finally {
        setReordering(false)
      }
    },
    [onChanged, refresh, t]
  )

  const handleReorder = useCallback(
    (next: RemoteWorkspaceConnection[]) => {
      if (searchActive) return
      const reordered = next.map((connection, index) => ({
        ...connection,
        sort_order: index,
      }))
      setConnections(reordered)
      pendingOrderRef.current = reordered.map((connection) => connection.id)
    },
    [searchActive]
  )

  const handleTest = useCallback(async () => {
    const result = remoteWorkspaceInput(draft, false)
    if (result.error) {
      setFormError(t(result.error))
      return
    }
    setTesting(true)
    setTestSucceeded(false)
    setSaveSucceeded(false)
    setFormError(null)
    const taskId = draft.mode === "ssh" ? randomUUID() : undefined
    try {
      if (taskId) await startSshProgress(taskId)
      if (taskId) {
        await testRemoteWorkspaceConnection(result.input, taskId)
      } else {
        await testRemoteWorkspaceConnection(result.input)
      }
      setTestSucceeded(true)
    } catch (err) {
      const message = `${t("testFailed")}: ${toErrorMessage(err)}`
      setFormError(message)
      if (taskId) setSshLogs((current) => [...current, `ERROR: ${message}`])
    } finally {
      stopSshProgress()
      setTesting(false)
    }
  }, [draft, startSshProgress, stopSshProgress, t])

  const handleSave = useCallback(async () => {
    const result = remoteWorkspaceInput(draft)
    if (result.error) {
      setFormError(t(result.error))
      return
    }
    setSaving(true)
    setTestSucceeded(false)
    setSaveSucceeded(false)
    setFormError(null)
    const taskId = draft.mode === "ssh" ? randomUUID() : undefined
    try {
      if (taskId) await startSshProgress(taskId)
      const input = result.input
      const saved =
        draft.id === null
          ? taskId
            ? await createRemoteWorkspaceConnection(input, taskId)
            : await createRemoteWorkspaceConnection(input)
          : taskId
            ? await updateRemoteWorkspaceConnection(draft.id, input, taskId)
            : await updateRemoteWorkspaceConnection(draft.id, input)
      setConnections((prev) => {
        const exists = prev.some((item) => item.id === saved.id)
        if (exists) {
          return prev.map((item) => (item.id === saved.id ? saved : item))
        }
        return [...prev, saved]
      })
      setSelectedId(saved.id)
      setDraft(remoteWorkspaceDraft(saved))
      setSaveSucceeded(true)
      onChanged()
    } catch (err) {
      const message = `${t("saveFailed")}: ${toErrorMessage(err)}`
      setFormError(message)
      if (taskId) setSshLogs((current) => [...current, `ERROR: ${message}`])
    } finally {
      stopSshProgress()
      setSaving(false)
    }
  }, [draft, onChanged, startSshProgress, stopSshProgress, t])

  const handleDelete = useCallback(async () => {
    if (deleteTargetId === null) return
    const target = deleteTargetId
    setDeleting(true)
    setFormError(null)
    try {
      await deleteRemoteWorkspaceConnection(target)
      setConnections((prev) => {
        const next = prev.filter((item) => item.id !== target)
        setSelectedId((current) =>
          current === target ? (next[0]?.id ?? null) : current
        )
        return next
      })
      onChanged()
      setDeleteTargetId(null)
    } catch (err) {
      setFormError(`${t("deleteFailed")}: ${toErrorMessage(err)}`)
      setDeleteTargetId(null)
    } finally {
      setDeleting(false)
    }
  }, [deleteTargetId, onChanged, t])

  return (
    <>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (busy) return
          if (!next) {
            resetSshProgress()
            void clearSshFormCredentials().catch(() => {})
          }
          onOpenChange(next)
        }}
      >
        <DialogContent className="flex h-[min(47.5rem,calc(100vh-4rem))] max-w-[min(61.25rem,calc(100vw-2rem))] flex-col gap-0 overflow-hidden p-0 sm:max-w-5xl">
          <DialogHeader className="border-b px-4 py-3">
            <DialogTitle>{t("manageTitle")}</DialogTitle>
          </DialogHeader>

          <div ref={panelContainerRef} className="min-h-0 min-w-0 flex-1 p-3">
            <ResizablePanelGroup
              direction="horizontal"
              className="h-full min-h-0 min-w-0"
            >
              <ResizablePanel
                defaultSize={36}
                minSize={leftMinSize}
                maxSize={leftMaxSize}
              >
                <div className="flex h-full min-h-0 min-w-0 flex-col overflow-hidden rounded-lg border bg-card lg:rounded-r-none">
                  <div className="space-y-2.5 border-b p-3">
                    <div className="flex items-center gap-2">
                      <Input
                        value={searchQuery}
                        onChange={(event) => setSearchQuery(event.target.value)}
                        placeholder={t("searchPlaceholder")}
                      />
                      <Button
                        size="sm"
                        onClick={startNew}
                        disabled={busy || loading || reordering}
                      >
                        <Plus className="h-3.5 w-3.5" />
                        {t("newConnection")}
                      </Button>
                    </div>
                  </div>

                  {loadError ? (
                    <div className="m-3 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                      {loadError}
                    </div>
                  ) : loading ? (
                    <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      {t("loading")}
                    </div>
                  ) : filteredConnections.length === 0 ? (
                    <div className="flex flex-1 items-center justify-center px-4 text-center text-xs text-muted-foreground">
                      {connections.length === 0
                        ? t("empty")
                        : t("searchPlaceholder")}
                    </div>
                  ) : (
                    <Reorder.Group
                      as="div"
                      axis="y"
                      values={filteredConnections}
                      onReorder={handleReorder}
                      className="min-h-0 flex-1 space-y-2 overflow-y-auto p-2"
                    >
                      {filteredConnections.map((connection) => {
                        const dragDisabled =
                          busy ||
                          reordering ||
                          searchActive ||
                          filteredConnections.length < 2
                        return (
                          <RemoteWorkspaceReorderItem
                            key={connection.id}
                            connection={connection}
                            selected={selectedId === connection.id}
                            disabled={dragDisabled}
                            onSelect={(id) => {
                              if (!busy) {
                                resetSshProgress()
                                void clearSshFormCredentials().catch(() => {})
                                setTestSucceeded(false)
                                setSaveSucceeded(false)
                                setSelectedId(id)
                              }
                            }}
                            onDragEnd={() => {
                              const order = pendingOrderRef.current
                              pendingOrderRef.current = null
                              if (order && !reordering) {
                                persistReorder(order).catch((err) => {
                                  console.error(
                                    "[RemoteWorkspace] reorder failed:",
                                    err
                                  )
                                })
                              }
                            }}
                          >
                            {(startDrag) => (
                              <div className="flex items-center gap-2 overflow-hidden">
                                <button
                                  type="button"
                                  className="cursor-grab rounded p-0.5 text-muted-foreground hover:bg-muted active:cursor-grabbing disabled:cursor-default disabled:opacity-40"
                                  title={t("dragSort")}
                                  aria-label={t("dragSortConnection", {
                                    name: connection.name,
                                  })}
                                  onPointerDown={startDrag}
                                  onClick={(event) => event.stopPropagation()}
                                  disabled={dragDisabled}
                                >
                                  <GripVertical className="h-3.5 w-3.5" />
                                </button>
                                <div className="min-w-0 flex-1">
                                  <div className="truncate text-sm font-medium">
                                    {connection.name}
                                  </div>
                                  <div className="mt-0.5 truncate text-2xs text-muted-foreground">
                                    {remoteWorkspaceAddress(connection)}
                                  </div>
                                </div>
                              </div>
                            )}
                          </RemoteWorkspaceReorderItem>
                        )
                      })}
                    </Reorder.Group>
                  )}
                </div>
              </ResizablePanel>

              <ResizableHandle withHandle />

              <ResizablePanel defaultSize={64} minSize={rightMinSize}>
                <div className="flex h-full min-h-0 min-w-0 flex-col overflow-hidden rounded-lg border bg-card lg:rounded-l-none lg:border-l-0">
                  <fieldset
                    disabled={busy}
                    className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4"
                  >
                    <div className="space-y-1.5">
                      <Label
                        htmlFor="remote-workspace-name"
                        className="text-xs"
                      >
                        {t("name")}
                      </Label>
                      <Input
                        id="remote-workspace-name"
                        value={draft.name}
                        onChange={(event) =>
                          updateDraft({ name: event.target.value })
                        }
                      />
                    </div>
                    <fieldset className="space-y-2">
                      <legend className="text-xs font-medium">
                        {t("connectionType")}
                      </legend>
                      <div className="flex flex-wrap gap-4 text-sm">
                        {(["http", "ssh"] as const).map((mode) => (
                          <label key={mode} className="flex items-center gap-2">
                            <input
                              type="radio"
                              name="remote-workspace-type"
                              value={mode}
                              checked={draft.mode === mode}
                              onChange={() => updateDraft({ mode })}
                            />
                            {t(mode === "ssh" ? "sshType" : "httpType")}
                          </label>
                        ))}
                      </div>
                    </fieldset>
                    {draft.mode === "ssh" ? (
                      <div className="space-y-4">
                        <p className="text-xs leading-relaxed text-muted-foreground">
                          {t("sshHelp")}
                        </p>
                        <div className="space-y-1.5">
                          <Label
                            htmlFor="remote-workspace-ssh-host"
                            className="text-xs"
                          >
                            {t("sshHost")}
                          </Label>
                          <Input
                            id="remote-workspace-ssh-host"
                            value={draft.sshHost}
                            placeholder="my-server"
                            maxLength={255}
                            onChange={(event) =>
                              updateDraft({ sshHost: event.target.value })
                            }
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div className="space-y-1.5">
                            <Label
                              htmlFor="remote-workspace-ssh-user"
                              className="text-xs"
                            >
                              {t("sshUsername")}
                            </Label>
                            <Input
                              id="remote-workspace-ssh-user"
                              value={draft.sshUsername}
                              placeholder={t("sshConfigDefault")}
                              onChange={(event) =>
                                updateDraft({ sshUsername: event.target.value })
                              }
                            />
                          </div>
                          <div className="space-y-1.5">
                            <Label
                              htmlFor="remote-workspace-ssh-port"
                              className="text-xs"
                            >
                              {t("sshPort")}
                            </Label>
                            <Input
                              id="remote-workspace-ssh-port"
                              inputMode="numeric"
                              value={draft.sshPort}
                              placeholder={t("sshConfigDefault")}
                              onChange={(event) =>
                                updateDraft({ sshPort: event.target.value })
                              }
                            />
                          </div>
                        </div>
                        <div className="space-y-1.5">
                          <Label
                            htmlFor="remote-workspace-ssh-key"
                            className="text-xs"
                          >
                            {t("sshIdentityFile")}
                          </Label>
                          <Input
                            id="remote-workspace-ssh-key"
                            value={draft.sshIdentityFile}
                            placeholder={t("sshConfigDefault")}
                            onChange={(event) =>
                              updateDraft({
                                sshIdentityFile: event.target.value,
                              })
                            }
                          />
                        </div>
                        <label className="flex items-start gap-2 text-sm">
                          <input
                            type="checkbox"
                            className="mt-0.5"
                            checked={draft.sshRememberPassword}
                            onChange={(event) => {
                              const checked = event.target.checked
                              updateDraft({
                                sshRememberPassword: checked,
                                sshCredentialId: checked
                                  ? draft.sshCredentialId || randomUUID()
                                  : draft.sshCredentialId,
                              })
                            }}
                          />
                          <span>
                            <span className="block text-xs font-medium">
                              {t("sshRememberPassword")}
                            </span>
                            <span className="mt-0.5 block text-2xs text-muted-foreground">
                              {t("sshRememberPasswordHint")}
                            </span>
                          </span>
                        </label>
                        {!draft.sshRememberPassword && (
                          <p className="text-xs text-muted-foreground">
                            {t("sshOptionalHint")}
                          </p>
                        )}
                      </div>
                    ) : (
                      <>
                        <div className="space-y-1.5">
                          <Label
                            htmlFor="remote-workspace-base-url"
                            className="text-xs"
                          >
                            {t("baseUrl")}
                          </Label>
                          <Input
                            id="remote-workspace-base-url"
                            value={draft.baseUrl}
                            placeholder="http://127.0.0.1:3080"
                            onChange={(event) =>
                              updateDraft({ baseUrl: event.target.value })
                            }
                          />
                        </div>
                        <div className="space-y-1.5">
                          <Label
                            htmlFor="remote-workspace-token"
                            className="text-xs"
                          >
                            {t("token")}
                          </Label>
                          <Input
                            id="remote-workspace-token"
                            type="password"
                            value={draft.token}
                            onChange={(event) =>
                              updateDraft({ token: event.target.value })
                            }
                          />
                        </div>
                        <Collapsible
                          open={headersOpen}
                          onOpenChange={setHeadersOpen}
                          className="space-y-2"
                        >
                          <CollapsibleTrigger className="flex h-6 w-full items-center gap-1.5 rounded-md text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40">
                            <ChevronRight
                              className={cn(
                                "h-3.5 w-3.5 transition-transform",
                                headersOpen && "rotate-90"
                              )}
                            />
                            {t("customHeaders")}
                            {draft.headers.length > 0 ? (
                              <span className="rounded bg-muted px-1.5 text-3xs leading-4 text-muted-foreground">
                                {draft.headers.length}
                              </span>
                            ) : null}
                          </CollapsibleTrigger>
                          <CollapsibleContent className="space-y-2">
                            {draft.headers.map((header, index) => (
                              <div
                                key={index}
                                className="flex items-center gap-2"
                                data-remote-workspace-header-row={index}
                              >
                                <Input
                                  className="flex-1"
                                  value={header.name}
                                  placeholder={t("customHeaderName")}
                                  aria-label={t("customHeaderName")}
                                  onChange={(event) =>
                                    updateHeader(index, {
                                      name: event.target.value,
                                    })
                                  }
                                />
                                <Input
                                  className="flex-1"
                                  type="password"
                                  value={header.value}
                                  placeholder={t("customHeaderValue")}
                                  aria-label={t("customHeaderValue")}
                                  onChange={(event) =>
                                    updateHeader(index, {
                                      value: event.target.value,
                                    })
                                  }
                                />
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  className="h-7 w-7 shrink-0 text-destructive"
                                  aria-label={t("removeCustomHeader")}
                                  title={t("removeCustomHeader")}
                                  onClick={() => removeHeader(index)}
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </Button>
                              </div>
                            ))}
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={addHeader}
                            >
                              <Plus className="h-3.5 w-3.5" />
                              {t("addCustomHeader")}
                            </Button>
                          </CollapsibleContent>
                        </Collapsible>
                      </>
                    )}
                    {testSucceeded && (
                      <p
                        role="status"
                        className="text-xs text-muted-foreground"
                      >
                        {t("testSucceeded")}
                      </p>
                    )}
                    {saveSucceeded && (
                      <p
                        role="status"
                        className="text-xs text-muted-foreground"
                      >
                        {t("saved")}
                      </p>
                    )}
                    {draft.mode === "ssh" && sshLogs.length > 0 && (
                      <div
                        role="log"
                        aria-live="polite"
                        aria-label={t("sshConnecting")}
                        className="max-h-44 overflow-y-auto rounded-md border bg-muted/50 p-3 font-mono text-2xs leading-relaxed text-muted-foreground"
                      >
                        {sshLogs.map((line, index) => (
                          <div
                            key={`${index}-${line}`}
                            className={
                              line.startsWith("ERROR:")
                                ? "text-destructive"
                                : undefined
                            }
                          >
                            {line}
                          </div>
                        ))}
                        <div ref={sshLogEndRef} />
                      </div>
                    )}
                  </fieldset>

                  <div className="space-y-3 border-t px-4 py-3">
                    {formError ? (
                      <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                        {formError}
                      </div>
                    ) : null}
                    <div className="flex items-center justify-between gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setDeleteTargetId(draft.id)}
                        disabled={busy || draft.id === null}
                        className="text-red-500 hover:text-red-500"
                      >
                        {deleting ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Trash2 className="h-3.5 w-3.5" />
                        )}
                        {t("delete")}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() => void handleTest()}
                      >
                        {testing && (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        )}
                        {t("testConnection")}
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => {
                          handleSave().catch((err) => {
                            console.error("[RemoteWorkspace] save failed:", err)
                          })
                        }}
                        disabled={busy}
                      >
                        {saving ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Save className="h-3.5 w-3.5" />
                        )}
                        {t("save")}
                      </Button>
                    </div>
                  </div>
                </div>
              </ResizablePanel>
            </ResizablePanelGroup>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={deleteTargetId !== null}
        onOpenChange={(nextOpen) => {
          if (!nextOpen && !deleting) setDeleteTargetId(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("confirmDelete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("confirmDelete.message", {
                name: deleteTarget?.name ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>
              {t("confirmDelete.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault()
                handleDelete().catch((err) => {
                  console.error("[RemoteWorkspace] delete failed:", err)
                })
              }}
              disabled={deleting}
            >
              {deleting ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : null}
              {t("confirmDelete.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

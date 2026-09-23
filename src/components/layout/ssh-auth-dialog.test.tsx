import { act, fireEvent, render, screen } from "@testing-library/react"
import { NextIntlClientProvider } from "next-intl"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import enMessages from "@/i18n/messages/en.json"

const mocks = vi.hoisted(() => ({
  desktop: true,
  list: vi.fn(),
  answer: vi.fn(),
  handlers: new Map<string, (value: unknown) => void>(),
}))
vi.mock("@/lib/transport", () => ({
  isDesktop: () => mocks.desktop,
  getShellTransport: () => ({
    call: (command: string, args: unknown) =>
      command === "list_ssh_auth_prompts"
        ? mocks.list()
        : mocks.answer(command, args),
    subscribe: (name: string, handler: (value: unknown) => void) => {
      mocks.handlers.set(name, handler)
      return Promise.resolve(() => mocks.handlers.delete(name))
    },
  }),
}))
vi.mock("@/lib/browser/window-label", () => ({
  getCurrentWindowLabel: () => "main",
}))

import { SshAuthDialog, type SshAuthPrompt } from "./ssh-auth-dialog"

function prompt(overrides: Partial<SshAuthPrompt> = {}): SshAuthPrompt {
  return {
    requestId: "first",
    ownerWindow: "main",
    host: "server",
    kind: "password",
    prompt: "alice@server's password: ",
    expiresAt: Date.now() + 180_000,
    ...overrides,
  }
}

async function mount() {
  const view = render(
    <NextIntlClientProvider locale="en" messages={enMessages}>
      <SshAuthDialog />
    </NextIntlClientProvider>
  )
  await act(async () => {})
  return view
}

async function send(value = prompt()) {
  await act(async () => {
    mocks.handlers.get("ssh-auth://prompt")?.(value)
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.desktop = true
  mocks.handlers.clear()
  mocks.list.mockResolvedValue([])
  mocks.answer.mockResolvedValue(undefined)
})
afterEach(() => {
  vi.useRealTimers()
})

describe("SshAuthDialog", () => {
  it("is desktop-only and invisible before authentication is requested", async () => {
    mocks.desktop = false
    await mount()
    expect(mocks.list).not.toHaveBeenCalled()
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
  })

  it("sends an untrimmed password only over local shell IPC and immediately clears the input", async () => {
    await mount()
    await send()
    const input = screen.getByLabelText("Password")
    expect(input).toHaveAttribute("type", "password")
    fireEvent.change(input, { target: { value: "  secret with spaces  " } })
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Connect", exact: true })
      )
    })
    expect(mocks.answer).toHaveBeenCalledWith("answer_ssh_auth_prompt", {
      requestId: "first",
      answer: "  secret with spaces  ",
    })
    expect(input).toHaveValue("")
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
  })

  it("shows the full fingerprint and defaults to refusing an unknown host", async () => {
    await mount()
    await send(
      prompt({
        kind: "hostKey",
        prompt:
          "Host server\nED25519 SHA256:expected-fingerprint\nTrust this host?",
      })
    )
    expect(screen.getByText(/SHA256:expected-fingerprint/)).toBeVisible()
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument()
    expect(mocks.answer).not.toHaveBeenCalled()
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    })
    expect(mocks.answer).toHaveBeenCalledWith("answer_ssh_auth_prompt", {
      requestId: "first",
      answer: null,
    })
  })

  it("treats Escape as cancellation, never host approval", async () => {
    await mount()
    await send(prompt({ kind: "hostKey" }))
    await act(async () => {
      fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" })
    })
    expect(mocks.answer).toHaveBeenCalledWith("answer_ssh_auth_prompt", {
      requestId: "first",
      answer: null,
    })
  })

  it("accepts a host only after an explicit trust click", async () => {
    await mount()
    await send(prompt({ kind: "hostKey" }))
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Trust host and connect" })
      )
    })
    expect(mocks.answer).toHaveBeenCalledWith("answer_ssh_auth_prompt", {
      requestId: "first",
      answer: "yes",
    })
  })

  it("ignores requests for a different window and deduplicates replayed events", async () => {
    await mount()
    await send(prompt({ ownerWindow: "remote-workspace-2" }))
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
    await send()
    await send()
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    })
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
    expect(mocks.answer).toHaveBeenCalledTimes(1)
  })

  it("queues prompts without carrying a typed secret into the next request", async () => {
    await mount()
    await send()
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "do-not-reuse" },
    })
    await send(prompt({ requestId: "second", kind: "passphrase" }))
    await act(async () => {
      mocks.handlers.get("ssh-auth://dismiss")?.({
        requestId: "first",
        ownerWindow: "main",
      })
    })
    expect(screen.getByLabelText("Key passphrase")).toHaveValue("")
    expect(mocks.answer).not.toHaveBeenCalled()
  })

  it("recovers prompts emitted before mount without resurrecting a dismissed snapshot", async () => {
    let resolve!: (value: SshAuthPrompt[]) => void
    mocks.list.mockReturnValue(
      new Promise<SshAuthPrompt[]>((done) => {
        resolve = done
      })
    )
    await mount()
    await send()
    await act(async () => {
      mocks.handlers.get("ssh-auth://dismiss")?.({
        requestId: "first",
        ownerWindow: "main",
      })
      resolve([prompt(), prompt({ requestId: "recovered" })])
    })
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    })
    expect(mocks.answer).toHaveBeenCalledWith("answer_ssh_auth_prompt", {
      requestId: "recovered",
      answer: null,
    })
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
  })

  it("expires unanswered prompts without accepting or storing anything", async () => {
    vi.useFakeTimers()
    await mount()
    await send(prompt({ expiresAt: Date.now() + 500 }))
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
    expect(mocks.answer).not.toHaveBeenCalled()
  })

  it("does not expose rejected IPC payloads in errors and clears the secret before retry", async () => {
    mocks.answer.mockRejectedValue(new Error("payload contains do-not-log-me"))
    await mount()
    await send()
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "do-not-log-me" },
    })
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Connect", exact: true })
      )
    })
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Unable to send your answer"
    )
    expect(screen.getByLabelText("Password")).toHaveValue("")
    expect(screen.queryByText(/do-not-log-me/)).not.toBeInTheDocument()
  })

  it("unsubscribes from both local events on unmount", async () => {
    const view = await mount()
    expect(mocks.handlers.size).toBe(2)
    view.unmount()
    expect(mocks.handlers.size).toBe(0)
  })
})

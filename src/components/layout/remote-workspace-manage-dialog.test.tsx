import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { NextIntlClientProvider } from "next-intl"
import { beforeEach, describe, expect, it, vi } from "vitest"
import type { RemoteWorkspaceConnection } from "@/lib/types"

const mocks = vi.hoisted(() => ({
  listRemoteWorkspaceConnections: vi.fn(),
  createRemoteWorkspaceConnection: vi.fn(),
  updateRemoteWorkspaceConnection: vi.fn(),
  deleteRemoteWorkspaceConnection: vi.fn(),
  reorderRemoteWorkspaceConnections: vi.fn(),
  testRemoteWorkspaceConnection: vi.fn(),
}))

vi.mock("@/lib/remote-workspace", () => ({
  listRemoteWorkspaceConnections: mocks.listRemoteWorkspaceConnections,
  createRemoteWorkspaceConnection: mocks.createRemoteWorkspaceConnection,
  updateRemoteWorkspaceConnection: mocks.updateRemoteWorkspaceConnection,
  deleteRemoteWorkspaceConnection: mocks.deleteRemoteWorkspaceConnection,
  reorderRemoteWorkspaceConnections: mocks.reorderRemoteWorkspaceConnections,
  testRemoteWorkspaceConnection: mocks.testRemoteWorkspaceConnection,
}))

import { RemoteWorkspaceManageDialog } from "./remote-workspace-manage-dialog"
import enMessages from "@/i18n/messages/en.json"

function connection(
  overrides: Partial<RemoteWorkspaceConnection> = {}
): RemoteWorkspaceConnection {
  return {
    id: 1,
    name: "prod-box",
    base_url: "https://prod.example",
    token: "secret",
    headers: [],
    sort_order: 0,
    created_at: "2026-08-25T00:00:00Z",
    updated_at: "2026-08-25T00:00:00Z",
    ...overrides,
  }
}

async function mount(connections: RemoteWorkspaceConnection[]) {
  mocks.listRemoteWorkspaceConnections.mockResolvedValue(connections)
  render(
    <NextIntlClientProvider locale="en" messages={enMessages}>
      <RemoteWorkspaceManageDialog
        open
        onOpenChange={() => {}}
        onChanged={() => {}}
      />
    </NextIntlClientProvider>
  )
  await screen.findByDisplayValue(connections[0].name)
}

describe("RemoteWorkspaceManageDialog custom headers", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("keeps the editor collapsed when the connection has no headers", async () => {
    await mount([connection()])
    expect(screen.queryByLabelText("Header name")).not.toBeInTheDocument()
  })

  it("opens the editor when the connection already has headers", async () => {
    await mount([
      connection({ headers: [{ name: "CF-Access-Client-Id", value: "abc" }] }),
    ])
    expect(await screen.findByDisplayValue("CF-Access-Client-Id")).toBeVisible()
  })

  it("masks every header value", async () => {
    await mount([connection({ headers: [{ name: "X-Secret", value: "abc" }] })])
    expect(await screen.findByDisplayValue("abc")).toHaveAttribute(
      "type",
      "password"
    )
  })

  it("sends the added header on save and drops a removed one", async () => {
    const saved = connection({
      headers: [{ name: "X-Team", value: "core" }],
    })
    mocks.updateRemoteWorkspaceConnection.mockResolvedValue(saved)
    await mount([connection()])

    await userEvent.click(
      screen.getByRole("button", { name: /Custom headers/ })
    )
    await userEvent.click(screen.getByRole("button", { name: "Add header" }))
    fireEvent.change(screen.getByLabelText("Header name"), {
      target: { value: "X-Team" },
    })
    fireEvent.change(screen.getByLabelText("Header value"), {
      target: { value: "core" },
    })

    // A second row, then removed again: the payload must hold one header.
    await userEvent.click(screen.getByRole("button", { name: "Add header" }))
    await userEvent.click(
      screen.getAllByRole("button", { name: "Remove header" })[1]
    )

    await userEvent.click(screen.getByRole("button", { name: "Save" }))

    await waitFor(() => {
      expect(mocks.updateRemoteWorkspaceConnection).toHaveBeenCalledWith(1, {
        name: "prod-box",
        baseUrl: "https://prod.example",
        token: "secret",
        headers: [{ name: "X-Team", value: "core" }],
      })
    })
  })
})

describe("RemoteWorkspaceManageDialog SSH profiles", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("refills SSH locators without a token input or an implicit port 22", async () => {
    await mount([
      connection({
        base_url: "ssh://build-host",
        token: "",
        ssh: { host: "build-host" },
      }),
    ])
    expect(
      screen.getByRole("radio", { name: "SSH (automatic setup)" })
    ).toBeChecked()
    expect(screen.getByLabelText("SSH host or config alias")).toHaveValue(
      "build-host"
    )
    expect(screen.getByLabelText("Port (optional)")).toHaveValue("")
    expect(screen.queryByLabelText("Access token")).not.toBeInTheDocument()
  })

  it("saves an HTTP-to-SSH switch without leaking the previous credentials", async () => {
    const saved = connection({
      base_url: "ssh://build-host",
      token: "",
      headers: [],
      ssh: { host: "build-host" },
    })
    mocks.updateRemoteWorkspaceConnection.mockResolvedValue(saved)
    await mount([
      connection({ headers: [{ name: "X-Secret", value: "private" }] }),
    ])
    await userEvent.click(
      screen.getByRole("radio", { name: "SSH (automatic setup)" })
    )
    fireEvent.change(screen.getByLabelText("SSH host or config alias"), {
      target: { value: "build-host" },
    })
    await userEvent.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() =>
      expect(mocks.updateRemoteWorkspaceConnection).toHaveBeenCalledWith(1, {
        name: "prod-box",
        baseUrl: "",
        token: "",
        headers: [],
        ssh: { host: "build-host" },
      })
    )
  })

  it("rejects invalid ports before starting an SSH operation", async () => {
    await mount([
      connection({
        base_url: "ssh://build-host",
        token: "",
        ssh: { host: "build-host" },
      }),
    ])
    fireEvent.change(screen.getByLabelText("Port (optional)"), {
      target: { value: "65536" },
    })
    await userEvent.click(screen.getByRole("button", { name: "Save" }))
    expect(await screen.findByText(/whole-number port/)).toBeVisible()
    expect(mocks.updateRemoteWorkspaceConnection).not.toHaveBeenCalled()
  })

  it("keeps the form stable during a long test and does not save a profile", async () => {
    let finish!: () => void
    mocks.testRemoteWorkspaceConnection.mockReturnValue(
      new Promise<void>((resolve) => {
        finish = resolve
      })
    )
    await mount([
      connection({
        base_url: "ssh://build-host",
        token: "",
        ssh: { host: "build-host" },
      }),
    ])
    await userEvent.click(
      screen.getByRole("button", { name: "Test connection" })
    )
    expect(screen.getByLabelText("SSH host or config alias")).toBeDisabled()
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled()
    expect(
      screen.getByRole("button", { name: "New connection" })
    ).toBeDisabled()
    expect(screen.getByText(/First-time installation may take/)).toBeVisible()
    await act(async () => finish())
    expect(await screen.findByText("Connection test succeeded.")).toBeVisible()
    expect(mocks.updateRemoteWorkspaceConnection).not.toHaveBeenCalled()
    expect(mocks.createRemoteWorkspaceConnection).not.toHaveBeenCalled()
  })

  it("searches SSH locators including the configured username", async () => {
    await mount([
      connection({
        name: "SSH machine",
        ssh: { host: "build-host", username: "coder" },
      }),
      connection({ id: 2, name: "HTTP machine" }),
    ])
    fireEvent.change(screen.getByPlaceholderText("Search remote workspaces"), {
      target: { value: "coder@build-host" },
    })
    expect(screen.getByText("SSH machine")).toBeVisible()
    expect(screen.queryByText("HTTP machine")).not.toBeInTheDocument()
  })
})

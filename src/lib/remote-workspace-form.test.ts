import { describe, expect, it } from "vitest"
import {
  EMPTY_REMOTE_WORKSPACE_DRAFT,
  remoteWorkspaceAddress,
  remoteWorkspaceDraft,
  remoteWorkspaceInput,
} from "./remote-workspace-form"
import type { RemoteWorkspaceConnection } from "./types"

const connection: RemoteWorkspaceConnection = {
  id: 7,
  name: "Build box",
  base_url: "https://box.example",
  token: "http-secret",
  headers: [{ name: "X-Secret", value: "private" }],
  sort_order: 0,
  created_at: "2026-09-23T00:00:00Z",
  updated_at: "2026-09-23T00:00:00Z",
}
const sshDraft = {
  ...EMPTY_REMOTE_WORKSPACE_DRAFT,
  name: "Build box",
  mode: "ssh" as const,
  sshHost: "build-alias",
  baseUrl: "https://old.example",
  token: "stale-secret",
  headers: connection.headers,
}

describe("SSH workspace form contract", () => {
  it("leaves optional SSH fields absent and never sends old HTTP credentials", () => {
    expect(remoteWorkspaceInput(sshDraft)).toEqual({
      input: {
        name: "Build box",
        baseUrl: "",
        token: "",
        headers: [],
        ssh: { host: "build-alias" },
      },
    })
  })

  it("normalizes optional values and preserves identity paths containing spaces", () => {
    const result = remoteWorkspaceInput({
      ...sshDraft,
      sshHost: " build-alias ",
      sshUsername: " coder ",
      sshPort: " 2222 ",
      sshIdentityFile: " C:\\My Keys\\id_ed25519 ",
    })
    expect(result.input?.ssh).toEqual({
      host: "build-alias",
      username: "coder",
      port: 2222,
      identityFile: "C:\\My Keys\\id_ed25519",
    })
  })

  it.each(["0", "65536", "-1", "22.5", "1e3", "+22", "NaN"])(
    "rejects invalid port %s",
    (sshPort) => {
      expect(remoteWorkspaceInput({ ...sshDraft, sshPort }).error).toBe(
        "sshPortInvalid"
      )
    }
  )

  it.each([
    "-oProxyCommand=evil",
    "host;command",
    "user@host",
    "host name",
    "$(command)",
  ])("rejects option-like or shell-shaped hosts: %s", (sshHost) => {
    expect(remoteWorkspaceInput({ ...sshDraft, sshHost }).error).toBe(
      "sshHostInvalid"
    )
  })

  it("requires a host and validates key paths and usernames", () => {
    expect(remoteWorkspaceInput({ ...sshDraft, sshHost: " " }).error).toBe(
      "sshHostRequired"
    )
    expect(
      remoteWorkspaceInput({ ...sshDraft, sshUsername: "-root" }).error
    ).toBe("sshUsernameInvalid")
    expect(
      remoteWorkspaceInput({ ...sshDraft, sshIdentityFile: "-i" }).error
    ).toBe("sshIdentityInvalid")
    expect(
      remoteWorkspaceInput({ ...sshDraft, sshIdentityFile: "key\nfile" }).error
    ).toBe("sshIdentityInvalid")
  })

  it("refills SSH profiles without displaying cached URLs or secrets", () => {
    const draft = remoteWorkspaceDraft({
      ...connection,
      ssh: { host: "build-alias" },
    })
    expect(draft.mode).toBe("ssh")
    expect(draft.sshPort).toBe("")
    expect(draft.token).toBe("")
    expect(draft.baseUrl).toBe("")
    expect(draft.headers).toEqual([])
  })

  it("preserves the legacy HTTP payload and clears SSH on a mode switch", () => {
    expect(remoteWorkspaceInput(remoteWorkspaceDraft(connection))).toEqual({
      input: {
        name: connection.name,
        baseUrl: connection.base_url,
        token: connection.token,
        headers: connection.headers,
      },
    })
    const switched = { ...sshDraft, mode: "http" as const }
    expect(remoteWorkspaceInput(switched).input).not.toHaveProperty("ssh")
  })

  it("formats the SSH locator, including IPv6, rather than a tunnel port", () => {
    expect(
      remoteWorkspaceAddress({
        ...connection,
        ssh: { host: "2001:db8::1", username: "coder", port: 2222 },
      })
    ).toBe("ssh://coder@[2001:db8::1]:2222")
    expect(remoteWorkspaceAddress(connection)).toBe(connection.base_url)
  })

  it("can test before naming, but cannot save an unnamed connection", () => {
    expect(remoteWorkspaceInput({ ...sshDraft, name: "" }).error).toBe(
      "nameRequired"
    )
    expect(
      remoteWorkspaceInput({ ...sshDraft, name: "" }, false).error
    ).toBeUndefined()
  })
})

import type {
  RemoteWorkspaceConnection,
  RemoteWorkspaceConnectionInput,
  RemoteWorkspaceHeader,
} from "@/lib/types"

export interface RemoteWorkspaceDraft {
  id: number | null
  name: string
  mode: "http" | "ssh"
  baseUrl: string
  token: string
  headers: RemoteWorkspaceHeader[]
  sshHost: string
  sshUsername: string
  sshPort: string
  sshIdentityFile: string
  sshRememberPassword: boolean
  sshCredentialId: string
}

export const EMPTY_REMOTE_WORKSPACE_DRAFT: RemoteWorkspaceDraft = {
  id: null,
  name: "",
  mode: "http",
  baseUrl: "",
  token: "",
  headers: [],
  sshHost: "",
  sshUsername: "",
  sshPort: "",
  sshIdentityFile: "",
  sshRememberPassword: false,
  sshCredentialId: "",
}

export function remoteWorkspaceDraft(
  connection: RemoteWorkspaceConnection
): RemoteWorkspaceDraft {
  return {
    ...EMPTY_REMOTE_WORKSPACE_DRAFT,
    id: connection.id,
    name: connection.name,
    mode: connection.ssh ? "ssh" : "http",
    baseUrl: connection.ssh ? "" : connection.base_url,
    token: connection.ssh ? "" : connection.token,
    headers: connection.ssh ? [] : (connection.headers ?? []),
    sshHost: connection.ssh?.host ?? "",
    sshUsername: connection.ssh?.username ?? "",
    sshPort: connection.ssh?.port?.toString() ?? "",
    sshIdentityFile: connection.ssh?.identityFile ?? "",
    sshRememberPassword: connection.ssh?.rememberPassword ?? false,
    sshCredentialId: connection.ssh?.credentialId ?? "",
  }
}

export function remoteWorkspaceAddress(
  connection: RemoteWorkspaceConnection
): string {
  const ssh = connection.ssh
  if (!ssh) return connection.base_url
  const host = ssh.host.includes(":") ? `[${ssh.host}]` : ssh.host
  return `ssh://${ssh.username ? `${ssh.username}@` : ""}${host}${ssh.port ? `:${ssh.port}` : ""}`
}

type ValidationKey =
  | "nameRequired"
  | "httpFieldsRequired"
  | "sshHostRequired"
  | "sshHostInvalid"
  | "sshUsernameInvalid"
  | "sshPortInvalid"
  | "sshIdentityInvalid"

type InputResult =
  | { input: RemoteWorkspaceConnectionInput; error?: never }
  | { error: ValidationKey; input?: never }

export function remoteWorkspaceInput(
  draft: RemoteWorkspaceDraft,
  requireName = true
): InputResult {
  if (requireName && !draft.name.trim()) return { error: "nameRequired" }
  if (draft.mode === "http") {
    if (!draft.baseUrl.trim() || !draft.token.trim()) {
      return { error: "httpFieldsRequired" }
    }
    // Preserve the legacy HTTP IPC shape, including custom headers. Omitting
    // ssh also clears it when switching an existing SSH profile to HTTP.
    return {
      input: {
        name: draft.name,
        baseUrl: draft.baseUrl,
        token: draft.token,
        headers: draft.headers,
      },
    }
  }
  const host = draft.sshHost.trim()
  const username = draft.sshUsername.trim()
  const port = draft.sshPort.trim()
  const identityFile = draft.sshIdentityFile.trim()
  if (!host) return { error: "sshHostRequired" }
  if (
    host.length > 255 ||
    host.startsWith("-") ||
    !/^[a-z0-9._:%-]+$/i.test(host)
  ) {
    return { error: "sshHostInvalid" }
  }
  if (
    username &&
    (username.length > 64 ||
      username.startsWith("-") ||
      !/^[a-z0-9._@$-]+$/i.test(username))
  ) {
    return { error: "sshUsernameInvalid" }
  }
  if (
    port &&
    (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)
  ) {
    return { error: "sshPortInvalid" }
  }
  if (
    identityFile.length > 4096 ||
    identityFile.startsWith("-") ||
    /\p{Cc}/u.test(identityFile)
  ) {
    return { error: "sshIdentityInvalid" }
  }
  return {
    input: {
      name: draft.name,
      baseUrl: "",
      token: "",
      headers: [],
      ssh: {
        host,
        ...(username ? { username } : {}),
        ...(port ? { port: Number(port) } : {}),
        ...(identityFile ? { identityFile } : {}),
        ...(draft.sshRememberPassword ? { rememberPassword: true } : {}),
        ...(draft.sshRememberPassword && draft.sshCredentialId
          ? { credentialId: draft.sshCredentialId }
          : {}),
      },
    },
  }
}

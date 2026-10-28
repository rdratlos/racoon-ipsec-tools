// RFC 0005 "provpaws" Phase 3: OpenCode capture adapter.
// Writes one JSON-lines session log per OpenCode session under
// .provpaws/sessions/ (git-ignored working data, never committed).
// `tools/prov.py declare --evidence opencode-session:FILE` reads it.
//
// Trust note (docs/research/rfc0005-phase3-model-identity.md): OpenCode's
// plugin API and session store only ever see the *configured* model. The
// `model` entries below are therefore `config` evidence, never `api`. For
// what actually answered behind a router, use tools/provcap-proxy.py.
import { mkdirSync, appendFileSync, existsSync, readFileSync } from "node:fs"
import path from "node:path"
import os from "node:os"

const DIR = process.env.PROVPAWS_DIR
  ? path.resolve(process.env.PROVPAWS_DIR)
  : path.join(".provpaws", "sessions")

const EDIT_TOOLS = new Set(["edit", "write", "patch", "multiedit"])

type Buf = { file: string; sessionID: string }
const bufs = new Map<string, Buf>()

function openBuf(sessionID: string): Buf {
  let b = bufs.get(sessionID)
  if (b) return b
  mkdirSync(DIR, { recursive: true })
  const p = path.join(DIR, `opencode-${sessionID}.jsonl`)
  b = { file: p, sessionID }
  if (!existsSync(p)) write(b, { type: "start", at: new Date().toISOString() })
  bufs.set(sessionID, b)
  return b
}

function write(b: Buf, ev: Record<string, unknown>) {
  appendFileSync(b.file, JSON.stringify({ sessionID: b.sessionID, ...ev }) + "\n")
}

export const ProvpawsCapture = async ({ directory }: { directory: string }) => {
  const root = path.resolve(directory)
  const rel = (p: string) => {
    if (!p) return p
    const abs = path.isAbsolute(p) ? p : path.join(root, p)
    const r = path.relative(root, abs)
    return r && !r.startsWith("..") && !path.isAbsolute(r) ? r : abs
  }
  const sessions = new Map<string, { agent?: string; model?: string; provider?: string; user?: string }>()
  const note = (sessionID: string, patch: Record<string, unknown>) => {
    const prev = sessions.get(sessionID) || {}
    const next = { ...prev, ...patch }
    sessions.set(sessionID, next)
    write(openBuf(sessionID), { type: "session", ...next })
  }
  const fileOf = (args: any) => {
    const p = args?.filePath || args?.path || args?.file
    return typeof p === "string" ? rel(p) : undefined
  }

  return {
    "chat.message": async (input: any, output: any) => {
      const model = input.model?.modelID
      const provider = input.model?.providerID
      const info = output?.message || {}
      if (!model && !provider && !info.agent) return
      if (!sessions.has(input.sessionID) && existsSync(
        path.join(DIR, `opencode-${input.sessionID}.jsonl`))) {
        try {
          for (const line of readFileSync(path.join(DIR, `opencode-${input.sessionID}.jsonl`), "utf8").split("\n")) {
            if (!line.trim()) continue
            const ev = JSON.parse(line)
            if (ev.type === "session") {
              const { type, sessionID, ...rest } = ev
              sessions.set(input.sessionID, rest)
              break
            }
          }
        } catch {}
      }
      const patch: Record<string, unknown> = {}
      if (input.agent) patch.agent = input.agent
      if (info.agent) patch.agent = info.agent
      if (model) patch.model = model
      if (provider) patch.provider = provider
      patch.user = new Date().toISOString()
      note(input.sessionID, patch)
    },
    "tool.execute.before": async (input: any, output: any) => {
      if (!EDIT_TOOLS.has(input.tool) || !input.sessionID) return
      const file = fileOf(output?.args)
      if (file) write(openBuf(input.sessionID), { type: "file", file, tool: input.tool, at: new Date().toISOString() })
    },
    "tool.execute.after": async (input: any, output: any) => {
      if (!EDIT_TOOLS.has(input.tool) || !input.sessionID) return
      const file = fileOf(input.args) || fileOf(output?.metadata)
      if (file) write(openBuf(input.sessionID), { type: "file", file, tool: input.tool, at: new Date().toISOString() })
    },
    event: async ({ event }: any) => {
      const p = event?.properties
      if (event?.type === "message.updated" && p?.info?.role === "assistant") {
        const i = p.info
        note(i.sessionID, { agent: i.mode, model: i.modelID, provider: i.providerID })
      } else if (event?.type === "file.edited" && p?.file) {
        const file = rel(p.file)
        for (const [, b] of bufs) write(b, { type: "file", file, tool: "file.edited", at: new Date().toISOString() })
      }
    },
  }
}

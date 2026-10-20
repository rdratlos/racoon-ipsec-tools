// OpenCode plugin used by q4_opencode.sh (RFC 0005 Phase 3 research).
// Records what each plugin hook receives about the model, as JSON lines in
// $PROVPROBE_LOG. Observation only: it changes no parameter or header.
import { appendFileSync } from "node:fs"

const LOG = process.env.PROVPROBE_LOG || "provprobe.jsonl"
const log = (hook, data) =>
  appendFileSync(LOG, JSON.stringify({ hook, t: Date.now(), ...data }) + "\n")

export const ProvProbe = async () => {
  log("init", {
    env: Object.fromEntries(Object.entries(process.env)
      .filter(([k]) => /^(OPENCODE|AGENT$|AI_AGENT|CLAUDECODE)/.test(k))
      .filter(([k]) => !/PASSWORD|TOKEN|KEY|AUTH/.test(k))),
  })
  return {
    "chat.message": async (input) =>
      log("chat.message", { model: input.model, agent: input.agent }),
    "chat.params": async (input) =>
      log("chat.params", {
        agent: input.agent,
        model: { id: input.model?.id, providerID: input.model?.providerID,
                 apiId: input.model?.api?.id },
        provider: { source: input.provider?.source, id: input.provider?.info?.id },
      }),
    "chat.headers": async (input, output) =>
      log("chat.headers", { model: input.model?.id,
                            requestHeaders: Object.keys(output.headers || {}) }),
    "tool.execute.after": async (input, output) =>
      log("tool.execute.after", { tool: input.tool,
                                  output: String(output.output).slice(0, 400) }),
    event: async ({ event }) => {
      if (event.type === "message.updated") {
        const i = event.properties.info
        log("event:message.updated", { role: i.role, modelID: i.modelID,
                                       providerID: i.providerID,
                                       userModel: i.model, finish: i.finish })
      } else if (/^session\.|^message\.part/.test(event.type)) {
        // keep the log small: names only
        log("event", { type: event.type })
      }
    },
  }
}

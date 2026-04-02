/**
 * Hook: before_tool_call — automatic interception of protected tool executions.
 *
 * Uses OpenClaw's `before_tool_call` plugin hook event to intercept tools
 * and require approval from the Airlock mobile approver.
 *
 * If `protectedTools` is empty, no tools are automatically protected
 * (opt-in model). Use the requestApproval tool for explicit control.
 *
 * Checks DND (Do Not Disturb) policies before requesting approval —
 * if a matching DND policy is active, the tool is auto-approved.
 *
 * Returns `{ block: true, blockReason }` to block, or `undefined` to allow.
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

/** Context passed to the before_tool_call hook by OpenClaw. */
export interface BeforeToolContext {
  /** The name of the tool being executed. */
  toolName: string;
  /** The tool's input parameters. */
  params?: Record<string, unknown>;
  /** The tool's input arguments (legacy compat). */
  toolInput?: unknown;
  /** Optional metadata about the tool call. */
  metadata?: Record<string, unknown>;
}

/** Return value for before_tool_call — OpenClaw checks these fields. */
export interface BeforeToolResult {
  block?: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
}

/**
 * Register the before_tool_call hook with the OpenClaw plugin API.
 *
 * @param api OpenClaw plugin API (api.registerHook)
 * @param client AirlockClient instance
 * @param config Validated AirlockConfig
 */
export function registerBeforeToolHook(
  api: { on: (hookName: string, handler: (event: unknown, ctx?: unknown) => unknown, opts?: { priority?: number }) => void },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  // OpenClaw API: api.on(hookName, handler) → registerTypedHook → registry.typedHooks (callable)
  // NOTE: api.registerHook() only adds to registry.hooks (metadata), never invoked by the hook runner.
  api.on("before_tool_call", async (rawContext: unknown) => {
    const context = rawContext as BeforeToolContext;
    const toolName = context.toolName;

    console.log(`[Airlock] tool:before_call fired — tool=${toolName}`);

    // ── Opt-in model: if protectedTools is empty, do nothing ──
    if (config.protectedTools.length === 0) {
      return {};
    }

    // ── Check if this tool is in the protected list ──
    const isProtected = config.protectedTools.some(
      (pattern) => matchToolName(toolName, pattern),
    );

    if (!isProtected) {
      console.log(`[Airlock] Tool ${toolName} not protected — allowing`);
      return {};
    }

    console.info(`[Airlock] Tool ${toolName} is PROTECTED — requesting approval`);

    // ── Check DND (Do Not Disturb) policies ──
    const dndActive = await client.isDndActive();

    if (dndActive) {
      console.info(`[Airlock] DND active — auto-approving tool ${toolName}`);
      return {};
    }

    // ── Build a readable command text from tool input ──
    const toolInput = context.params ?? context.toolInput;
    let commandText: string;
    try {
      commandText = typeof toolInput === "string"
        ? toolInput
        : JSON.stringify(toolInput, null, 2);
    } catch {
      commandText = String(toolInput);
    }

    // Truncate very long inputs
    const maxLen = 2000;
    if (commandText.length > maxLen) {
      commandText = commandText.slice(0, maxLen) + "\n... (truncated)";
    }

    // ── Request approval from Airlock Gateway ──
    const decision = await client.requestApproval({
      actionType: toolName,
      commandText,
      description: `Tool: ${toolName}`,
    });

    // ── Apply decision using OpenClaw's { block, blockReason } response ──
    if (decision.decision === "approved") {
      console.info(`[Airlock] Tool ${toolName} APPROVED`);
      return {};
    }

    if (decision.decision === "rejected") {
      const reason = decision.reason ?? "no reason provided";
      console.warn(`[Airlock] Tool ${toolName} DENIED — ${reason}`);
      return {
        block: true,
        blockReason: `Airlock: Action denied by approver — ${reason}. Do NOT retry this action automatically.`,
      };
    }

    // Timeout — apply failMode
    if (config.failMode === "closed") {
      console.warn(`[Airlock] Tool ${toolName} TIMEOUT — blocking (fail-closed)`);
      return {
        block: true,
        blockReason: "Airlock: Approval timed out — blocking (fail-closed). Do NOT retry this action automatically.",
      };
    }

    // failMode === "open" — allow silently
    console.warn(`[Airlock] Tool ${toolName} TIMEOUT — allowing (fail-open)`);
    return {};
  });
}

/**
 * Match a tool name against a pattern.
 * Supports exact match and glob-like wildcards (*).
 */
function matchToolName(toolName: string, pattern: string): boolean {
  // Exact match
  if (toolName === pattern) return true;

  // Simple wildcard: "shell.*" matches "shell.exec", "shell.run", etc.
  if (pattern.includes("*")) {
    const regex = new RegExp(
      "^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
    );
    return regex.test(toolName);
  }

  // Case-insensitive match
  if (toolName.toLowerCase() === pattern.toLowerCase()) return true;

  return false;
}

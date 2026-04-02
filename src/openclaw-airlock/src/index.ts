/**
 * Airlock Plugin for OpenClaw — Entry Point
 *
 * Registers all Airlock capabilities with the OpenClaw plugin system:
 * - Config validation
 * - Pairing state restoration from disk
 * - Presence heartbeat
 * - requestApproval tool (AI-callable)
 * - checkStatus tool (AI-callable)
 * - beforeTool hook (automatic enforcement with DND check)
 * - /airlock-status command (diagnostics)
 * - airlock setup CLI command
 * - airlock pair CLI command
 */

import { loadAndValidateConfig, type AirlockConfig } from "./config.js";
import { createAirlockClient, type AirlockClient } from "./client.js";
import { registerRequestApprovalTool } from "./tools/requestApproval.js";
import { registerCheckStatusTool } from "./tools/checkStatus.js";
import { registerBeforeToolHook } from "./hooks/beforeTool.js";
import { registerAirlockStatusCommand } from "./commands/airlockStatus.js";
import { registerCliCommands } from "./cli/register.js";

// ── OpenClaw Plugin API types ───────────────────────────────────
// These are minimal type stubs for the OpenClaw plugin SDK.
// Replace with actual imports from "openclaw/plugin-sdk" when available.

interface OpenClawPluginAPI {
  getConfig(): Record<string, unknown>;
  registerTool(def: unknown, handler: (input: unknown) => Promise<unknown>): void;
  registerHook(event: string, handler: (context: unknown) => Promise<unknown>, options?: { name?: string; description?: string }): void;
  registerCommand(def: unknown, handler: () => Promise<string>): void;
  registerCli(
    registrar: (ctx: { program: unknown; config: unknown; workspaceDir: string; logger: unknown }) => void | Promise<void>,
    opts?: { commands?: string[] },
  ): void;
  on(
    hookName: string,
    handler: (event: unknown, ctx?: unknown) => unknown,
    opts?: { priority?: number },
  ): void;
}

interface OpenClawPluginAPICompat extends Partial<OpenClawPluginAPI> {
  pluginConfig?: Record<string, unknown>;
}

interface PluginEntryDefinition {
  id: string;
  name: string;
  description: string;
  register(api: OpenClawPluginAPICompat): void;
}

/**
 * Stub for OpenClaw's definePluginEntry.
 * Replace with actual import when the SDK is available:
 *   import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
 */
function definePluginEntry(def: PluginEntryDefinition): PluginEntryDefinition {
  return def;
}

// ── Plugin Definition ───────────────────────────────────────────

export default definePluginEntry({
  id: "openclaw-airlock",
  name: "Airlock Security Gateway",
  description:
    "Enforces human-in-the-loop approval for risky AI actions via Airlock Gateway. " +
    "Supports tool-based and hook-based enforcement with polling-based decision handling.",

  register(api: OpenClawPluginAPICompat) {
    // AIRLOCK_COMPAT_SHIM v7
    if (!api.getConfig) {
      api.getConfig = () => api.pluginConfig ?? {};
    }
    const _oCmd = api.registerCommand;
    if (_oCmd) {
      api.registerCommand = function (a: unknown, b: unknown) {
        if (typeof b === "function") {
          return (_oCmd as (def: unknown) => void).call(
            api,
            Object.assign({}, a as Record<string, unknown>, { handler: b }),
          );
        }
        return (_oCmd as (def: unknown) => void).call(api, a);
      } as OpenClawPluginAPICompat["registerCommand"];
    }
    // Hook shim removed — using correct OpenClaw API: registerHook(event, handler, { name, description })
    // END AIRLOCK_COMPAT_SHIM

    const readyApi = api as OpenClawPluginAPI;

    // Phase 2: Config
    let config: AirlockConfig;
    try {
      config = loadAndValidateConfig(readyApi.getConfig());
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[Airlock] Plugin disabled — config error: ${msg}`);
      return;
    }

    // Phase 3: Client
    const client: AirlockClient = createAirlockClient(config);

    // Restore pairing state from disk + start presence heartbeat
    // (async — non-blocking; plugin is usable immediately if state exists in config)
    client.initialize().catch((err) => {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[Airlock] Initialization warning: ${msg}`);
    });

    // Phase 4: Tool — requestApproval
    registerRequestApprovalTool(readyApi, client, config);

    // Phase 5: Tool — checkStatus
    registerCheckStatusTool(readyApi, client, config);

    // Phase 6: Hook — beforeTool (with DND check)
    registerBeforeToolHook(readyApi, client, config);

    // Phase 7: Command — /airlock-status
    registerAirlockStatusCommand(readyApi, client, config);

    // Phase 8: CLI commands — single registrar for all airlock subcommands
    registerCliCommands(readyApi, client, config);

    console.info(
      `[Airlock] Plugin loaded — enforcer=${config.enforcerId}, ` +
      `failMode=${config.failMode}, ` +
      `protectedTools=${config.protectedTools.length > 0 ? config.protectedTools.join(",") : "(none)"}`,
    );
  },
});

// Re-export types for consumers
export type { AirlockConfig } from "./config.js";
export type { AirlockClient, Decision, ApprovalPayload, HealthResult, ConsentResult, ConsentStatus } from "./client.js";
export { loadAndValidateConfig, ConfigError } from "./config.js";
export { createAirlockClient } from "./client.js";

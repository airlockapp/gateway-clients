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
import { registerSetupCommand } from "./cli/setup.js";
import { registerPairCommand } from "./cli/pair.js";

// ── OpenClaw Plugin API types ───────────────────────────────────
// These are minimal type stubs for the OpenClaw plugin SDK.
// Replace with actual imports from "openclaw/plugin-sdk" when available.

interface OpenClawPluginAPI {
  pluginConfig?: Record<string, unknown>;
  getConfig?(): Record<string, unknown>;
  registerTool(def: unknown, handler: (input: unknown) => Promise<unknown>): void;
  registerHook?(event: string, handler: (context: unknown) => Promise<void>): void;
  registerCommand?(def: unknown, handler: () => Promise<string>): void;
  registerCliCommand?(def: unknown, handler: (args: unknown) => Promise<void>): void;
  registerCli?(def: unknown, handler: (args: unknown) => Promise<void>): void;
}

interface PluginEntryDefinition {
  id: string;
  name: string;
  description: string;
  register(api: OpenClawPluginAPI): void;
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
  id: "airlock",
  name: "Airlock Security Gateway",
  description:
    "Enforces human-in-the-loop approval for risky AI actions via Airlock Gateway. " +
    "Supports tool-based and hook-based enforcement with polling-based decision handling.",

  register(api: OpenClawPluginAPI) {
    // AIRLOCK_COMPAT_SHIM v6
    if (!api.getConfig) {
      api.getConfig = () => api.pluginConfig ?? {};
    }
    if (!api.registerCliCommand) {
      api.registerCliCommand = api.registerCli || (function (_def: unknown, _handler: (args: unknown) => Promise<void>) {});
    }
    const _oCmd = api.registerCommand;
    if (_oCmd) {
      api.registerCommand = function (a: unknown, b: unknown) {
        if (typeof b === "function") {
          return _oCmd.call(api, Object.assign({}, a as Record<string, unknown>, { handler: b }));
        }
        return (_oCmd as (def: unknown) => void).call(api, a);
      } as OpenClawPluginAPI["registerCommand"];
    }
    const _oHook = api.registerHook;
    if (_oHook) {
      api.registerHook = function (a: string, b: (context: unknown) => Promise<void>) {
        try {
          return _oHook.call(api, a, b);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          console.warn("[Airlock] registerHook warning:", msg);
        }
      };
    }
    // END AIRLOCK_COMPAT_SHIM

    // Phase 2: Config
    let config: AirlockConfig;
    try {
      config = loadAndValidateConfig(api.getConfig?.() ?? {});
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
      console.error(`[Airlock] Initialization warning: ${msg}`);
    });

    // Phase 4: Tool — requestApproval
    registerRequestApprovalTool(api, client, config);

    // Phase 5: Tool — checkStatus
    registerCheckStatusTool(api, client, config);

    // Phase 6: Hook — beforeTool (with DND check)
    registerBeforeToolHook(api, client, config);

    // Phase 7: Command — /airlock-status
    registerAirlockStatusCommand(api, client, config);

    // Phase 8: CLI commands
    registerSetupCommand(api, client, config);
    registerPairCommand(api, client, config);

    console.error(
      `[Airlock] Plugin loaded — enforcer=${config.enforcerId}, ` +
      `failMode=${config.failMode}, ` +
      `protectedTools=${config.protectedTools.length > 0 ? config.protectedTools.join(",") : "(none)"}`,
    );
  },
});

// Re-export types for consumers
export type { AirlockConfig } from "./config.js";
export type { AirlockClient, Decision, ApprovalPayload, HealthResult } from "./client.js";
export { loadAndValidateConfig, ConfigError } from "./config.js";
export { createAirlockClient } from "./client.js";

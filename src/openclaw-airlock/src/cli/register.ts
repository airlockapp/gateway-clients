/**
 * CLI registration — registers all Airlock CLI subcommands under `openclaw airlock`.
 *
 * All subcommands are registered in a single `registerCli` call because
 * OpenClaw deduplicates by top-level command name: if "airlock" is already
 * claimed, subsequent registrars for the same command are skipped.
 *
 * Subcommands:
 *   openclaw airlock setup  — Validate config and test gateway connectivity
 *   openclaw airlock pair   — Claim a pre-generated pairing code
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

export function registerCliCommands(
  api: {
    registerCli?(
      registrar: (ctx: { program: unknown }) => void | Promise<void>,
      opts?: { commands?: string[] },
    ): void;
  },
  client: AirlockClient,
  config: AirlockConfig,
): void {
  if (!api.registerCli) return;

  api.registerCli(
    ({ program }: { program: any }) => {
      const airlockCmd = program
        .command("airlock")
        .description("Airlock security gateway");

      // ── airlock setup ───────────────────────────────────────
      airlockCmd
        .command("setup")
        .description(
          "Validate Airlock configuration and test gateway connectivity",
        )
        .action(async () => {
          console.log("Airlock Setup");
          console.log("═".repeat(40));

          // 1. Config summary
          console.log(`\nGateway URL:    ${config.gatewayUrl}`);
          console.log(`Enforcer ID:   ${config.enforcerId}`);
          console.log(`Workspace:     ${config.workspaceName}`);
          console.log(`Fail Mode:     ${config.failMode}`);
          console.log(`Auth (PAT):    ${config.pat ? "✓" : "✗"}`);
          console.log(`Auth (Client): ${config.clientId ? "✓" : "✗"}`);

          // 2. Gateway connectivity
          console.log("\nTesting gateway connectivity...");
          const health = await client.checkHealth();
          if (health.connected) {
            console.log(`✓ Connected to ${health.gatewayUrl}`);
            if (health.serverTime) {
              console.log(`  Server time: ${health.serverTime}`);
            }
          } else {
            console.error(`✗ Cannot reach gateway: ${health.error}`);
            console.error("  Check the gatewayUrl in your plugin config.");
            return;
          }

          // 3. Pairing status
          if (config.routingToken && config.encryptionKey) {
            console.log("\n✓ Paired — ready to enforce");
          } else if (config.pairingCode) {
            console.log(
              "\n⚠ Not paired — run 'openclaw airlock pair' to claim your pairing code",
            );
          } else {
            console.log(
              "\n⚠ Not paired — configure a pairingCode and run 'openclaw airlock pair'",
            );
          }

          // 4. Protected tools
          if (config.protectedTools.length > 0) {
            console.log(`\nProtected tools (${config.protectedTools.length}):`);
            for (const tool of config.protectedTools) {
              console.log(`  • ${tool}`);
            }
          } else {
            console.log("\nNo tools protected via hook (opt-in model).");
            console.log(
              "Use the airlock_request_approval tool for explicit approval.",
            );
          }

          console.log("\n✓ Setup complete");
        });

      // ── airlock pair ────────────────────────────────────────
      airlockCmd
        .command("pair")
        .description(
          "Claim a pre-generated pairing code and establish encrypted communication",
        )
        .action(async () => {
          console.log("Airlock Pairing");
          console.log("═".repeat(40));

          // Check if already paired
          if (config.routingToken && config.encryptionKey) {
            console.log("✓ Already paired.");
            console.log("  To re-pair, clear the existing pairing first.");
            return;
          }

          // Check for pairing code
          if (!config.pairingCode) {
            console.error("✗ No pairing code configured.");
            console.error(
              "  Set 'pairingCode' in your Airlock plugin config.",
            );
            console.error(
              "  Generate a code in the Airlock admin dashboard or mobile app.",
            );
            return;
          }

          // Test gateway connectivity first
          const health = await client.checkHealth();
          if (!health.connected) {
            console.error(`✗ Cannot reach gateway: ${health.error}`);
            console.error("  Fix connectivity before pairing.");
            return;
          }

          console.log(`Gateway:      ${config.gatewayUrl}`);
          console.log(`Enforcer ID:  ${config.enforcerId}`);
          console.log(`Workspace:    ${config.workspaceName}`);
          console.log(`Pairing Code: ${config.pairingCode}`);
          console.log(
            "\nClaiming pairing code (X25519 ECDH key exchange)...",
          );

          try {
            const result = await client.claimPairing(config.pairingCode);

            console.log("\n✓ Pairing successful!");
            console.log(
              `  Routing Token: ${result.routingToken.slice(0, 12)}...`,
            );
            console.log(
              "  Encryption:    ✓ Key derived (X25519 ECDH + HKDF-SHA256)",
            );
            console.log(
              "  State File:    ✓ Persisted to .airlock/pairing-state.json",
            );
            console.log("\n  Airlock is now ready to enforce approvals.");
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`\n✗ Pairing failed: ${msg}`);

            if (msg.includes("expired")) {
              console.error(
                "  Generate a new pairing code and update your config.",
              );
            }
            if (msg.includes("x25519PublicKey")) {
              console.error(
                "  The pairing response may be missing key exchange data.",
              );
            }
          }
        });
    },
    { commands: ["airlock"] },
  );
}

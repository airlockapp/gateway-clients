/**
 * CLI: pair — Claim a pre-generated pairing code.
 *
 * Usage: openclaw airlock pair
 *
 * Reads the `pairingCode` from plugin config, claims it against the gateway,
 * derives the shared encryption key via X25519 ECDH, and persists the
 * pairing state to disk (`.airlock/pairing-state.json`).
 */

import type { AirlockClient } from "../client.js";
import type { AirlockConfig } from "../config.js";

/**
 * Register the `airlock pair` CLI command with the OpenClaw plugin API.
 *
 * Uses the OpenClaw `registerCli` API which receives a Commander.js-style
 * registrar function: `({ program }) => void`.
 */
export function registerPairCommand(
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
      const airlockCmd =
        program.commands?.find((c: any) => c.name() === "airlock") ??
        program.command("airlock").description("Airlock security gateway");

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

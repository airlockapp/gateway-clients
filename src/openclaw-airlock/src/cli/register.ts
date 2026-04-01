/**
 * CLI registration — registers all Airlock CLI subcommands under `openclaw airlock`.
 *
 * All subcommands are registered in a single `registerCli` call because
 * OpenClaw deduplicates by top-level command name: if "airlock" is already
 * claimed, subsequent registrars for the same command are skipped.
 *
 * Subcommands:
 *   openclaw airlock setup   — Validate config and test gateway connectivity
 *   openclaw airlock consent — Trigger and wait for user consent on the mobile app
 *   openclaw airlock pair    — Claim a pre-generated pairing code
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
          // Ensure pairing state is loaded from disk before checking config
          await client.ensureInitialized();

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

          // 3. Consent status
          try {
            const consent = await client.checkConsent();
            if (consent.status === "approved") {
              console.log("\n✓ App consent: approved");
            } else if (consent.status === "required") {
              console.log("\n⚠ App consent: required — run 'openclaw airlock consent' to trigger approval");
              if (consent.message) console.log(`  ${consent.message}`);
            } else if (consent.status === "pending") {
              console.log("\n⏳ App consent: pending — check your Airlock mobile app");
            } else if (consent.status === "denied") {
              console.error("\n✗ App consent: denied by user");
              if (consent.message) console.error(`  ${consent.message}`);
            }
          } catch {
            console.log("\n⚠ App consent: could not check (non-fatal)");
          }

          // 4. Pairing status
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

          // 5. Protected tools
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

      // ── airlock consent ─────────────────────────────────────
      airlockCmd
        .command("consent")
        .description(
          "Trigger and wait for user consent on the Airlock mobile app",
        )
        .action(async () => {
          await client.ensureInitialized();

          console.log("Airlock Consent");
          console.log("═".repeat(40));

          console.log(`\nEnforcer ID:  ${config.enforcerId}`);
          console.log(`Gateway:      ${config.gatewayUrl}`);

          // Initial check — this triggers the consent push if first time
          console.log("\nChecking consent status...");
          let consent = await client.checkConsent();

          if (consent.status === "approved") {
            console.log("✓ Consent already granted — you're good to go.");
            return;
          }

          if (consent.status === "denied") {
            console.error("✗ Consent was denied by the user.");
            console.error("  Ask the user to re-approve in the Airlock mobile app.");
            if (consent.consentUrl) {
              console.error(`  Consent URL: ${consent.consentUrl}`);
            }
            return;
          }

          // Status is "required" or "pending" — show instructions and poll
          console.log("\n┌─ Consent Required ──────────────────────────────┐");
          if (consent.message) {
            console.log(`│ ${consent.message}`);
          }
          console.log("│ A consent request has been sent to the user's");
          console.log("│ Airlock mobile app. Please approve it there.");
          if (consent.consentUrl) {
            console.log(`│ Or open: ${consent.consentUrl}`);
          }
          console.log("└─────────────────────────────────────────────────┘");
          console.log("\nWaiting for consent approval...");

          // Poll every 5 seconds for up to 5 minutes
          const deadline = Date.now() + 5 * 60 * 1000;
          let pollCount = 0;

          while (Date.now() < deadline) {
            await new Promise((r) => setTimeout(r, 5000));
            pollCount++;

            try {
              consent = await client.checkConsent();
            } catch {
              console.log(`  Poll ${pollCount}: error (retrying...)`);
              continue;
            }

            if (consent.status === "approved") {
              console.log(`\n✓ Consent granted! (after ${pollCount * 5}s)`);
              console.log("  You can now proceed with 'openclaw airlock pair'.");
              return;
            }

            if (consent.status === "denied") {
              console.error(`\n✗ Consent was denied. (after ${pollCount * 5}s)`);
              return;
            }

            const elapsed = pollCount * 5;
            console.log(`  Waiting... (${elapsed}s elapsed, status: ${consent.status})`);
          }

          console.error("\n✗ Timed out waiting for consent (5 minutes).");
          console.error("  Try again or check the Airlock mobile app.");
        });

      // ── airlock pair ────────────────────────────────────────
      airlockCmd
        .command("pair")
        .description(
          "Claim a pre-generated pairing code and establish encrypted communication",
        )
        .action(async () => {
          // Ensure pairing state is loaded from disk before checking config
          await client.ensureInitialized();

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

          // Check consent before attempting to pair
          try {
            const consent = await client.checkConsent();
            if (consent.status !== "approved") {
              console.error("⚠ App consent not yet granted.");
              console.error("  Run 'openclaw airlock consent' first to get user approval.");
              return;
            }
          } catch {
            // Consent check failed — continue with pairing anyway
            console.log("⚠ Could not verify consent status (continuing...)");
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
              "  State File:    ✓ Persisted to ~/.openclaw/.airlock/pairing-state.json",
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

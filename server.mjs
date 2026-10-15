import { config } from "./src/server/config.mjs";
import { close, listen } from "./src/server/server.mjs";
import { sessionCount } from "./src/server/database.mjs";

try {
  const server = await listen();
  const address = server.address();
  console.log(`AI Quality Governance Framework listening on http://${config.host}:${address.port}`);
  console.log(`Private governance data: ${config.dataRoot}`);
  if (config.generatedBootstrapToken && sessionCount() === 0) {
    console.log(`One-time administrator bootstrap token: ${config.bootstrapToken}`);
    console.log("Store this token securely; it will not be displayed again.");
  }

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${signal}: shutting down gracefully.`);
    try {
      await close();
      process.exitCode = 0;
    } catch (error) {
      console.error("Graceful shutdown failed:", error);
      process.exitCode = 1;
    }
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
} catch (error) {
  console.error("Governance service failed to start:", error);
  process.exitCode = 1;
}

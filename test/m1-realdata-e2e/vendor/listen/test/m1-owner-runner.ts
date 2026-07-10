import { fileURLToPath, URL } from "node:url";
import { createServer } from "../frontend/node_modules/vite/dist/node/index.js";

const root = fileURLToPath(new URL("..", import.meta.url));

async function main() {
  const server = await createServer({
    configFile: false,
    root,
    appType: "custom",
    logLevel: "error",
    resolve: {
      alias: [
        {
          find: /^@listen\/client$/,
          replacement: fileURLToPath(new URL("./listen-client-shim.ts", import.meta.url)),
        },
        {
          find: /^@tinycloud\/sdk-core$/,
          replacement: fileURLToPath(
            new URL(
              "../frontend/node_modules/@tinycloud/sdk-core-m1/dist/index.js",
              import.meta.url,
            ),
          ),
        },
        {
          find: /^@tinycloud\/sdk-core\/policy$/,
          replacement: fileURLToPath(
            new URL(
              "../frontend/node_modules/@tinycloud/sdk-core-m1/dist/policy/index.js",
              import.meta.url,
            ),
          ),
        },
        {
          find: /^@tinycloud\/sdk-core\/bootstrap$/,
          replacement: fileURLToPath(
            new URL(
              "../frontend/node_modules/@tinycloud/sdk-core-m1/dist/bootstrap/index.js",
              import.meta.url,
            ),
          ),
        },
        {
          find: /^@tinycloud\/bootstrap$/,
          replacement: fileURLToPath(
            new URL(
              "../frontend/node_modules/@tinycloud/bootstrap-m1/dist/index.js",
              import.meta.url,
            ),
          ),
        },
        {
          find: /^@tinycloud\/sdk-services$/,
          replacement: fileURLToPath(
            new URL(
              "../frontend/node_modules/@tinycloud/sdk-services-m1/dist/index.js",
              import.meta.url,
            ),
          ),
        },
      ],
    },
    server: {
      middlewareMode: true,
    },
    ssr: {
      noExternal: true,
    },
  });

  try {
    const module = (await server.ssrLoadModule("/test/m1-owner-demo.ts")) as {
      runCli: (argv: string[]) => Promise<void>;
    };
    await module.runCli(process.argv.slice(2));
  } finally {
    await server.close();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});

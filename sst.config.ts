/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
  app(input) {
    return {
      name: "tinycloud",
      removal: input?.stage === "production" ? "retain" : "remove",
      home: "aws",
    };
  },
  async run() {
    // Detect environment type
    const isPR = $app.stage.startsWith("pr-");
    const isProd = $app.stage === "production";
    const isDev = !isPR && !isProd;
    const secrets = {
      tinycloudKeysSecret: new sst.Secret("TINYCLOUD_KEYS_SECRET"),
      awsAccessKeyId: new sst.Secret("AWS_ACCESS_KEY_ID"),
      awsSecretAccessKey: new sst.Secret("AWS_SECRET_ACCESS_KEY"),
    };

    const bucket = new sst.aws.Bucket("BlockStorage", {
      public: false,
    });

    const vpc = new sst.aws.Vpc("TinycloudVpc", {
      // v2 Cluster doesn't require NAT gateways - cost optimization
    });

    const cluster = new sst.aws.Cluster("TinycloudCluster", {
      vpc,
      forceUpgrade: "v2",
    });

    const database = new sst.aws.Postgres.v1("Database", {
      vpc,
      scaling: {
        min: isPR ? "0.5 ACU" : isProd ? "2 ACU" : "0.5 ACU",
        max: isPR ? "1 ACU" : isProd ? "16 ACU" : "2 ACU",
        pauseAfter: isPR ? "10 minutes" : isProd ? undefined : "30 minutes",
      },
    });

    // Get image from environment or build locally for dev
    const image = process.env.TINYCLOUD_IMAGE || {
      context: ".",
      dockerfile: "Dockerfile",
    };

    const service = new sst.aws.Service("TinycloudService", {
      cluster,
      image,
      cpu: isPR ? "0.5 vCPU" : isProd ? "2 vCPU" : "1 vCPU",
      memory: isPR ? "1 GB" : isProd ? "4 GB" : "2 GB",
      link: [bucket, database, ...Object.values(secrets)],
      scaling: {
        min: isPR ? 1 : isProd ? 2 : 1,
        max: isPR ? 2 : isProd ? 20 : 5,
        cpuUtilization: 70,
        memoryUtilization: 80,
      },
      loadBalancer: {
        ports: [{ listen: "80/http", forward: "8000/http" }],
        health: {
          "8000/http": {
            path: "/healthz",
            interval: "30 seconds",
            timeout: "10 seconds",
            unhealthyThreshold: 3,
          },
        },
      },
      dev: {
        command: "cargo run",
        directory: ".",
        autostart: true,
        watch: ["src", "Cargo.toml", "Cargo.lock"],
        // Ensure we always connect to cloud resources in dev mode
        env: {
          // Force S3 storage type for dev (no local filesystem option)
          TINYCLOUD_STORAGE_BLOCKS_TYPE: "S3",
          // Add debug logging for dev
          RUST_LOG: "debug",
          RUST_BACKTRACE: "1",
        },
      },
      environment: {
        // TinyCloud configuration
        TINYCLOUD_LOG_LEVEL: isDev ? "debug" : "normal",
        TINYCLOUD_ADDRESS: "0.0.0.0",
        TINYCLOUD_PORT: "8000",
        
        // Storage configuration - ALWAYS use cloud resources
        TINYCLOUD_STORAGE_BLOCKS_TYPE: "S3",
        TINYCLOUD_STORAGE_BLOCKS_BUCKET: bucket.name,
        TINYCLOUD_STORAGE_DATABASE: database.connectionString,
        TINYCLOUD_STORAGE_STAGING: "Memory",
        
        // Authentication configuration
        TINYCLOUD_KEYS_TYPE: "Static",
        TINYCLOUD_KEYS_SECRET: secrets.tinycloudKeysSecret.value,
        
        // AWS credentials for S3 access
        AWS_ACCESS_KEY_ID: secrets.awsAccessKeyId.value,
        AWS_SECRET_ACCESS_KEY: secrets.awsSecretAccessKey.value,
        AWS_DEFAULT_REGION: "us-east-1",
        
        // Rocket configuration
        ROCKET_ADDRESS: "0.0.0.0",
        ROCKET_PORT: "8000",
        
        // Debug configuration for dev
        ...(isDev && {
          RUST_LOG: "tinycloud=debug,info",
          RUST_BACKTRACE: "1",
        }),
      },
    });

    return {
      serviceUrl: service.url,
      bucketName: bucket.name,
      databaseHost: database.host,
    };
  },
});
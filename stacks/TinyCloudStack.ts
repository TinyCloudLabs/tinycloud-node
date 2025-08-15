import { StackContext, Service, Bucket, RDS, Config } from "sst/constructs";
import * as efs from "@aws-cdk/aws-efs-alpha";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";

export function TinyCloudStack({ stack }: StackContext) {
  // Configuration secrets
  const secrets = Config.Secret.create(stack, 
    "TINYCLOUD_KEYS_SECRET",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY"
  );

  // S3 bucket for block storage (when using S3 mode)
  const blocksBucket = new Bucket(stack, "BlockStorage", {
    cors: true,
  });

  // RDS database (PostgreSQL recommended for production)
  const database = new RDS(stack, "Database", {
    engine: "postgresql13.7",
    defaultDatabaseName: "tinycloud",
    scaling: {
      autoPause: true,
      minCapacity: "ACU_2",
      maxCapacity: "ACU_16",
    },
  });

  // EFS for persistent local storage (when using Local mode)
  const fileSystem = new efs.FileSystem(stack, "FileSystem", {
    encrypted: true,
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });

  // Access point for TinyCloud data
  const accessPoint = new efs.AccessPoint(stack, "AccessPoint", {
    fileSystem,
    path: "/tinycloud",
    createAcl: {
      ownerGid: "1000",
      ownerUid: "1000",
      permissions: "755",
    },
    posixUser: {
      gid: "1000",
      uid: "1000",
    },
  });

  // Main TinyCloud service
  const service = new Service(stack, "TinyCloudService", {
    path: ".",
    port: 8000,
    
    // Container configuration
    cpu: "1 vCPU",
    memory: "2 GB",
    
    // Auto-scaling configuration
    scaling: {
      minContainers: 2,
      maxContainers: 10,
      cpuUtilization: 70,
      memoryUtilization: 80,
      requestsPerContainers: 1000,
    },

    // Environment variables
    environment: {
      TINYCLOUD_LOG_LEVEL: "normal",
      TINYCLOUD_ADDRESS: "0.0.0.0",
      TINYCLOUD_PORT: "8000",
      TINYCLOUD_STORAGE_BLOCKS_TYPE: "S3",
      TINYCLOUD_STORAGE_BLOCKS_BUCKET: blocksBucket.bucketName,
      TINYCLOUD_STORAGE_DATABASE: `postgres://${database.defaultDatabaseName}`,
      TINYCLOUD_STORAGE_STAGING: "Memory",
      TINYCLOUD_KEYS_TYPE: "Static",
      ROCKET_ADDRESS: "0.0.0.0",
      ROCKET_PORT: "8000",
    },

    // Bind resources
    bind: [blocksBucket, database, ...secrets],

    // Mount EFS for local storage option
    volumes: [{
      efs: {
        fileSystem,
        accessPoint,
      },
      path: "/tinycloud/blocks",
    }],

    // Health check
    health: {
      path: "/healthz",
      interval: "30 seconds",
      timeout: "10 seconds",
      retries: 3,
    },
  });

  // CloudWatch alarms for monitoring
  const cpuAlarm = new cloudwatch.Alarm(stack, "CPUAlarm", {
    metric: service.metricCpuUtilization(),
    threshold: 85,
    evaluationPeriods: 2,
  });

  const memoryAlarm = new cloudwatch.Alarm(stack, "MemoryAlarm", {
    metric: service.metricMemoryUtilization(),
    threshold: 85,
    evaluationPeriods: 2,
  });

  // Outputs
  stack.addOutputs({
    ServiceUrl: service.url,
    BucketName: blocksBucket.bucketName,
    DatabaseSecretArn: database.secretArn,
  });
}
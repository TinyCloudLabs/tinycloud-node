# TinyCloud SST Deployment Guide

## Prerequisites

1. Install SST v3: `npm install -g sst`
2. Install AWS CLI and configure credentials
3. Install Docker for building containers

## Deployment Steps

### 1. Initialize SST Project

```bash
# Install SST dependencies
npm init -y
npm install sst @aws-cdk/aws-efs-alpha typescript
```

### 2. Configure Environment

Create `.env` file for local testing:
```env
TINYCLOUD_KEYS_SECRET=your-base64-encoded-secret-here
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### 3. Deploy to AWS

```bash
# Deploy to development
npx sst deploy --stage dev

# Deploy to production
npx sst deploy --stage prod
```

### 4. Configuration Options

The deployment uses:
- **ECS Fargate** for serverless container hosting
- **RDS Aurora Serverless** for database (auto-scales)
- **S3** for block storage
- **EFS** for persistent file storage (optional)
- **Application Load Balancer** for traffic distribution

### 5. Monitoring

- CloudWatch dashboards automatically created
- CPU and Memory alarms configured at 85% threshold
- Access logs via: `npx sst console`

## Architecture Decision: Fargate vs EC2

We chose **AWS Fargate** because:

1. **Serverless Operations**: No server management required
2. **Auto-scaling**: Built-in scaling based on CPU/memory/requests
3. **Cost Efficiency**: Pay only for resources used
4. **Security**: Each container runs in isolation
5. **Perfect for TinyCloud**: Handles variable workloads efficiently

## Switching Between Storage Modes

### S3 Storage (Recommended)
```typescript
environment: {
  TINYCLOUD_STORAGE_BLOCKS_TYPE: "S3",
  TINYCLOUD_STORAGE_BLOCKS_BUCKET: blocksBucket.bucketName,
}
```

### Local Storage with EFS
```typescript
environment: {
  TINYCLOUD_STORAGE_BLOCKS_TYPE: "Local",
  TINYCLOUD_STORAGE_BLOCKS_PATH: "/tinycloud/blocks",
}
```

## Cost Optimization

1. Use Aurora Serverless with auto-pause for dev environments
2. Configure appropriate container sizes (start with 1 vCPU, 2GB RAM)
3. Set minimum containers to 2 for production, 1 for development
4. Use S3 lifecycle policies for old block data

## Security Best Practices

1. All secrets stored in AWS Secrets Manager
2. EFS encrypted at rest
3. Network isolation with VPC
4. IAM roles with least privilege
5. Regular security updates via new container deployments
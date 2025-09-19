# TinyCloud SST Deployment Quick Start

## Prerequisites
- Node.js 18+ installed
- AWS CLI configured with credentials
- Docker installed (for building containers)
- SST CLI: `npm install -g sst`

## Quick Deploy

1. **Install dependencies**
```bash
npm install
```

2. **Set up secrets** (one time only)
```bash
# Generate a secure secret key (32+ bytes)
openssl rand -base64 32

# Set the secret in SST
npx sst secrets set TINYCLOUD_KEYS_SECRET "your-generated-secret"
npx sst secrets set AWS_ACCESS_KEY_ID "your-access-key" 
npx sst secrets set AWS_SECRET_ACCESS_KEY "your-secret-key"
```

3. **Deploy to AWS**
```bash
# Development environment
npx sst deploy --stage dev

# Production environment  
npx sst deploy --stage prod
```

4. **Access your deployment**
After deployment, SST will output:
- ServiceUrl: Your TinyCloud API endpoint
- BucketName: S3 bucket for block storage
- DatabaseSecretArn: RDS database connection info

## Storage Configuration

By default, uses S3 for block storage. To switch to EFS:

1. Edit `stacks/TinyCloudStack.ts`
2. Change `TINYCLOUD_STORAGE_BLOCKS_TYPE` from "S3" to "Local"
3. Set `TINYCLOUD_STORAGE_BLOCKS_PATH` to "/tinycloud/blocks"
4. Redeploy

## Monitoring

View logs and metrics:
```bash
npx sst console
```

## Remove Deployment

```bash
npx sst remove --stage dev
```

## Troubleshooting

1. **Build fails**: Ensure Docker is running
2. **Deploy fails**: Check AWS credentials and permissions
3. **Health check fails**: Verify the service started correctly in CloudWatch logs
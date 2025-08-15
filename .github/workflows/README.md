# TinyCloud GitHub Workflows

This directory contains automated deployment workflows for TinyCloud using SST and AWS.

## Workflows

### 1. PR Preview Deploy (`pr-deploy.yml`)
- **Triggers**: On PR open, synchronize, or reopen
- **Actions**:
  - **Build & Push**: Builds Docker image and pushes to ECR with tag `pr-{number}`
  - **Deploy**: Creates isolated environment with stage name `pr-{number}`
  - **Infrastructure**: Deploys with its own database (Aurora Serverless)
  - **Notification**: Posts/updates a comment with the preview URL
  - **Optimization**: Uses smaller resources and pre-built containers to save costs and time

### 2. PR Preview Cleanup (`pr-cleanup.yml`)
- **Triggers**: On PR close
- **Actions**:
  - Removes all AWS resources for the PR
  - Updates the PR comment to show cleanup status
  - Ensures no orphaned resources

### 3. Production Deploy (`deploy-production.yml`)
- **Triggers**: On push to `main` branch
- **Actions**:
  - **Test**: Runs Rust tests before deployment
  - **Build & Push**: Builds optimized Docker image and pushes to ECR with tags `latest` and `main-{sha}`
  - **Deploy**: Deploys to production stage using pre-built container
  - **Resources**: Uses production-grade resources
  - **Record**: Creates GitHub deployment record
  - **Cleanup**: Configures ECR lifecycle policies to manage image retention

## Required GitHub Secrets

Set these in your repository's Settings → Secrets:

### AWS Deployment
- `AWS_DEPLOY_ROLE_ARN`: ARN of the IAM role for GitHub Actions (uses OIDC)

### TinyCloud Secrets
- `TINYCLOUD_AWS_ACCESS_KEY_ID`: AWS access key for TinyCloud S3 operations
- `TINYCLOUD_AWS_SECRET_ACCESS_KEY`: AWS secret key for TinyCloud S3 operations
- `PROD_TINYCLOUD_KEYS_SECRET`: Production static key secret (base64 encoded, 32+ bytes)
- `PROD_TINYCLOUD_AWS_ACCESS_KEY_ID`: Production AWS access key
- `PROD_TINYCLOUD_AWS_SECRET_ACCESS_KEY`: Production AWS secret key

## AWS IAM Setup

### Quick Fix (if you get IAM permissions error)

If deployment fails with `iam:CreateRole` permission denied:

```bash
aws iam attach-role-policy \
  --role-name GitHubActions-TinyCloud-Deploy \
  --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
```

### Secure Setup (Recommended)

For new setups, use the secure script with minimal permissions:

```bash
cd scripts
./setup-github-oidc-secure.sh YOUR_AWS_ACCOUNT_ID YOUR_ORG/REPO_NAME
```

This creates:
- OIDC provider for GitHub Actions
- IAM role with trust policy
- Custom policy with only required IAM permissions (not full IAM access)

### Manual Setup

1. Run the basic setup script:
```bash
./scripts/setup-github-oidc.sh YOUR_AWS_ACCOUNT_ID YOUR_ORG/REPO_NAME
```

2. The script attaches these policies:
   - `PowerUserAccess` (for most AWS services)
   - `IAMFullAccess` (for ECS role creation)

### Why IAM Permissions Are Needed

SST creates IAM roles for:
- ECS task execution roles
- ECS service roles  
- Lambda execution roles (if using functions)
- Other service-linked roles

The deployment fails without IAM permissions because PowerUserAccess specifically excludes IAM and Organizations services.

## Container Optimization

### ECR Setup

Before first deployment, set up the ECR repository:

```bash
./scripts/setup-ecr.sh
```

This creates:
- ECR repository named `tinycloud`
- Lifecycle policies for automatic image cleanup
- Security scanning enabled

### Build Optimization Strategy

**Build Once, Deploy Everywhere:**
1. **GitHub Actions**: Builds Docker image with Rust compilation
2. **ECR Storage**: Stores tagged images (`pr-123`, `main-abc1234`, `latest`)
3. **SST Deploy**: Uses pre-built image, skips compilation entirely

**Benefits:**
- ⚡ **Faster deployments**: No Rust compilation during deploy (5-10x faster)
- 🔄 **Reliable retries**: Same image for retries, no rebuild needed
- 🎯 **Consistent environments**: Exact same container in test and production
- 💰 **Cost savings**: Less compute time in deployment phase

**Image Tagging Strategy:**
- PR environments: `pr-123`, `pr-123-abc1234`
- Production: `latest`, `main-abc1234`
- Automatic cleanup via lifecycle policies

### Caching Strategy

- **Docker layer cache**: Shared between workflow runs via GitHub Actions cache
- **Cargo dependencies**: Cached using cargo-chef in multi-stage build
- **Incremental builds**: Only changed layers rebuilt

## Environment Isolation

Each PR gets:
- Isolated Aurora Serverless database
- Separate S3 bucket for block storage
- Unique secrets and configuration
- Independent scaling settings

## Cost Optimization

PR environments are configured to minimize costs:
- Aurora auto-pauses after 10 minutes of inactivity
- Smaller container sizes (0.5 vCPU, 1GB RAM)
- Maximum 2 containers (vs 20 in production)
- Automatic cleanup on PR close

## Monitoring

- Check deployment status in GitHub Actions tab
- View SST console: `npx sst console --stage pr-123`
- CloudWatch logs available in AWS Console
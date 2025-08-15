# TinyCloud GitHub Workflows

This directory contains automated deployment workflows for TinyCloud using SST and AWS.

## Workflows

### 1. PR Preview Deploy (`pr-deploy.yml`)
- **Triggers**: On PR open, synchronize, or reopen
- **Actions**:
  - Builds the Rust application
  - Creates an isolated environment with stage name `pr-{number}`
  - Deploys with its own database (Aurora Serverless)
  - Posts/updates a comment with the preview URL
  - Uses smaller resources to save costs

### 2. PR Preview Cleanup (`pr-cleanup.yml`)
- **Triggers**: On PR close
- **Actions**:
  - Removes all AWS resources for the PR
  - Updates the PR comment to show cleanup status
  - Ensures no orphaned resources

### 3. Production Deploy (`deploy-production.yml`)
- **Triggers**: On push to `main` branch
- **Actions**:
  - Runs tests before deployment
  - Builds optimized release binary
  - Deploys to production stage
  - Uses production-grade resources
  - Creates GitHub deployment record

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
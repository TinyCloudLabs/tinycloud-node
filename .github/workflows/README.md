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

1. Create an OIDC provider for GitHub Actions:
```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

2. Create an IAM role with trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/tinycloud:*"
        }
      }
    }
  ]
}
```

3. Attach necessary policies for SST deployment (see SST documentation)

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
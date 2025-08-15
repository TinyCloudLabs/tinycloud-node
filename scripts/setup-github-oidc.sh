#!/bin/bash

# Script to set up GitHub Actions OIDC for AWS deployments

set -e

# Check if required arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <aws-account-id> <github-org/repo>"
    echo "Example: $0 123456789012 myorg/tinycloud"
    exit 1
fi

AWS_ACCOUNT_ID=$1
GITHUB_REPO=$2

echo "Setting up GitHub OIDC for AWS Account: $AWS_ACCOUNT_ID and Repo: $GITHUB_REPO"

# Create OIDC provider (skip if already exists)
echo "Creating OIDC provider..."
aws iam create-open-id-connect-provider \
    --url https://token.actions.githubusercontent.com \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 \
    2>/dev/null || echo "OIDC provider already exists"

# Create trust policy
TRUST_POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:${GITHUB_REPO}:*"
                }
            }
        }
    ]
}
EOF
)

# Create IAM role
ROLE_NAME="GitHubActions-TinyCloud-Deploy"
echo "Creating IAM role: $ROLE_NAME"

aws iam create-role \
    --role-name $ROLE_NAME \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "Role for GitHub Actions to deploy TinyCloud via SST" \
    || echo "Role already exists"

# Attach necessary policies for SST
echo "Attaching policies..."

# SST requires broad permissions for CloudFormation and resource creation
aws iam attach-role-policy \
    --role-name $ROLE_NAME \
    --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# Get the role ARN
ROLE_ARN=$(aws iam get-role --role-name $ROLE_NAME --query 'Role.Arn' --output text)

echo ""
echo "✅ Setup complete!"
echo ""
echo "Add the following secret to your GitHub repository:"
echo "  Name: AWS_DEPLOY_ROLE_ARN"
echo "  Value: $ROLE_ARN"
echo ""
echo "For more restrictive permissions, see the SST documentation on IAM permissions."
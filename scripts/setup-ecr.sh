#!/bin/bash

# Script to set up ECR repository for TinyCloud container images

set -e

# Default values
REPOSITORY_NAME="tinycloud"
AWS_REGION="us-east-1"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --repository-name)
      REPOSITORY_NAME="$2"
      shift 2
      ;;
    --region)
      AWS_REGION="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--repository-name NAME] [--region REGION]"
      echo ""
      echo "Options:"
      echo "  --repository-name NAME    ECR repository name (default: tinycloud)"
      echo "  --region REGION          AWS region (default: us-east-1)"
      echo "  -h, --help               Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

echo "Setting up ECR repository: $REPOSITORY_NAME in region: $AWS_REGION"

# Check if repository already exists
if aws ecr describe-repositories --repository-names "$REPOSITORY_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
    echo "✅ ECR repository '$REPOSITORY_NAME' already exists"
    REPOSITORY_URI=$(aws ecr describe-repositories --repository-names "$REPOSITORY_NAME" --region "$AWS_REGION" --query 'repositories[0].repositoryUri' --output text)
else
    echo "Creating ECR repository..."
    
    # Create the repository
    REPOSITORY_URI=$(aws ecr create-repository \
        --repository-name "$REPOSITORY_NAME" \
        --region "$AWS_REGION" \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256 \
        --query 'repository.repositoryUri' \
        --output text)
    
    echo "✅ Created ECR repository: $REPOSITORY_URI"
fi

# Set up lifecycle policy to manage image cleanup
echo "Setting up lifecycle policy..."

cat <<EOF > /tmp/lifecycle-policy.json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep last 10 production images (main- prefix)",
      "selection": {
        "tagStatus": "tagged",
        "tagPrefixList": ["main-"],
        "countType": "imageCountMoreThan",
        "countNumber": 10
      },
      "action": {
        "type": "expire"
      }
    },
    {
      "rulePriority": 2,
      "description": "Keep last 5 PR images per PR",
      "selection": {
        "tagStatus": "tagged",
        "tagPrefixList": ["pr-"],
        "countType": "imageCountMoreThan",
        "countNumber": 20
      },
      "action": {
        "type": "expire"
      }
    },
    {
      "rulePriority": 3,
      "description": "Remove untagged images after 1 day",
      "selection": {
        "tagStatus": "untagged",
        "countType": "sinceImagePushed",
        "countUnit": "days",
        "countNumber": 1
      },
      "action": {
        "type": "expire"
      }
    }
  ]
}
EOF

aws ecr put-lifecycle-policy \
    --repository-name "$REPOSITORY_NAME" \
    --region "$AWS_REGION" \
    --lifecycle-policy-text file:///tmp/lifecycle-policy.json

rm /tmp/lifecycle-policy.json

echo "✅ Lifecycle policy configured"

# Optional: Set up repository policy for cross-account access
# (uncomment if you need to share images across AWS accounts)
# cat <<EOF > /tmp/repository-policy.json
# {
#   "Version": "2008-10-17",
#   "Statement": [
#     {
#       "Sid": "AllowPull",
#       "Effect": "Allow",
#       "Principal": {
#         "AWS": "arn:aws:iam::ACCOUNT_ID:root"
#       },
#       "Action": [
#         "ecr:GetDownloadUrlForLayer",
#         "ecr:BatchGetImage",
#         "ecr:BatchCheckLayerAvailability"
#       ]
#     }
#   ]
# }
# EOF

# aws ecr set-repository-policy \
#     --repository-name "$REPOSITORY_NAME" \
#     --region "$AWS_REGION" \
#     --policy-text file:///tmp/repository-policy.json

echo ""
echo "🎉 ECR repository setup complete!"
echo ""
echo "Repository URI: $REPOSITORY_URI"
echo "Region: $AWS_REGION"
echo ""
echo "You can now push images to this repository using:"
echo "  docker tag your-image:latest $REPOSITORY_URI:latest"
echo "  docker push $REPOSITORY_URI:latest"
echo ""
echo "The GitHub Actions workflows will automatically use this repository."
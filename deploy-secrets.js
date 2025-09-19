#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const envPath = path.join(__dirname, '.env');

if (!fs.existsSync(envPath)) {
  console.error('❌ .env file not found');
  process.exit(1);
}

const secrets = Object.entries(process.env).filter(([key]) => 
  key.startsWith('TINYCLOUD_') || key.startsWith('AWS_')
);

if (secrets.length === 0) {
  console.log('No secrets found to deploy');
  process.exit(0);
}

console.log(`🔐 Deploying ${secrets.length} secrets to SST...`);

for (const [key, value] of secrets) {
  try {
    console.log(`Setting ${key}...`);
    execSync(`npx sst secret set ${key} "${value}"`, { stdio: 'inherit' });
    console.log(`✅ ${key} set successfully`);
  } catch (error) {
    console.error(`❌ Failed to set ${key}: ${error.message}`);
    process.exit(1);
  }
}

console.log('✨ All secrets deployed successfully!');
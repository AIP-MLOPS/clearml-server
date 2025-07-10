#!/usr/bin/env bash
set -x
set -e

cd /opt/open-webapp/
# sleep 15 

# npm ci --legacy-peer-deps
npm ci --legacy-peer-deps --registry="https://mirror-npm.runflare.com"
# echo passed
# sleep 50 
echo "--- Building main application ---"
cd /opt/open-webapp/
npm run build
echo "--- Listing contents of /opt/open-webapp/build ---"
# ls -la /opt/open-webapp/build

echo "--- Building widgets ---"
npm run build-widgets
echo "--- Listing contents of /opt/open-webapp/dist ---"
# ls -la /opt/open-webapp/dist


#!/bin/bash

# Build both Lambda functions
echo "🔨 Building Lambda functions..."

# Build instant handler
cd cmd/instant-handler
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap
zip ../../instant-function.zip bootstrap
echo "✅ Built instant-handler"

# Build batch handler  
cd ../batch-handler
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap
zip ../../batch-function.zip bootstrap
echo "✅ Built batch-handler"

cd ../..
echo "Lambda functions packaged successfully!"
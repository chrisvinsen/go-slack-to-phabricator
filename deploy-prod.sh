#!/bin/sh

set +e

gcloud --project sirclo-prod alpha functions deploy alert-to-slack \
  --entry-point F \
  --memory 128MB \
  --region asia-east2 \
  --runtime go113 \
  --env-vars-file .env.production.yaml \
  --trigger-http

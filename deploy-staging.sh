#!/bin/sh

set +e

gcloud --project sirclo-1152 alpha functions deploy slack-to-phabricator --verbosity debug \
  --entry-point F \
  --memory 128MB \
  --region asia-east2 \
  --runtime go113 \
  --env-vars-file .env.staging.yaml \
  --trigger-http \
  --allow-unauthenticated
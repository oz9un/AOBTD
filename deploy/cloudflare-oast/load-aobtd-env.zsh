#!/bin/zsh

export AOBTD_OAST_BASE_URL="${AOBTD_OAST_BASE_URL:-https://oast.aobtd.com}"
export AOBTD_OAST_API_TOKEN="$(security find-generic-password -a "$USER" -s aobtd-oast-api-token -w)"
export AOBTD_OAST_SIGNING_KEY="$(security find-generic-password -a "$USER" -s aobtd-oast-signing-key -w)"

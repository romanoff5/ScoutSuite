#!/bin/bash
set -euo pipefail
scout_docker_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
scout_root="$(cd -- "${scout_docker_dir}/.." && pwd)"
scout_target="${1:-base}"
case "${scout_target}" in
  base|combined)
    docker build -f "${scout_docker_dir}/Dockerfile-base" \
      --build-arg "VCS_REF=$(git -C "${scout_root}" describe --always --dirty)" \
      -t scoutsuite-fork-base:local "${scout_root}" ;;
  aws|azure|gcp)
    "$0" base
    docker build -f "${scout_docker_dir}/Dockerfile-${scout_target}" \
      --build-arg SCOUT_BASE_IMAGE=scoutsuite-fork-base:local \
      -t "scoutsuite-fork-${scout_target}:local" "${scout_root}" ;;
  all)
    "$0" base
    "$0" aws
    "$0" azure
    "$0" gcp ;;
  *) printf '%s\n' 'Usage: build.sh [base|combined|aws|azure|gcp|all]' >&2; exit 1 ;;
esac

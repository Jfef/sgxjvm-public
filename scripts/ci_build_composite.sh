#!/usr/bin/env bash
set -xeuo pipefail

# This script expects the sgxjvm project to be checked out in the `sgxjvm` subdirectory.

SCRIPT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
export OBLIVIUM_VERSION=$(cd "$SCRIPT_DIR/../sgxjvm" && git describe --long --abbrev=10)
export OBLIVIUM_DEPENDENCY_VERSION=$(cd "$SCRIPT_DIR/../sgxjvm" && git describe --abbrev=0)-+

source $SCRIPT_DIR/../sgxjvm/scripts/ci_build_common.sh

# Login and pull the current build image
docker login $OBLIVIUM_CONTAINER_REGISTRY_URL -u $OBLIVIUM_CONTAINER_REGISTRY_USERNAME -p $OBLIVIUM_CONTAINER_REGISTRY_PASSWORD
docker pull $OBLIVIUM_CONTAINER_REGISTRY_URL/com.r3.sgx/sgxjvm-build

mkdir -p /home/$(id -un)/.gradle
mkdir -p /home/$(id -un)/.ccache

export CODE_HOST_DIR=$PWD
export CONTAINER_NAME=$(echo "code${CODE_HOST_DIR}" | sed -e 's/[^a-zA-Z0-9_.-]/_/g')
export CODE_DOCKER_DIR="$CODE_HOST_DIR"

runDocker com.r3.sgx/sgxjvm-build "cd $CODE_DOCKER_DIR && ./gradlew $EXCLUDE_NATIVE build -i"

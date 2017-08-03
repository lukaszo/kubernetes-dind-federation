#!/bin/bash

# Copyright 2015 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds a docker image that contains the kubernetes binaries.

set -o errexit
set -o nounset
set -o pipefail

IMAGE_REPO=${IMAGE_REPO:-k8s.io/kubernetes-dind}
IMAGE_TAG=${IMAGE_TAG:-latest}

script_dir=$(cd $(dirname "${BASH_SOURCE}") && pwd -P)

# Find a platform specific binary, whether it was cross compiled or locally built (on Linux)
find-binary() {
  local lookfor="${1}"
  local platform="${2}"
  local locations=(
    "_output/dockerized/bin/${platform}/${lookfor}"
  )
  if [ "$(uname)" = Linux ]; then
    locations[${#locations[*]}]="_output/local/bin/${platform}/${lookfor}"
  fi
  local bin=$( (ls -t "${locations[@]}" 2>/dev/null || true) | head -1 )
  echo -n "${bin}"
}

hyperkube_path=$(find-binary hyperkube linux/amd64)
if [ -z "$hyperkube_path" ]; then
  echo "Failed to find hyperkube binary for linux/amd64" 1>&2
  exit 1
fi
kube_bin_path=$(dirname ${hyperkube_path})

# possibly build socat container
SOCAT_IMG=kubernetes-socat:v1
if ! docker images ${SOCAT_IMG} | grep -q ${SOCAT_IMG}; then
  docker build -t ${SOCAT_IMG} "${script_dir}/socat"
fi

# download nsenter and socat
overlay_dir=${DOCKER_IN_DOCKER_OVERLAY_DIR:-${script_dir}/overlay}
mkdir -p "${overlay_dir}"
! which selinuxenabled &>/dev/null || ! selinuxenabled 2>&1 || sudo chcon -Rt svirt_sandbox_file_t -l s0 "${overlay_dir}"
docker run --rm jpetazzo/nsenter cat /nsenter > ${overlay_dir}/nsenter && chmod +x ${overlay_dir}/nsenter
docker run --rm ${SOCAT_IMG} cat /src/socat*/socat > ${overlay_dir}/socat && chmod +x ${overlay_dir}/socat

# create temp workspace to place compiled binaries with image-specific scripts
# create temp workspace dir in KUBE_ROOT to avoid permission issues of TMPDIR on mac os x
workspace=$(env TMPDIR=$PWD mktemp -d -t "k8sm-workspace-XXXXXX")
echo "Workspace created: ${workspace}"

cleanup() {
  rm -rf "${workspace}"
  rm -f "${overlay_dir}/*"
  echo "Workspace deleted: ${workspace}"
}
trap 'cleanup' EXIT

# setup workspace to mirror script dir (dockerfile expects /bin & /opt)
echo "Copying files to workspace"

# binaries & scripts
mkdir -p "${workspace}/bin"
cp -a "${script_dir}/wrapdocker"* "${workspace}/bin/"
cp -a "${kube_bin_path}/hyperkube" "${workspace}/bin/"
cp -a "${overlay_dir}/nsenter" "${workspace}/bin"
cp -a "${overlay_dir}/socat" "${workspace}/bin"

# docker
cp "${script_dir}/Dockerfile" "${workspace}/"

cd "${workspace}"

# build docker image
echo "Building docker image ${IMAGE_REPO}:${IMAGE_TAG}"
set -o xtrace
docker build -t ${IMAGE_REPO}:${IMAGE_TAG} "$@" .
set +o xtrace
echo "Built docker image ${IMAGE_REPO}:${IMAGE_TAG}"

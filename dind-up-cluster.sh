#!/bin/bash

# Copyright 2016 The Kubernetes Authors
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

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

if [ $(uname) = Darwin ]; then
  readlinkf(){ perl -MCwd -e 'print Cwd::abs_path shift' "$1";}
else
  readlinkf(){ readlink -f "$1"; }
fi
DIND_ROOT="$(cd $(dirname "$(readlinkf "${BASH_SOURCE}")"); pwd)"

if [ ! -f cluster/kubectl.sh ]; then
  echo "$0 must be called from the Kubernetes repository root directory" 1>&2
  exit 1
fi

# Execute a docker-compose command with the default environment and compose file.
function dind::docker_compose {
  local params="$@"

  # All vars required to be set
  declare -a env_vars=(
    "DOCKER_IN_DOCKER_WORK_DIR"
    "APISERVER_SERVICE_IP"
    "SERVICE_CIDR"
    "DNS_SERVER_IP"
    "DNS_DOMAIN"
    "CLUSTER_NAME"
  )

  (
    for var_name in "${env_vars[@]}"; do
      export ${var_name}="${!var_name}"
    done

    export DOCKER_IN_DOCKER_STORAGE_DIR=${DOCKER_IN_DOCKER_STORAGE_DIR:-${DOCKER_IN_DOCKER_WORK_DIR}/storage}

    docker-compose -p ${CLUSTER_NAME} -f "${DIND_ROOT}/docker-compose.yml" ${params}
  )
}

# Pull the images from a docker compose file, if they're not already cached.
# This avoid slow remote calls from `docker-compose pull` which delegates
# to `docker pull` which always hits the remote docker repo, even if the image
# is already cached.
function dind::docker_compose_lazy_pull {
  for img in $(grep '^\s*image:\s' "${DIND_ROOT}/docker-compose.yml" | sed 's/[ \t]*image:[ \t]*//'); do
    read repo tag <<<$(echo "${img} "| sed 's/:/ /')
    if [[ "${repo}" = k8s.io/kubernetes-dind* ]]; then
      continue
    fi
    if [ -z "${tag}" ]; then
      tag="latest"
    fi
    if ! docker images "${repo}" | awk '{print $2;}' | grep -q "${tag}"; then
      docker pull "${img}"
    fi
  done
}

# Generate kubeconfig data for the created cluster.
function dind::create-kubeconfig {
  local -r auth_dir="${DOCKER_IN_DOCKER_WORK_DIR}/auth"
  local kubectl="cluster/kubectl.sh"

  local token="$(cut -d, -f1 ${auth_dir}/token-users)"
  "${kubectl}" config set-cluster "${CLUSTER_NAME}" --server="${KUBE_SERVER}" --certificate-authority="${auth_dir}/ca.pem"
  "${kubectl}" config set-context "${CLUSTER_NAME}" --cluster="${CLUSTER_NAME}" --user="${CLUSTER_NAME}-cluster-admin"
  "${kubectl}" config set-credentials ${CLUSTER_NAME}-cluster-admin --token="${token}"
  "${kubectl}" config use-context "${CLUSTER_NAME}" --cluster="${CLUSTER_NAME}"

   echo "Wrote config for ${CLUSTER_NAME} context" 1>&2
}

# get apiserver published port
function dind::get-apiserver-port {
  local base_port=$1
  local port_mapping=$(docker port ${CLUSTER_NAME}_apiserver_1 ${base_port})
  local port=${port_mapping#0.0.0.0:}
  echo ${port}
}

# Must ensure that the following ENV vars are set
function dind::detect-master {
  #KUBE_MASTER_IP="${APISERVER_ADDRESS}:6443"
  KUBE_MASTER_IP="${APISERVER_ADDRESS}:$(dind::get-apiserver-port 8888)"
  #KUBE_SERVER="https://${KUBE_MASTER_IP}"
  KUBE_SERVER="http://${KUBE_MASTER_IP}"

  echo "KUBE_MASTER_IP: $KUBE_MASTER_IP" 1>&2
}

# Get minion IP addresses and store in KUBE_NODE_IP_ADDRESSES[]
function dind::detect-nodes {
  local docker_ids=$(docker ps --filter="name=${CLUSTER_NAME}_node" --quiet)
  if [ -z "${docker_ids}" ]; then
    echo "ERROR: node(s) not running" 1>&2
    return 1
  fi
  while read -r docker_id; do
    local minion_ip=$(docker inspect --format="{{.NetworkSettings.IPAddress}}" "${docker_id}")
    KUBE_NODE_IP_ADDRESSES+=("${minion_ip}")
  done <<< "$docker_ids"
  echo "KUBE_NODE_IP_ADDRESSES: [${KUBE_NODE_IP_ADDRESSES[*]}]" 1>&2
}

# Verify prereqs on host machine
function dind::verify-prereqs {
  dind::step "Verifying required commands"
  hash docker 2>/dev/null || { echo "Missing required command: docker" 1>&2; exit 1; }
  hash docker 2>/dev/null || { echo "Missing required command: docker-compose" 1>&2; exit 1; }
  docker run busybox grep -q -w -e "overlay\|aufs" /proc/filesystems || {
    echo "Missing required kernel filesystem support: overlay or aufs."
    echo "Run 'sudo modprobe overlay' or 'sudo modprobe aufs' (on Ubuntu) and try again."
    exit 1
  }
}

# Initialize
function dind::init_auth {
  local -r auth_dir="${DOCKER_IN_DOCKER_WORK_DIR}/auth"

  dind::step "Creating auth directory:" "${auth_dir}"
  mkdir -p "${auth_dir}"
  ! which selinuxenabled &>/dev/null || ! selinuxenabled 2>&1 || sudo chcon -Rt svirt_sandbox_file_t -l s0 "${auth_dir}"
  rm -rf "${auth_dir}"/*

  dind::step "Creating service accounts key:" "${auth_dir}/service-accounts-key.pem"
  openssl genrsa -out "${auth_dir}/service-accounts-key.pem" 2048 &>/dev/null

  local -r BASIC_PASSWORD="$(openssl rand -hex 16)"
  local -r KUBELET_TOKEN="$(openssl rand -hex 32)"
  echo "${BASIC_PASSWORD},admin,admin" > ${auth_dir}/basic-users
  echo "${KUBELET_TOKEN},kubelet,kubelet" > ${auth_dir}/token-users
  dind::step "Creating credentials:" "admin:${BASIC_PASSWORD}, kubelet token"

  dind::step "Create TLS certs & keys:"
  docker run --rm -i  --entrypoint /bin/bash -v "${auth_dir}:/certs" -w /certs cfssl/cfssl:latest -ec "$(cat <<EOF
    cd /certs
    echo '{"CN":"CA","key":{"algo":"rsa","size":2048}}' | cfssl gencert -initca - | cfssljson -bare ca -
    echo '{"signing":{"default":{"expiry":"43800h","usages":["signing","key encipherment","server auth","client auth"]}}}' > ca-config.json
    echo '{"CN":"'apiserver'","hosts":[""],"key":{"algo":"rsa","size":2048},"names":[{"CN":"kube-admin", "O":"system:masters"}]}' | \
      cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -hostname=apiserver,kubernetes,kubernetes.default.svc.${DNS_DOMAIN},${APISERVER_SERVICE_IP},${APISERVER_ADDRESS},${CLUSTER_NAME} - | \
      cfssljson -bare apiserver
EOF
  )"
  cat "${auth_dir}/apiserver.pem" "${auth_dir}/ca.pem" > "${auth_dir}/apiserver-bundle.pem"
}

# Create default docker network for the cluster
function dind::create_default_network {
  docker network create --driver=bridge --subnet=${IP_RANGE} ${CLUSTER_NAME}_default
}

# Delete default docker network for the cluster
function dind::delete_default_network {
  docker network rm ${CLUSTER_NAME}_default
}

# Instantiate a kubernetes cluster.
function dind::kube-up {
  dind::ensure-hyperkube

  # Pull before `docker-compose up` to avoid timeouts caused by slow pulls during deployment.
  dind::step "Pulling docker images"
  dind::docker_compose_lazy_pull

  if [ "${DOCKER_IN_DOCKER_SKIP_BUILD}" != "true" ]; then
    dind::step "Building docker images"
    "${DIND_ROOT}/image/build.sh"
  fi

  dind::init_auth

  dind::step "Creating network for the cluster: ${CLUSTER_NAME}_default"
  dind::create_default_network

  dind::step "Starting dind cluster"
  dind::docker_compose up -d --force-recreate --scale node=${NUM_NODES}

  local apiserver_port=$(dind::get-apiserver-port 6443)
  dind::step -n "Waiting for https://${APISERVER_ADDRESS}:${apiserver_port} to be healthy"
  while ! curl -o /dev/null -s --cacert ${DOCKER_IN_DOCKER_WORK_DIR}/auth/ca.pem https://${APISERVER_ADDRESS}:${apiserver_port}; do
    sleep 1
    echo -n "."
  done
  echo

  dind::detect-master
  dind::detect-nodes
  dind::create-kubeconfig

  if [ "${ENABLE_CLUSTER_DNS}" == "true" ]; then
    dind::deploy-dns
  fi
  if [ "${ENABLE_CLUSTER_UI}" == "true" ]; then
    dind::deploy-ui
  fi

  # Wait for addons to deploy
  dind::await_ready "k8s-app=kube-dns" "${DOCKER_IN_DOCKER_ADDON_TIMEOUT}"
  dind::await_ready "k8s-app=kubernetes-dashboard" "${DOCKER_IN_DOCKER_ADDON_TIMEOUT}"

  if [ "${ENABLE_FEDERATION}" == "true" ]; then
    dind::deploy_federation
  fi
}

function dind::deploy-dns {
  dind::step "Deploying kube-dns"
  "cluster/kubectl.sh" --namespace kube-system create -f "${DIND_ROOT}/k8s/kubedns-cm.yml"
  "cluster/kubectl.sh" --namespace kube-system create -f "cluster/addons/dns/kubedns-sa.yaml"
  "cluster/kubectl.sh" create -f <(
    for f in kubedns-controller.yaml kubedns-svc.yaml; do
      echo "---"
      eval "cat <<EOF
$(<"cluster/addons/dns/${f}.sed")
EOF
" 2>/dev/null
    done
  )
}

function dind::deploy-ui {
  dind::step "Deploying dashboard"
  "cluster/kubectl.sh" create -f "cluster/addons/dashboard/dashboard-controller.yaml"
  "cluster/kubectl.sh" create -f "cluster/addons/dashboard/dashboard-service.yaml"
}

function dind::deploy-federation {
  dind::ensure-hyperkube

  "cluster/kubectl.sh" create namespace "${FEDERATION_NAMESPACE}"

  # install etcd
  "cluster/kubectl.sh" create -n ${FEDERATION_NAMESPACE} -f "${DIND_ROOT}/k8s/etcd.yml"
  dind::await_ready "k8s-app=coredns-etcd" "600" ${FEDERATION_NAMESPACE}

  # install coredns
  "cluster/kubectl.sh" create -n ${FEDERATION_NAMESPACE} -f "${DIND_ROOT}/k8s/coredns.yml"
  dind::await_ready "k8s-app=coredns" "600" ${FEDERATION_NAMESPACE}

  # install private docker registry
  "cluster/kubectl.sh" create -n ${FEDERATION_NAMESPACE} -f "${DIND_ROOT}/k8s/registry.yml"
  dind::await_ready "k8s-app=kube-registry" "${DOCKER_IN_DOCKER_ADDON_TIMEOUT}" "${FEDERATION_NAMESPACE}"
  "cluster/kubectl.sh" create -n ${FEDERATION_NAMESPACE} -f "${DIND_ROOT}/k8s/registry-svc.yml"
  "cluster/kubectl.sh" create -n ${FEDERATION_NAMESPACE} -f <(eval "cat <<EOF
$(<"${DIND_ROOT}/k8s/registry-ds.yml")
EOF
" 2>/dev/null)
  dind::await_ready "k8s-app=registry-proxy" "${DOCKER_IN_DOCKER_ADDON_TIMEOUT}" "${FEDERATION_NAMESPACE}"
  
  # local proxy to push images
  POD=$("cluster/kubectl.sh" get pods --namespace ${FEDERATION_NAMESPACE} -l k8s-app=kube-registry \
	  -o template --template '{{range .items}}{{.metadata.name}} {{.status.phase}}{{"\n"}}{{end}}' \
	  | grep Running | head -1 | cut -f1 -d' ')
  "cluster/kubectl.sh" port-forward --namespace ${FEDERATION_NAMESPACE} $POD ${REGISTRY_LOCAL_PORT}:5000 &

  # push hyperkube image
  tag=`< /dev/urandom tr -dc A-Za-z0-9 | head -c${1:-8};echo`
  pushd "cluster/images/hyperkube/"
  REGISTRY=127.0.0.1:${REGISTRY_LOCAL_PORT} make build VERSION=${tag} ARCH=amd64
  docker push 127.0.0.1:${REGISTRY_LOCAL_PORT}/hyperkube-amd64:${tag}
  # clean local image
  docker rmi 127.0.0.1:${REGISTRY_LOCAL_PORT}/hyperkube-amd64:${tag}
  popd

  # run kubefed
  tmpfile=$(mktemp /tmp/coredns-provider.conf.XXXXXX)
  cat >${tmpfile} << EOF
    [Global]
    etcd-endpoints = http://coredns-etcd.${FEDERATION_NAMESPACE}:2379
    zones = ${DNS_ZONE}.
EOF

  kubefed init federation --host-cluster-context=${CLUSTER_NAME} --kubeconfig=${KUBECONFIG} --federation-system-namespace=${FEDERATION_NAMESPACE}-system --api-server-service-type=NodePort --etcd-persistent-storage=false --dns-provider=coredns --dns-provider-config=${tmpfile} --dns-zone-name=${DNS_ZONE} --image=127.0.0.1:5000/hyperkube-amd64:${tag} --apiserver-enable-basic-auth=true --apiserver-enable-token-auth=true
  kubefed join "${CLUSTER_NAME}" --host-cluster-context=${CLUSTER_NAME} --context=federation
}

function dind::remove-federation {
  "cluster/kubectl.sh" delete namespace ${FEDERATION_NAMESPACE} || true
  "cluster/kubectl.sh" delete namespace ${FEDERATION_NAMESPACE}-system || true
  "cluster/kubectl.sh" delete clusterrole "federation-controller-manager:federation-${CLUSTER_NAME}-${CLUSTER_NAME}" || true
  "cluster/kubectl.sh" delete clusterrolebindings "federation-controller-manager:federation-${CLUSTER_NAME}-${CLUSTER_NAME}" || true
  pkill -f "kubectl.*${REGISTRY_LOCAL_PORT}"
}

function dind::validate-cluster {
  dind::step "Validating dind cluster"

  # Do not validate cluster size. There will be zero k8s minions until a pod is created.
  # TODO(karlkfi): use componentstatuses or equivalent when it supports non-localhost core components

  # Validate immediate cluster reachability and responsiveness
  echo "KubeDNS: $(dind::addon_status 'kube-dns')"
  echo "Kubernetes Dashboard: $(dind::addon_status 'kubernetes-dashboard')"
}

# Delete a kubernetes cluster
function dind::kube-down {
  dind::step "Stopping dind cluster"
  # Since restoring a stopped cluster is not yet supported, use the nuclear option
  dind::docker_compose kill
  dind::docker_compose rm -f
  dind::step "Removing cluster network ${CLUSTER_NAME}_default"
  dind::delete_default_network
}

# Waits for a kube-system pod (of the provided name) to have the phase/status "Running".
function dind::await_ready {
  local pod_name="$1"
  local max_attempts="$2"
  local namespace=${3:-kube-system}
  local phase="Unknown"
  echo -n "${pod_name}: "
  local n=0
  until [ ${n} -ge ${max_attempts} ]; do
    ready=$(dind::is_pod_ready "${pod_name}" "${namespace}")
    if [ "${ready}" == "True" ]; then
      break
    fi
    echo -n "."
    n=$[$n+1]
    sleep 1
  done
  echo "${ready}"
  return $([ "${ready}" == "True" ]; echo $?)
}

function dind::await_tpr {
  local tpr="$1"
  local max_attempts="$2"
  local ready="False"
  echo -n "${tpr}: "
  local n=0
  until [ ${n} -ge ${max_attempts} ]; do
    if [ "$(cluster/kubectl.sh get thirdpartyresources 2>/dev/null|grep ${tpr})" ]; then
      ready="True"
      break
    fi
    echo -n "."
    n=$[$n+1]
    sleep 1
  done
  return $([ "${ready}" == "True" ]; echo $?)
}

# Prints the status of the kube-system pod specified
function dind::is_pod_ready {
  local label="$1"
  local namespace="$2"
  local kubectl="cluster/kubectl.sh"
  local phase=$("${kubectl}" get pods --namespace=${namespace} -l ${label} -o jsonpath --template="{.items[0]['status']['conditions'][?(@.type==\"Ready\")].status}" 2>/dev/null)
  phase="${phase:-Unknown}"
  echo "${phase}"
}

function dind::step {
  local OPTS=""
  if [ "$1" = "-n" ]; then
    shift
    OPTS+="-n"
  fi
  GREEN="${1}"
  shift
  if [ -t 1 ] ; then
    echo -e ${OPTS} "\x1B[97m* \x1B[92m${GREEN}\x1B[39m $*" 1>&2
  else
    echo ${OPTS} "* ${GREEN} $*" 1>&2
  fi
}

function dind::ensure-hyperkube {
  if [ ! -f _output/dockerized/bin/linux/amd64/hyperkube ] && [ ! -f _output/bin/hyperkube ]; then
    echo "No hyperkube file in _output. Please build it first" 1>&2
    exit 1
  fi

  mkdir -p _output/dockerized/bin/linux/amd64
  cp -u _output/bin/hyperkube _output/dockerized/bin/linux/amd64/hyperkube || true
}

if [ $(basename "$0") = dind-up-cluster.sh ]; then
    source "${DIND_ROOT}/config.sh"
    dind::kube-up
    echo
    "cluster/kubectl.sh" cluster-info
    if [ "${1:-}" = "-w" ]; then
      trap "echo; dind::kube-down" INT
      echo
      echo "Press Ctrl-C to shutdown cluster"
      while true; do sleep 1; done
    fi
elif [ $(basename "$0") = dind-down-cluster.sh ]; then
  source "${DIND_ROOT}/config.sh"
  dind::kube-down
elif [ $(basename "$0") = dind-deploy-federation.sh ]; then
  source "${DIND_ROOT}/config.sh"
  dind::deploy-federation
elif [ $(basename "$0") = dind-remove-federation.sh ]; then
  source "${DIND_ROOT}/config.sh"
  dind::remove-federation
fi

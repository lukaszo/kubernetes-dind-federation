# kubernetes-dind-federation
A Federated Kubernetes multi-node cluster for developer _of_ Kubernetes

- works with [kubernetes master branch](https://github.com/kubernetes/kubernetes)
- requires docker(1.12) and docker-compose(1.13.0)
- with kube-dns and dashboard

```shell
$ cd kubernetes
$ git clone git@github.com:lukaszo/kubernetes-dind-federation dind

$ make WHAT=cmd/hyperkube
$ make WHAT=cmd/kubectl

$ dind/dind-up-cluster.sh
$ kubectl get nodes
NAME         STATUS    AGE
172.17.0.4   Ready     23s
172.17.0.7   Ready     21s

$ make WHAT=federation/cmd/kubefed
$ dind/dind-deploy-federation.sh
$ kubectl get cluster --context=federation
NAME      STATUS    AGE
dind      Ready     2m

$ dind/dind-remove-federation.sh

$ dind/dind-down-cluster.sh
```

## Running e2e tests

Name of clusters used in e2e tests has to be prefixed with `federation`. Two clusters are required.

```shell
# deploy two k8s clusters
$ CLUSTER_NAME=federation1 dind/dind-up-cluster.sh
$ CLUSTER_NAME=federation2 IP_RANGE=172.128.0.0/16 APISERVER_ADDRESS=172.128.0.1 dind/dind-up-cluster.sh

# switch back to federation1 context
$ kubectl config use-context federation1

# deploy federation control plane
$ CLUSTER_NAME=federation1 dind/dind-deploy-federation.sh

# add second cluster to the federation
kubefed join federation2 --host-cluster-context=federation1 --context=federation

# make e2e.test binary
$ make WHAT=test/e2e/e2e.test

# run federated e2e tests
FEDERATION_NAME=federation e2e.test --provider=dind --kubeconfig ~/.kube/config -ginkgo.v=true --ginkgo.focus="Feature:Federation" --federated-kube-context=federation
```




The work is based on https://github.com/sttts/kubernetes-dind-cluster

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

The work is based on https://github.com/sttts/kubernetes-dind-cluster

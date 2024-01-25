# Mitigating K8s OWASP T10 risks with a cloud-native response engine
The lab should be reproducable for all EKS users. <br/>
The cluster runs ```cilium cni``` for network traffic control in EKS <br/>
Falco Talom is created in the same ```falco``` netwok namespace as OSS Falco.

Set up an ```AWS-CLI Profile``` in order to interact with AWS services via my local workstation
```
aws configure --profile nigel-aws-profile
export AWS_PROFILE=nigel-aws-profile                                            
aws sts get-caller-identity --profile nigel-aws-profile
aws eks update-kubeconfig --region eu-west-1 --name falco-cluster
```

## Create EKS Cluster with Cilium CNI

```
eksctl create cluster --name falco-cluster --without-nodegroup
```

Once ```aws-node``` DaemonSet is deleted, EKS will not try to restore it.
```
kubectl -n kube-system delete daemonset aws-node
```

Setup Helm repository:
```
helm repo add cilium https://helm.cilium.io/
```

Deploy Cilium release via Helm:
```
helm install cilium cilium/cilium --version 1.9.18 \
  --namespace kube-system \
  --set eni=true \
  --set ipam.mode=eni \
  --set egressMasqueradeInterfaces=eth0 \
  --set tunnel=disabled \
  --set nodeinit.enabled=true
```

Create a node group since there are no worker nodes for our pods
```
eksctl create nodegroup --cluster falco-cluster --node-type t3.xlarge --nodes 1 --nodes-min=0 --nodes-max=3 --max-pods-per-node 58
```

```
mkdir falco-response
```

```
cd falco-response
```

Download the ```custom-rules.yaml``` file - this enables the by default disabled ```Detect outbound connections to common miner pool ports``` Falco Rule. <br/>
However, I see to be breaking the deployment with the below ```custom-rules.yaml``` file, so I'm leaving it out for now.
```
wget https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/falco-talon/custom-rules.yaml
```

## Install Falco and FalcoSideKick

```
helm install falco falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false \
  --set falcosidekick.config.webhook.address=http://falco-talon:2803 \
  --set "falcoctl.config.artifact.install.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falcoctl.config.artifact.follow.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falco.rules_file={/etc/falco/falco_rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml,/etc/falco/rules.d}" \
  -f custom-rules.yaml
```

<img width="1075" alt="Screenshot 2024-01-16 at 11 37 38" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/148ebf95-65c9-4e63-a4ea-b5145017ff5e">



## Install Falco Talon

```
git clone https://github.com/Issif/falco-talon.git
```

The Talon rules file ```rules.yaml``` is located in the ```helm``` directory:
```
cd falco-talon/deployment/helm/
```

Before installing, let's enforce the custom response actions for OWASP T10 framework.

```
rm rules.yaml
```

```
wget https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/falco-talon/rules.yaml
```

Deploy Talon into the newly created ```falco``` network namespace:
```
helm install falco-talon . -n falco
```


## K01: Insecure Workload Configurations
The security context of a workload in Kubernetes is highly configurable which can lead to serious security misconfigurations propagating across an organization’s workloads and clusters. The Kubernetes adoption, security, and market trends report 2022 from Redhat stated that nearly 53% of respondents have experienced a misconfiguration incident in their Kubernetes environments in the last 12 months.



### K01.01: Application processes should not run as root

Running the process inside of a container as the ```root``` user is a common misconfiguration in many clusters. While ```root``` may be an absolute requirement for some workloads, it should be avoided when possible. If the container were to be compromised, the attacker would have root-level privileges that allow actions such as starting a malicious process that otherwise wouldn’t be permitted with other users on the system. In this example, I created a [pod deployment manifest](https://github.com/nigel-falco/falco-talon-testing/blob/main/RunAsRoot.yaml) with securityContext set to ```runAsUser: 0```. There is a Falco rule that detects when a [container is run as root](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml#L1598,L1612). The rule is disabled by default, so I enabled it in the [custom_rules.yaml](https://github.com/nigel-falco/falco-talon-testing/blob/main/falco-talon/custom-rules.yaml#L47-L49) file. Once the Falco rule enabled, I configured a Falco Talon response action to [gracefully terminate the workload](https://github.com/nigel-falco/falco-talon-testing/blob/main/falco-talon/rules.yaml#L38-L43) if it was launched as a root user - which enforces the OWASP T10 control.

```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/RunAsRoot.yaml
```
```
kubectl get events -n default -w
```

<img width="866" alt="Screenshot 2024-01-25 at 19 59 15" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/7ea928c2-fd23-4f7a-a0d9-e75b66edbb2f">

<img width="1366" alt="Screenshot 2024-01-25 at 19 59 44" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/ffb465aa-4a0e-49f2-b761-fd65feb56281">

### K01.03: Privileged containers should be disallowed

When setting a container to ```privileged``` within Kubernetes, the container can access additional resources and kernel capabilities of the host. Workloads running as root combined with privileged containers can be devastating as the user can get complete access to the host. This is, however, limited when running as a non-root user. Privileged containers are dangerous as they remove many of the built-in container isolation mechanisms entirely.

```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
```
kubectl get events -n default -w
```



## K02: Supply Chain Vulnerabilities
## K03: Overly Permissive RBAC Configurations
## K04: Lack of Centralized Policy Enforcement
## K05: Inadequate Logging and Monitoring
## K06: Broken Authentication Mechanisms
## K07: Missing Network Segmentation Controls
## K08: Secrets Management Failures
## K09: Misconfigured Cluster Components
## K10: Outdated and Vulnerable Kubernetes Components








<br/><br/><br/><br/><br/>


## Check for killed process in realtime
Run this command command in the second window:
```
kubectl get events -n default
```

## Kill stratum protocol in realtime

Create a dodgy, overprivleged workload:
```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
```
kubectl exec -it dodgy-pod -- bash
```
Download the miner from Github
```
curl -OL https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz
```
Unzip xmrig package:
```
tar -xvf xmrig-6.16.4-linux-static-x64.tar.gz
```
```
cd xmrig-6.16.4
```
```
./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u lies@lies.lies -p x -t 2
```

![Screenshot 2024-01-25 at 16 29 09](https://github.com/nigel-falco/falco-talon-testing/assets/152274017/ce72b48a-bbef-417d-a26b-33740ff3d3c4)


## Testing the Script response action

Copy file from a container and trigger a ```Kubernetes Client Tool Launched in Container``` detection in Falco: <br/>
https://thomas.labarussias.fr/falco-rules-explorer/?status=enabled&source=syscalls&maturity=all&hash=bc5091ab0698e22b68d788e490e8eb66

```
kubectl cp dodgy-pod:xmrig-6.16.4-linux-static-x64.tar.gz ~/desktop/xmrig-6.16.4-linux-static-x64.tar.gz
```


## Enforce Network Policy on Suspicious Traffic

```
kubectl exec -it dodgy-pod -- bash
```

Installing a suspicious networking tool like telnet
```
curl 52.21.188.179
```

Check to confirm the IP address was blocked:
```
kubectl get networkpolicy dodgy-pod -o yaml
```

```
kubectl delete networkpolicy dodgy-pod
```

<br/><br/>

## Miscellaneous commands:
Expose the Falcosidekick UI
```
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802 --insecure-skip-tls-verify
```

Talon can be removed at any time via:
```
helm uninstall falco-talon -n falco
```

Scale down the cluster
```
eksctl get nodegroups --cluster falco-cluster
```
```
eksctl scale nodegroup --cluster falco-cluster --name ng-03dfe2da --nodes 0
```

Kubecolor
```
alias kubectl="kubecolor"
```

# Detecting & Responding to threats in EKS in realtime via Falco Talon
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

<img width="919" alt="Screenshot 2023-12-13 at 20 22 38" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/e3e82de6-8da6-4d14-a83c-a1efed4ea685">


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

<img width="919" alt="Screenshot 2023-12-13 at 20 44 34" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/0d725bae-e9f0-4710-8844-37ea5c86f4f6">


Create a node group since there are no worker nodes for our pods
```
eksctl create nodegroup --cluster falco-cluster --node-type t3.xlarge --nodes 1 --nodes-min=0 --nodes-max=3 --max-pods-per-node 58
```

<img width="1199" alt="Screenshot 2023-12-13 at 20 45 45" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/e0e9f120-3777-4ec1-a8e3-21be46abeb8e">


<img width="1199" alt="Screenshot 2023-12-13 at 20 51 27" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/c421c606-3570-4d66-ab90-2d2f218c165b">

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
  --set "falco.rules_file={/etc/falco/rules.d,/etc/falco/falco-rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml}"
```

<img width="1199" alt="Screenshot 2023-12-13 at 20 54 12" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/245f4b4d-f1e3-422f-827c-24679c86c1ee">


## Install Falco Talon

```
git clone https://github.com/Issif/falco-talon.git
```

The Talon rules file ```rules.yaml``` is located in the ```helm``` directory:
```
cd deployment/helm/
```

Deploy Talon into the newly created ```falco``` network namespace:
```
helm install falco-talon . -n falco
```

```
kubectl get pods -n falco
```

<img width="1199" alt="Screenshot 2023-12-13 at 20 58 02" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/b26f6857-ad33-4fe4-8b7a-d904ccd2c2c1">

Now that Talon is installed successfully, let's play around with the rule logic.

## Building custom rules for Falco Talon

```
rm rules.yaml
```

```
wget https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/falco-talon/rules.yaml
```

```
cat rules.yaml
```

## Check for killed process in realtime
Run this command command in the second window:
```
kubectl get events -n default
```

## Kill stratum protocol in realtime



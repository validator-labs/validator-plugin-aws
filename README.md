[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/spectrocloud-labs/validator-plugin-aws/issues)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Build](https://github.com/spectrocloud-labs/validator-plugin-aws/actions/workflows/build_container.yaml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/spectrocloud-labs/validator-plugin-aws)](https://goreportcard.com/report/github.com/spectrocloud-labs/validator-plugin-aws)
[![codecov](https://codecov.io/gh/spectrocloud-labs/validator-plugin-aws/graph/badge.svg?token=QHR08U8SEQ)](https://codecov.io/gh/spectrocloud-labs/validator-plugin-aws)
[![Go Reference](https://pkg.go.dev/badge/github.com/spectrocloud-labs/validator-plugin-aws.svg)](https://pkg.go.dev/github.com/spectrocloud-labs/validator-plugin-aws)

# validator-plugin-aws
The AWS [validator](https://github.com/spectrocloud-labs/validator) plugin ensures that your AWS environment matches a user-configurable expected state.

## Description
The AWS validator plugin reconciles `AwsValidator` custom resources to perform the following validations against your AWS environment:

1. Compare the IAM permissions associated with an IAM user / group / role / policy against an expected permission set
2. Compare the usage for a particular service quota against the active quota
3. Compare the tags associated with a subnet against an expected tag set

Each `AwsValidator` CR is (re)-processed every two minutes to continuously ensure that your AWS environment matches the expected state.

See the [samples](https://github.com/spectrocloud-labs/validator-plugin-aws/tree/main/config/samples) directory for example `AwsValidator` configurations.

## Authn & Authz
Authentication details for the AWS validator controller are provided within each `AwsValidator` custom resource. AWS authentication can be configured either implicitly or explicitly. All supported options are detailed below:
* Implicit (`AwsValidator.auth.implicit == true`)
  * [IAM roles for Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
  * [IAM roles for Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html)
  * [IAM roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) (OIDC)
    * In this scenario, a valid Service Account must be specified during plugin installation. See [values.yaml](https://github.com/spectrocloud-labs/validator-plugin-aws/blob/main/chart/validator-plugin-aws/values.yaml) for details.
* Explicit (`AwsValidator.auth.implicit == false && AwsValidator.auth.secretName != ""`)
  * [Environment variables](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#environment-variables)
  * Environment variables + [role assumption via AWS STS](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/stscreds#AssumeRoleOptions)

> [!NOTE]
> See [values.yaml](https://github.com/spectrocloud-labs/validator-plugin-aws/tree/main/chart/validator-plugin-aws/values.yaml) for additional configuration details for each authentication option.

### Minimal AWS managed IAM permission policies by validation type
For validation to succeed, certain AWS managed permission policies must be attached to the principal used and/or assumed by the AWS validator controller. The minimal required IAM policies, broken out by validation category, are as follows:
* IAM
  * `IAMReadOnlyAccess`
* Service Quotas
  * `AmazonEC2ReadOnlyAccess`
  * `AmazonElasticFileSystemReadOnlyAccess`
  * `ElasticLoadBalancingReadOnly`
  * `ServiceQuotasReadOnlyAccess`
* Tags
  * `AmazonVPCReadOnlyAccess`

> [!NOTE]
> Validation *can* be successful with custom IAM policies that are even more restrictive than the AWS managed policies listed above, but these will vary on a case-by-case basis and hence are undocumented for the sake of maintainability.

## Supported Service Quotas by AWS Service
EC2:
- EC2-VPC Elastic IPs
- Public AMIs

EFS:
- File systems per account

ELB:
- Application Load Balancers per Region
- Classic Load Balancers per Region
- Network Load Balancers per Region

VPC:
- Internet gateways per Region
- Network interfaces per Region
- VPCs per Region
- NAT gateways per Availability Zone
- Subnets per VPC

## Installation
The AWS validator plugin is meant to be [installed by validator](https://github.com/spectrocloud-labs/validator/tree/gh_pages#installation) (via a ValidatorConfig), but it can also be installed directly as follows:

```bash
helm repo add validator-plugin-aws https://spectrocloud-labs.github.io/validator-plugin-aws
helm repo update
helm install validator-plugin-aws validator-plugin-aws/validator-plugin-aws -n validator-plugin-aws --create-namespace
```

## Development
You’ll need a Kubernetes cluster to run against. You can use [kind](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.
**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

### Running on the cluster
1. Install Instances of Custom Resources:

```sh
kubectl apply -f config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/validator-plugin-aws:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/validator-plugin-aws:tag
```

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller from the cluster:

```sh
make undeploy
```

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/),
which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

### Test It Out
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## Contributing
All contributions are welcome! Feel free to reach out on the [Spectro Cloud community Slack](https://spectrocloudcommunity.slack.com/join/shared_invite/zt-g8gfzrhf-cKavsGD_myOh30K24pImLA#/shared-invite/email).

Make sure `pre-commit` is [installed](https://pre-commit.com#install).

Install the `pre-commit` scripts:

```console
pre-commit install --hook-type commit-msg
pre-commit install --hook-type pre-commit
```

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


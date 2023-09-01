package servicequota

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/test"
	v8or "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or/pkg/types"
	"github.com/spectrocloud-labs/valid8or/pkg/util/ptr"
)

type ec2ApiMock struct {
	addresses         *ec2.DescribeAddressesOutput
	images            *ec2.DescribeImagesOutput
	internetGateways  *ec2.DescribeInternetGatewaysOutput
	natGateways       *ec2.DescribeNatGatewaysOutput
	networkInterfaces *ec2.DescribeNetworkInterfacesOutput
	subnets           *ec2.DescribeSubnetsOutput
	vpcs              *ec2.DescribeVpcsOutput
}

func (m ec2ApiMock) DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return m.addresses, nil
}

func (m ec2ApiMock) DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return m.images, nil
}

func (m ec2ApiMock) DescribeInternetGateways(ctx context.Context, params *ec2.DescribeInternetGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	return m.internetGateways, nil
}

func (m ec2ApiMock) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return m.networkInterfaces, nil
}

func (m ec2ApiMock) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return m.subnets, nil
}

func (m ec2ApiMock) DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return m.vpcs, nil
}

func (m ec2ApiMock) DescribeNatGateways(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return m.natGateways, nil
}

type efsApiMock struct {
	filesystems *efs.DescribeFileSystemsOutput
}

func (m efsApiMock) DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	return m.filesystems, nil
}

type elbApiMock struct {
	loadBalancers *elasticloadbalancing.DescribeLoadBalancersOutput
}

func (m elbApiMock) DescribeLoadBalancers(context.Context, *elasticloadbalancing.DescribeLoadBalancersInput, ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancersOutput, error) {
	return m.loadBalancers, nil
}

type elbv2ApiMock struct {
	loadBalancers *elasticloadbalancingv2.DescribeLoadBalancersOutput
}

func (m elbv2ApiMock) DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return m.loadBalancers, nil
}

type sqApiMock struct {
	serviceQuotas *servicequotas.ListServiceQuotasOutput
}

func (m sqApiMock) ListServiceQuotas(context.Context, *servicequotas.ListServiceQuotasInput, ...func(*servicequotas.Options)) (*servicequotas.ListServiceQuotasOutput, error) {
	return m.serviceQuotas, nil
}

var svcQuotaService = NewServiceQuotaRuleService(
	logr.Logger{},
	ec2ApiMock{},
	efsApiMock{},
	elbApiMock{},
	elbv2ApiMock{},
	sqApiMock{},
)

type testCase struct {
	name           string
	rule           v1alpha1.ServiceQuotaRule
	expectedResult types.ValidationResult
	expectedError  error
}

func TestTagValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing tag)",
			rule: v1alpha1.ServiceQuotaRule{
				Region:      "us-west-1",
				ServiceCode: "",
				ServiceQuotas: []v1alpha1.ServiceQuota{
					{
						Name:   "EC2-VPC Elastic IPs",
						Buffer: 3,
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &v8or.ValidationCondition{
					ValidationType: "aws-tag",
					ValidationRule: "validation-subnet-kubernetes.io/role/elb",
					Message:        "One or more required subnet tags was not found",
					Details:        []string{},
					Failures:       []string{"Subnet with ARN subnetArn1 missing tag kubernetes.io/role/elb=1"},
					Status:         corev1.ConditionFalse,
				},
				State: ptr.Ptr(v8or.ValidationFailed),
			},
		},
	}
	for _, c := range cs {
		result, err := svcQuotaService.ReconcileServiceQuotaRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}

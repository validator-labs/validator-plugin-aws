package tag

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

type tagApiMock struct {
	subnetsByTagValue map[string]*ec2.DescribeSubnetsOutput
}

func (m tagApiMock) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	key := fmt.Sprintf("%s=%s", *params.Filters[0].Name, params.Filters[0].Values[0])
	return m.subnetsByTagValue[key], nil
}

var tagService = NewTagRuleService(logr.Logger{}, tagApiMock{
	subnetsByTagValue: map[string]*ec2.DescribeSubnetsOutput{
		"tag:kubernetes.io/role/elb=1": {
			Subnets: []ec2types.Subnet{
				{
					SubnetArn: util.Ptr("subnetArn2"),
				},
			},
		},
	},
})

type testCase struct {
	name           string
	rule           v1alpha1.TagRule
	expectedResult types.ValidationRuleResult
	expectedError  error
}

func TestTagValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing tag)",
			rule: v1alpha1.TagRule{
				Name:          "ELBSubnetTag",
				Key:           "kubernetes.io/role/elb",
				ExpectedValue: "1",
				Region:        "us-west-1",
				ResourceType:  "subnet",
				ARNs:          []string{"subnetArn1"},
			},
			expectedResult: types.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-tag",
					ValidationRule: "validation-elbsubnettag",
					Message:        "One or more required subnet tags was not found",
					Details:        []string{},
					Failures:       []string{"Subnet with ARN subnetArn1 missing tag kubernetes.io/role/elb=1"},
					Status:         corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass",
			rule: v1alpha1.TagRule{
				Name:          "ELBSubnetTag",
				Key:           "kubernetes.io/role/elb",
				ExpectedValue: "1",
				Region:        "us-west-1",
				ResourceType:  "subnet",
				ARNs:          []string{"subnetArn2"},
			},
			expectedResult: types.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-tag",
					ValidationRule: "validation-elbsubnettag",
					Message:        "All required subnet tags were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := tagService.ReconcileTagRule(c.rule)
		util.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}

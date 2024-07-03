package ami

import (
	"context"
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

type amiApiMock struct {
	images map[string]ec2types.Image
}

func (m amiApiMock) DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	images := make([]ec2types.Image, 0)
	for _, id := range params.ImageIds {
		if image, ok := m.images[id]; ok {
			images = append(images, image)
		}
	}
	return &ec2.DescribeImagesOutput{Images: images}, nil
}

var amiService = NewAmiRuleService(logr.Logger{}, amiApiMock{
	images: map[string]ec2types.Image{
		"ami-12345678": {
			ImageId: util.Ptr("ami-12345678"),
		},
	},
})

type testCase struct {
	name           string
	rule           v1alpha1.AmiRule
	expectedResult types.ValidationRuleResult
	expectedError  error
}

func TestAmiValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing image)",
			rule: v1alpha1.AmiRule{
				Name:   "AMI Rule Fail",
				AmiIds: []string{"ami-87654321"},
				Region: "us-west-1",
			},
			expectedResult: types.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-ami",
					ValidationRule: "validation-ami-rule-fail",
					Message:        "One or more required AMIs was not found",
					Details:        []string{},
					Failures:       []string{"AMI with ID ami-87654321 not found in region us-west-1"},
					Status:         corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass",
			rule: v1alpha1.AmiRule{
				Name:   "AMI Rule Pass",
				AmiIds: []string{"ami-12345678"},
				Region: "us-west-1",
			},
			expectedResult: types.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-ami",
					ValidationRule: "validation-ami-rule-pass",
					Message:        "All required AMIs were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := amiService.ReconcileAmiRule(c.rule)
		util.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}

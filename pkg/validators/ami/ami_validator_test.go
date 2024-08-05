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
			ImageId:       util.Ptr("ami-12345678"),
			Name:          util.Ptr("my-image"),
			ImageLocation: util.Ptr("self"),
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
				AmiIDs: []string{"ami-87654321"},
				Region: "us-west-1",
			},
			expectedResult: types.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-ami",
					ValidationRule: "validation-ami-rule-fail",
					Message:        "One or more required AMIs was not found",
					Details:        []string{},
					Failures:       []string{"AMI not found. Region: us-west-1. DescribeImagesInput{ImageIds: [ami-87654321]}"},
					Status:         corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass",
			rule: v1alpha1.AmiRule{
				Name:   "AMI Rule Pass",
				AmiIDs: []string{"ami-12345678"},
				Region: "us-west-1",
			},
			expectedResult: types.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-ami",
					ValidationRule: "validation-ami-rule-pass",
					Message:        "All required AMIs were found",
					Details:        []string{"Found AMI; ID: 'ami-12345678'; Name: 'my-image'; Source: 'self'"},
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

func Test_prettyPrintDescribeImagesInput(t *testing.T) {
	tests := []struct {
		name  string
		input *ec2.DescribeImagesInput
		want  string
	}{
		{
			name:  "empty input",
			input: &ec2.DescribeImagesInput{},
			want:  "",
		},
		{
			name: "input with image IDs",
			input: &ec2.DescribeImagesInput{
				ImageIds: []string{"ami-12345678", "ami-87654321"},
			},
			want: "ImageIds: [ami-12345678, ami-87654321]",
		},
		{
			name: "input with owners",
			input: &ec2.DescribeImagesInput{
				Owners: []string{"self", "123456789012"},
			},
			want: "Owners: [self, 123456789012]",
		},
		{
			name: "input with filters",
			input: &ec2.DescribeImagesInput{
				Filters: []ec2types.Filter{
					{
						Name:   util.Ptr("name"),
						Values: []string{"my-image"},
					},
				},
			},
			want: "Filters: [{name: [my-image]}]",
		},
		{
			name: "input with all fields",
			input: &ec2.DescribeImagesInput{
				ImageIds: []string{"ami-12345678", "ami-87654321"},
				Owners:   []string{"self", "123456789012"},
				Filters: []ec2types.Filter{
					{
						Name:   util.Ptr("name"),
						Values: []string{"my-image"},
					},
					{
						Name:   util.Ptr("architecture"),
						Values: []string{"x86_64"},
					},
				},
			},
			want: "ImageIds: [ami-12345678, ami-87654321], Owners: [self, 123456789012], Filters: [{name: [my-image]}, {architecture: [x86_64]}]",
		},
	}
	for _, tt := range tests {
		got := prettyPrintDescribeImagesInput(tt.input)
		if got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

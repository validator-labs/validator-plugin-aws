package iam

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	v8or "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or/pkg/types"
	"github.com/spectrocloud-labs/valid8or/pkg/util/ptr"
)

type iamApiMock struct {
	attachedGroupPolicies map[string]*iam.ListAttachedGroupPoliciesOutput
	attachedRolePolicies  map[string]*iam.ListAttachedRolePoliciesOutput
	attachedUserPolicies  map[string]*iam.ListAttachedUserPoliciesOutput
	policyArns            map[string]*iam.GetPolicyOutput
	policyVersions        map[string]*iam.GetPolicyVersionOutput
}

func (m iamApiMock) GetPolicy(input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	return m.policyArns[*input.PolicyArn], nil
}

func (m iamApiMock) GetPolicyVersion(input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	return m.policyVersions[*input.PolicyArn], nil
}

func (m iamApiMock) ListAttachedGroupPolicies(input *iam.ListAttachedGroupPoliciesInput) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return m.attachedGroupPolicies[*input.GroupName], nil
}

func (m iamApiMock) ListAttachedRolePolicies(input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
	return m.attachedRolePolicies[*input.RoleName], nil
}

func (m iamApiMock) ListAttachedUserPolicies(input *iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	return m.attachedUserPolicies[*input.UserName], nil
}

const (
	policyDocumentOutput1 string = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Action": [
					"ec2:DescribeInstances"
				],
				"Resource": [
					"*"
				],
				"Effect": "Allow"
			}
		]
	}`
	policyDocumentOutput2 string = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Action": [
					"*"
				],
				"Resource": [
					"*"
				],
				"Effect": "Allow"
			}
		]
	}`
)

func TestIAMValidation(t *testing.T) {

	iamService := NewIAMRuleService(logr.Logger{}, iamApiMock{
		attachedRolePolicies: map[string]*iam.ListAttachedRolePoliciesOutput{
			"iamRole1": &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []*iam.AttachedPolicy{
					{
						PolicyArn:  ptr.Ptr("iamRoleArn1"),
						PolicyName: ptr.Ptr("iamRole1"),
					},
				},
			},
			"iamRole2": &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []*iam.AttachedPolicy{
					{
						PolicyArn:  ptr.Ptr("iamRoleArn2"),
						PolicyName: ptr.Ptr("iamRole2"),
					},
				},
			},
		},
		policyArns: map[string]*iam.GetPolicyOutput{
			"iamRoleArn1": &iam.GetPolicyOutput{
				Policy: ptr.Ptr(iam.Policy{
					DefaultVersionId: ptr.Ptr("1"),
				}),
			},
			"iamRoleArn2": &iam.GetPolicyOutput{
				Policy: ptr.Ptr(iam.Policy{
					DefaultVersionId: ptr.Ptr("1"),
				}),
			},
		},
		policyVersions: map[string]*iam.GetPolicyVersionOutput{
			"iamRoleArn1": &iam.GetPolicyVersionOutput{
				PolicyVersion: ptr.Ptr(iam.PolicyVersion{
					Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput1)),
				}),
			},
			"iamRoleArn2": &iam.GetPolicyVersionOutput{
				PolicyVersion: ptr.Ptr(iam.PolicyVersion{
					Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput2)),
				}),
			},
		},
	})

	cs := []struct {
		name           string
		rule           iamRule
		expectedResult types.ValidationResult
		expectedError  error
	}{
		{
			name: "Fail (missing permission)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole1",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect:    "Allow",
								Actions:   []string{"s3:GetBuckets"},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &v8or.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole1",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamRoleRule iamRole1 missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(v8or.ValidationFailed),
			},
		},
		{
			name: "Pass (basic)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole1",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect:    "Allow",
								Actions:   []string{"ec2:DescribeInstances"},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &v8or.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole1",
					Message:        "All required aws-iam-role-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(v8or.ValidationSucceeded),
			},
		},
		{
			name: "Pass (wildcard)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole2",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect:    "Allow",
								Actions:   []string{"ec2:DescribeInstances"},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &v8or.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole2",
					Message:        "All required aws-iam-role-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(v8or.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMRoleRule(c.rule)
		if !reflect.DeepEqual(result.State, c.expectedResult.State) {
			t.Errorf("expected state (%+v), got (%+v)", c.expectedResult.State, result.State)
		}
		if !reflect.DeepEqual(result.Condition.ValidationType, c.expectedResult.Condition.ValidationType) {
			t.Errorf("expected validation type (%s), got (%s)", c.expectedResult.Condition.ValidationType, result.Condition.ValidationType)
		}
		if !reflect.DeepEqual(result.Condition.ValidationRule, c.expectedResult.Condition.ValidationRule) {
			t.Errorf("expected validation rule (%s), got (%s)", c.expectedResult.Condition.ValidationRule, result.Condition.ValidationRule)
		}
		if !reflect.DeepEqual(result.Condition.Message, c.expectedResult.Condition.Message) {
			t.Errorf("expected message (%s), got (%s)", c.expectedResult.Condition.Message, result.Condition.Message)
		}
		if !reflect.DeepEqual(result.Condition.Details, c.expectedResult.Condition.Details) {
			t.Errorf("expected details (%s), got (%s)", c.expectedResult.Condition.Details, result.Condition.Details)
		}
		if !reflect.DeepEqual(result.Condition.Failures, c.expectedResult.Condition.Failures) {
			t.Errorf("expected failures (%s), got (%s)", c.expectedResult.Condition.Failures, result.Condition.Failures)
		}
		if !reflect.DeepEqual(result.Condition.Status, c.expectedResult.Condition.Status) {
			t.Errorf("expected status (%s), got (%s)", c.expectedResult.Condition.Status, result.Condition.Status)
		}
		if !reflect.DeepEqual(err, c.expectedError) {
			t.Errorf("expected error (%v), got (%v)", c.expectedError, err)
		}
	}
}

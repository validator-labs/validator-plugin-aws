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

var iamService = NewIAMRuleService(logr.Logger{}, iamApiMock{
	attachedGroupPolicies: map[string]*iam.ListAttachedGroupPoliciesOutput{
		"iamGroup": &iam.ListAttachedGroupPoliciesOutput{
			AttachedPolicies: []*iam.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("iamRoleArn1"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
	},
	attachedRolePolicies: map[string]*iam.ListAttachedRolePoliciesOutput{
		"iamRole1": &iam.ListAttachedRolePoliciesOutput{
			AttachedPolicies: []*iam.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("iamRoleArn1"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
		"iamRole2": &iam.ListAttachedRolePoliciesOutput{
			AttachedPolicies: []*iam.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("iamRoleArn2"),
					PolicyName: ptr.Ptr("iamPolicy"),
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
	attachedUserPolicies: map[string]*iam.ListAttachedUserPoliciesOutput{
		"iamUser": &iam.ListAttachedUserPoliciesOutput{
			AttachedPolicies: []*iam.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("iamRoleArn1"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
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

type testCase struct {
	name           string
	rule           iamRule
	expectedResult types.ValidationResult
	expectedError  error
}

func checkTestCase(t *testing.T, c testCase, res *types.ValidationResult, err error) {
	if !reflect.DeepEqual(res.State, c.expectedResult.State) {
		t.Errorf("expected state (%+v), got (%+v)", c.expectedResult.State, res.State)
	}
	if !reflect.DeepEqual(res.Condition.ValidationType, c.expectedResult.Condition.ValidationType) {
		t.Errorf("expected validation type (%s), got (%s)", c.expectedResult.Condition.ValidationType, res.Condition.ValidationType)
	}
	if !reflect.DeepEqual(res.Condition.ValidationRule, c.expectedResult.Condition.ValidationRule) {
		t.Errorf("expected validation rule (%s), got (%s)", c.expectedResult.Condition.ValidationRule, res.Condition.ValidationRule)
	}
	if !reflect.DeepEqual(res.Condition.Message, c.expectedResult.Condition.Message) {
		t.Errorf("expected message (%s), got (%s)", c.expectedResult.Condition.Message, res.Condition.Message)
	}
	if !reflect.DeepEqual(res.Condition.Details, c.expectedResult.Condition.Details) {
		t.Errorf("expected details (%s), got (%s)", c.expectedResult.Condition.Details, res.Condition.Details)
	}
	if !reflect.DeepEqual(res.Condition.Failures, c.expectedResult.Condition.Failures) {
		t.Errorf("expected failures (%s), got (%s)", c.expectedResult.Condition.Failures, res.Condition.Failures)
	}
	if !reflect.DeepEqual(res.Condition.Status, c.expectedResult.Condition.Status) {
		t.Errorf("expected status (%s), got (%s)", c.expectedResult.Condition.Status, res.Condition.Status)
	}
	if !reflect.DeepEqual(err, c.expectedError) {
		t.Errorf("expected error (%v), got (%v)", c.expectedError, err)
	}
}

func TestIAMGroupValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing permission)",
			rule: v1alpha1.IamGroupRule{
				IamGroupName: "iamGroup",
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
					ValidationType: "aws-iam-group-policy",
					ValidationRule: "validation-iamGroup",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamGroupRule iamGroup missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(v8or.ValidationFailed),
			},
		},
		{
			name: "Pass (basic)",
			rule: v1alpha1.IamGroupRule{
				IamGroupName: "iamGroup",
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
					ValidationType: "aws-iam-group-policy",
					ValidationRule: "validation-iamGroup",
					Message:        "All required aws-iam-group-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(v8or.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMGroupRule(c.rule)
		checkTestCase(t, c, result, err)
	}
}

func TestIAMRoleValidation(t *testing.T) {
	cs := []testCase{
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
		checkTestCase(t, c, result, err)
	}
}

func TestIAMUserValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing permission)",
			rule: v1alpha1.IamUserRule{
				IamUserName: "iamUser",
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
					ValidationType: "aws-iam-user-policy",
					ValidationRule: "validation-iamUser",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamUserRule iamUser missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(v8or.ValidationFailed),
			},
		},
		{
			name: "Pass (basic)",
			rule: v1alpha1.IamUserRule{
				IamUserName: "iamUser",
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
					ValidationType: "aws-iam-user-policy",
					ValidationRule: "validation-iamUser",
					Message:        "All required aws-iam-user-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(v8or.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMUserRule(c.rule)
		checkTestCase(t, c, result, err)
	}
}

func TestIAMPolicyValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing permission)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "iamRoleArn1",
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
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-iamRoleArn1",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamPolicyRule iamRoleArn1 missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(v8or.ValidationFailed),
			},
		},
		{
			name: "Pass (basic)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "iamRoleArn1",
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
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-iamRoleArn1",
					Message:        "All required aws-iam-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(v8or.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMPolicyRule(c.rule)
		checkTestCase(t, c, result, err)
	}
}
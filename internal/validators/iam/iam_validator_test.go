package iam

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/utils/test"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
)

type iamApiMock struct {
	attachedGroupPolicies         map[string]*iam.ListAttachedGroupPoliciesOutput
	attachedRolePolicies          map[string]*iam.ListAttachedRolePoliciesOutput
	attachedUserPolicies          map[string]*iam.ListAttachedUserPoliciesOutput
	policyArns                    map[string]*iam.GetPolicyOutput
	policyVersions                map[string]*iam.GetPolicyVersionOutput
	simulatePrincipalPolicyResult map[string]*iam.SimulatePrincipalPolicyOutput
	user                          map[string]*iam.GetUserOutput
	group                         map[string]*iam.GetGroupOutput
	role                          map[string]*iam.GetRoleOutput
	contextKeys                   map[string]*iam.GetContextKeysForPrincipalPolicyOutput
}

func (m iamApiMock) GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return m.policyArns[*params.PolicyArn], nil
}

func (m iamApiMock) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return m.policyVersions[*params.PolicyArn], nil
}

func (m iamApiMock) ListAttachedGroupPolicies(ctx context.Context, params *iam.ListAttachedGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return m.attachedGroupPolicies[*params.GroupName], nil
}

func (m iamApiMock) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return m.attachedRolePolicies[*params.RoleName], nil
}

func (m iamApiMock) ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return m.attachedUserPolicies[*params.UserName], nil
}

func (m iamApiMock) SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	return m.simulatePrincipalPolicyResult[*params.PolicySourceArn], nil
}

func (m iamApiMock) GetUser(ctx context.Context, params *iam.GetUserInput, optFns ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	return m.user[*params.UserName], nil
}

func (m iamApiMock) GetGroup(ctx context.Context, params *iam.GetGroupInput, optFns ...func(*iam.Options)) (*iam.GetGroupOutput, error) {
	return m.group[*params.GroupName], nil
}

func (m iamApiMock) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return m.role[*params.RoleName], nil
}

func (m iamApiMock) GetContextKeysForPrincipalPolicy(ctx context.Context, params *iam.GetContextKeysForPrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error) {
	return m.contextKeys[*params.PolicySourceArn], nil
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
	policyDocumentOutput3 string = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Condition": {
					"ForAnyValue:StringLike": {
						"kms:ResourceAliases": "alias/cluster-api-provider-aws-*"
					}
				},
				"Action": [
					"kms:CreateGrant",
					"kms:DescribeKey"
				],
				"Resource": [
					"*"
				],
				"Effect": "Allow"
			}
		]
	}`
	policyDocumentOutput4 string = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": [
					"eks:AssociateIdentityProviderConfig",
					"eks:ListIdentityProviderConfigs"
				],
				"Resource": [
					"arn:*:eks:*:*:cluster/*"
				]
			},
			{
				"Effect": "Allow",
				"Action": [
					"eks:DisassociateIdentityProviderConfig",
					"eks:DescribeIdentityProviderConfig"
				],
				"Resource": [
					"*"
				]
			}
		]
	}`
	policyDocumentOutput5 string = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Action": [
					"ec2:*",
					"s3:List*",
					"organizations:*Organizations",
					"iam:*Group*"
				],
				"Resource": [
					"*"
				],
				"Effect": "Allow"
			},
			{
				"Action": [
					"ec2:DescribeInstances"
				],
				"Resource": [
					"*"
				],
				"Effect": "Deny"
			}
		]
	}`
)

var iamService = NewIAMRuleService(logr.Logger{}, iamApiMock{
	attachedGroupPolicies: map[string]*iam.ListAttachedGroupPoliciesOutput{
		"iamGroup": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn1"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
	},
	attachedRolePolicies: map[string]*iam.ListAttachedRolePoliciesOutput{
		"iamRole1": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn1"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
		"iamRole2": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn2"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
		"iamRole3": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn3"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
		"iamRole4": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn4"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
		"iamRole5": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn5"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
	},
	policyArns: map[string]*iam.GetPolicyOutput{
		"arn:aws:iam::123456789012:role/iamRoleArn1": {
			Policy: ptr.Ptr(iamtypes.Policy{
				DefaultVersionId: ptr.Ptr("1"),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn2": {
			Policy: ptr.Ptr(iamtypes.Policy{
				DefaultVersionId: ptr.Ptr("1"),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn3": {
			Policy: ptr.Ptr(iamtypes.Policy{
				DefaultVersionId: ptr.Ptr("1"),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn4": {
			Policy: ptr.Ptr(iamtypes.Policy{
				DefaultVersionId: ptr.Ptr("1"),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn5": {
			Policy: ptr.Ptr(iamtypes.Policy{
				DefaultVersionId: ptr.Ptr("1"),
			}),
		},
	},
	attachedUserPolicies: map[string]*iam.ListAttachedUserPoliciesOutput{
		"iamUser": {
			AttachedPolicies: []iamtypes.AttachedPolicy{
				{
					PolicyArn:  ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn1"),
					PolicyName: ptr.Ptr("iamPolicy"),
				},
			},
		},
	},
	policyVersions: map[string]*iam.GetPolicyVersionOutput{
		"arn:aws:iam::123456789012:role/iamRoleArn1": {
			PolicyVersion: ptr.Ptr(iamtypes.PolicyVersion{
				Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput1)),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn2": {
			PolicyVersion: ptr.Ptr(iamtypes.PolicyVersion{
				Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput2)),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn3": {
			PolicyVersion: ptr.Ptr(iamtypes.PolicyVersion{
				Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput3)),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn4": {
			PolicyVersion: ptr.Ptr(iamtypes.PolicyVersion{
				Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput4)),
			}),
		},
		"arn:aws:iam::123456789012:role/iamRoleArn5": {
			PolicyVersion: ptr.Ptr(iamtypes.PolicyVersion{
				Document: ptr.Ptr(url.QueryEscape(policyDocumentOutput5)),
			}),
		},
	},
	simulatePrincipalPolicyResult: map[string]*iam.SimulatePrincipalPolicyOutput{
		"arn:aws:iam::123456789012:group/iamGroupArn1": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:group/iamGroupArn2": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "implicitDeny",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: false},
				},
			},
		},
		"arn:aws:iam::123456789012:user/iamUserArn1": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:user/iamUserArn2": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "implicitDeny",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: false},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn1": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn2": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn3": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn4": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn5": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn6": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "implicitDeny",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: false},
				},
			},
		},
		"arn:aws:iam::123456789012:role/iamRoleZanzibar": {
			EvaluationResults: []iamtypes.EvaluationResult{
				{
					EvalActionName:              ptr.Ptr("ec2:DescribeInstances"),
					EvalDecision:                "allowed",
					OrganizationsDecisionDetail: &iamtypes.OrganizationsDecisionDetail{AllowedByOrganizations: true},
				},
			},
		},
	},
	group: map[string]*iam.GetGroupOutput{
		"iamGroup": {
			Group: &iamtypes.Group{
				Arn:       ptr.Ptr("arn:aws:iam::123456789012:group/iamGroupArn1"),
				GroupName: ptr.Ptr("iamGroup"),
			},
		},
		"iamGroup2": {
			Group: &iamtypes.Group{
				Arn:       ptr.Ptr("arn:aws:iam::123456789012:group/iamGroupArn2"),
				GroupName: ptr.Ptr("iamGroup2"),
			},
		},
	},
	role: map[string]*iam.GetRoleOutput{
		"iamRole1": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn1"),
				RoleName: ptr.Ptr("iamRole1"),
				RoleId:   ptr.Ptr("iamRoleID1"),
			},
		},
		"iamRole2": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn2"),
				RoleName: ptr.Ptr("iamRole2"),
				RoleId:   ptr.Ptr("iamRoleID2"),
			},
		},
		"iamRole3": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn3"),
				RoleName: ptr.Ptr("iamRole3"),
				RoleId:   ptr.Ptr("iamRoleID3"),
			},
		},
		"iamRole4": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn4"),
				RoleName: ptr.Ptr("iamRole4"),
				RoleId:   ptr.Ptr("iamRoleID4"),
			},
		},
		"iamRole5": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn5"),
				RoleName: ptr.Ptr("iamRole5"),
				RoleId:   ptr.Ptr("iamRoleID5"),
			},
		},
		"iamRole6": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleArn6"),
				RoleName: ptr.Ptr("iamRole6"),
				RoleId:   ptr.Ptr("iamRoleID6"),
			},
		},
		"iamRoleZanzibar": {
			Role: &iamtypes.Role{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:role/iamRoleZanzibar"),
				RoleName: ptr.Ptr("iamRoleZanzibar"),
				RoleId:   ptr.Ptr("iamRoleIDZanzibar"),
			},
		},
	},
	user: map[string]*iam.GetUserOutput{
		"iamUser": {
			User: &iamtypes.User{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:user/iamUserArn1"),
				UserName: ptr.Ptr("iamUser"),
				UserId:   ptr.Ptr("iamUserID1"),
			},
		},
		"iamUser2": {
			User: &iamtypes.User{
				Arn:      ptr.Ptr("arn:aws:iam::123456789012:user/iamUserArn2"),
				UserName: ptr.Ptr("iamUser2"),
				UserId:   ptr.Ptr("iamUserID2"),
			},
		},
	},
	contextKeys: map[string]*iam.GetContextKeysForPrincipalPolicyOutput{
		"arn:aws:iam::123456789012:user/iamUserArn1": {
			ContextKeyNames: []string{"aws:username", "aws:PrincipalArn", "aws:PrincipalAccount"},
		},
		"arn:aws:iam::123456789012:role/iamRoleArn1": {
			ContextKeyNames: []string{"aws:PrincipalAccount", "aws:PrincipalArn"},
		},
	},
})

type testCase struct {
	name           string
	rule           iamRule
	expectedResult types.ValidationResult
	expectedError  error
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-group-policy",
					ValidationRule: "validation-iamGroup",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamGroupRule iamGroup missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-group-policy",
					ValidationRule: "validation-iamGroup",
					Message:        "All required aws-iam-group-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (basic) - SCP",
			rule: v1alpha1.IamGroupRule{
				IamGroupName: "iamGroup2",
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-group-policy",
					ValidationRule: "validation-iamGroup2",
					Message:        "One or more required SCP permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures:       []string{"Action: ec2:DescribeInstances is denied due to an Organization level SCP policy for group: iamGroup2"},
					Status:         corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMGroupRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole1",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamRoleRule iamRole1 missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole1",
					Message:        "All required aws-iam-role-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole2",
					Message:        "All required aws-iam-role-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (condition)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole3",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Condition: &v1alpha1.Condition{
									Type:   "ForAnyValue:StringLike",
									Key:    "kms:ResourceAliases",
									Values: []string{"alias/cluster-api-provider-aws-*"},
								},
								Effect: "Allow",
								Actions: []string{
									"kms:CreateGrant",
									"kms:DescribeKey",
								},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole3",
					Message:        "All required aws-iam-role-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (condition, missing value)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole3",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Condition: &v1alpha1.Condition{
									Type: "ForAnyValue:StringLike",
									Key:  "kms:ResourceAliases",
									Values: []string{
										"alias/cluster-api-provider-aws-*",
										"alias/another-value",
									},
								},
								Effect: "Allow",
								Actions: []string{
									"kms:CreateGrant",
									"kms:DescribeKey",
								},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole3",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"Condition ForAnyValue:StringLike: kms:ResourceAliases=[alias/cluster-api-provider-aws-* alias/another-value] not applied to action(s) [kms:CreateGrant kms:DescribeKey] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (condition, total miss)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole2",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Condition: &v1alpha1.Condition{
									Type:   "ForAnyValue:StringLike",
									Key:    "kms:ResourceAliases",
									Values: []string{"alias/cluster-api-provider-aws-*"},
								},
								Effect: "Allow",
								Actions: []string{
									"kms:CreateGrant",
									"kms:DescribeKey",
								},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole2",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"Condition ForAnyValue:StringLike: kms:ResourceAliases=[alias/cluster-api-provider-aws-*] not applied to action(s) [kms:CreateGrant kms:DescribeKey] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (error)",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRoleZanzibar",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"kms:CreateGrant",
								},
								Resources: []string{"*"},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRoleZanzibar",
					Message:        "All required aws-iam-role-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
			expectedError: errors.New("no policies found for IAM role iamRoleZanzibar"),
		},
		{
			name: "Fail (basic) - SCP",
			rule: v1alpha1.IamRoleRule{
				IamRoleName: "iamRole6",
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-role-policy",
					ValidationRule: "validation-iamRole6",
					Message:        "One or more required SCP permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures:       []string{"Action: ec2:DescribeInstances is denied due to an Organization level SCP policy for role: iamRole6"},
					Status:         corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMRoleRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-user-policy",
					ValidationRule: "validation-iamUser",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamUserRule iamUser missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-user-policy",
					ValidationRule: "validation-iamUser",
					Message:        "All required aws-iam-user-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (basic) - SCP",
			rule: v1alpha1.IamUserRule{
				IamUserName: "iamUser2",
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-user-policy",
					ValidationRule: "validation-iamUser2",
					Message:        "One or more required SCP permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures:       []string{"Action: ec2:DescribeInstances is denied due to an Organization level SCP policy for user: iamUser2"},
					Status:         corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMUserRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}

func TestIAMPolicyValidation(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing permission)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn1",
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn1",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamPolicyRule arn:aws:iam::123456789012:role/iamRoleArn1 missing action(s): [s3:GetBuckets] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass (basic)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn1",
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
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn1",
					Message:        "All required aws-iam-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (multi-resource w/ wildcard)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn4",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"eks:AssociateIdentityProviderConfig",
									"eks:ListIdentityProviderConfigs",
									"eks:DisassociateIdentityProviderConfig",
									"eks:DescribeIdentityProviderConfig",
								},
								Resources: []string{
									"arn:*:eks:*:*:cluster/*",
									"arn:*:eks:*:*:nodegroup/*/*/*",
								},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn4",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					// TODO: fix this flaky test as the missing actions list can sometimes be jumbled: [eks:ListIdentityProviderConfigs eks:AssociateIdentityProviderConfig]
					Failures: []string{
						"v1alpha1.IamPolicyRule arn:aws:iam::123456789012:role/iamRoleArn4 missing action(s): [eks:AssociateIdentityProviderConfig eks:ListIdentityProviderConfigs] for resource arn:*:eks:*:*:nodegroup/*/*/* from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (explicit deny override)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn5",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"ec2:DescribeInstances",
								},
								Resources: []string{
									"*",
								},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn5",
					Message:        "One or more required IAM permissions was not found, or a condition was not met",
					Details:        []string{},
					Failures: []string{
						"v1alpha1.IamPolicyRule arn:aws:iam::123456789012:role/iamRoleArn5 missing action(s): [ec2:DescribeInstances] for resource * from policy iamPolicy",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass (explicit allow with irrelevant explicit deny)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn5",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"ec2:StartInstances",
								},
								Resources: []string{
									"*",
								},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn5",
					Message:        "All required aws-iam-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (action with wildcard suffix)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn5",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"s3:ListBuckets",
								},
								Resources: []string{
									"*",
								},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn5",
					Message:        "All required aws-iam-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (action with wildcard prefix)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn5",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"organizations:ListOrganizations",
								},
								Resources: []string{
									"*",
								},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn5",
					Message:        "All required aws-iam-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (action with wildcard prefix and suffix)",
			rule: v1alpha1.IamPolicyRule{
				IamPolicyARN: "arn:aws:iam::123456789012:role/iamRoleArn5",
				Policies: []v1alpha1.PolicyDocument{
					{
						Name:    "iamPolicy",
						Version: "1",
						Statements: []v1alpha1.StatementEntry{
							{
								Effect: "Allow",
								Actions: []string{
									"iam:DetachGroupPolicy",
								},
								Resources: []string{
									"*",
								},
							},
						},
					},
				},
			},
			expectedResult: types.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "aws-iam-policy",
					ValidationRule: "validation-arn:aws:iam::123456789012:role/iamRoleArn5",
					Message:        "All required aws-iam-policy permissions were found",
					Details:        []string{},
					Failures:       nil,
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		result, err := iamService.ReconcileIAMPolicyRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}

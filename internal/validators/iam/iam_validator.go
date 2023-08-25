package iam

import (
	"fmt"
	"net/url"

	awspolicy "github.com/L30Bola/aws-policy"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/go-logr/logr"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/types"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/aws"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/strings"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

type permission struct {
	Actions    map[string]bool
	Condition  *v1alpha1.Condition
	Errors     []string
	PolicyName string
}

type missing struct {
	Actions    []string
	PolicyName string
}

// reconcileIAMRule reconciles an IAM validation rule from the AWSValidator config
func ReconcileIAMRule(nn k8stypes.NamespacedName, rule v1alpha1.IamRule, s *session.Session, log logr.Logger) (*types.ValidationResult, error) {
	iamSvc := aws.IAMService(s)

	// Build the latest condition for this IAM rule
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := valid8orv1alpha1.DefaultValidationCondition()
	latestCondition.Message = "All required IAM permissions were found"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", constants.ValidationRulePrefix, rule.IamRole)
	latestCondition.ValidationType = constants.ValidationTypeIAMRolePolicy
	validationResult := &types.ValidationResult{Condition: &latestCondition, State: &state}

	// Build map of required permissions
	permissions := make(map[string]*permission)
	for _, p := range rule.Policies {
		for _, s := range p.Statements {
			if s.Effect != "Allow" {
				continue
			}
			for _, r := range s.Resources {
				if permissions[r] == nil {
					permissions[r] = &permission{
						Actions: make(map[string]bool),
						Errors:  make([]string, 0),
					}
				}
				permissions[r].PolicyName = p.Name
				if s.Condition != nil {
					permissions[r].Condition = s.Condition
				}
				for _, action := range s.Actions {
					permissions[r].Actions[action] = false
				}
			}
		}
	}

	// Retrieve existing permissions & update the permission map
	policies, err := iamSvc.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
		RoleName: &rule.IamRole,
	})
	if err != nil {
		log.V(0).Error(err, "failed to list policies for IAM role", "role", rule.IamRole)
		return validationResult, err
	}
	for _, p := range policies.AttachedPolicies {
		// Fetch the IAM policy's policy document
		policyOutput, err := iamSvc.GetPolicy(&iam.GetPolicyInput{
			PolicyArn: p.PolicyArn,
		})
		if err != nil {
			log.V(0).Error(err, "failed to get IAM policy", "role", rule.IamRole, "policyArn", p.PolicyArn)
			return validationResult, err
		}
		policyVersionOutput, err := iamSvc.GetPolicyVersion(&iam.GetPolicyVersionInput{
			PolicyArn: p.PolicyArn,
			VersionId: policyOutput.Policy.DefaultVersionId,
		})
		if err != nil {
			log.V(0).Error(err, "failed to get IAM policy version", "policyArn", p.PolicyArn, "versionId", policyOutput.Policy.DefaultVersionId)
			return validationResult, err
		}

		// Parse the policy document
		if policyVersionOutput.PolicyVersion.Document == nil {
			log.V(0).Info("Skipping IAM policy with empty permissions", "policyArn", p.PolicyArn, "versionId", policyOutput.Policy.DefaultVersionId)
			continue
		}
		policyUnescaped, err := url.QueryUnescape(*policyVersionOutput.PolicyVersion.Document)
		if err != nil {
			log.V(0).Error(err, "failed to decode IAM policy document", "policyArn", p.PolicyArn, "versionId", policyOutput.Policy.DefaultVersionId)
			return validationResult, err
		}
		policyDocument := &awspolicy.Policy{}
		if err := policyDocument.UnmarshalJSON([]byte(policyUnescaped)); err != nil {
			log.V(0).Error(err, "failed to unmarshal IAM policy", "role", rule.IamRole, "policyArn", p.PolicyArn)
			return validationResult, err
		}

		// Update the permission map based on the content of the current policy
		for _, s := range policyDocument.Statements {
			if s.Effect != "Allow" {
				continue
			}
			for _, resource := range s.Resource {
				permission, ok := permissions[resource]
				if ok {
					if permission.Condition != nil {
						errMsg := fmt.Sprintf("Resource %s missing condition %s", resource, permission.Condition)
						condition, ok := s.Condition[permission.Condition.Type]
						if !ok {
							permission.Errors = append(permission.Errors, errMsg)
							continue
						}
						v, ok := condition[permission.Condition.Key]
						if !ok {
							permission.Errors = append(permission.Errors, errMsg)
							continue
						}
						if !slices.Equal(v, permission.Condition.Values) {
							permission.Errors = append(permission.Errors, errMsg)
							continue
						}
					}
					for _, action := range s.Action {
						permission.Actions[action] = true
					}
				}
			}
		}
	}

	// Build failure messages, if applicable
	failures := make([]string, 0)
	missingActions := make(map[string]*missing)

	for resource, permission := range permissions {
		if len(permission.Errors) > 0 {
			failures = append(failures, strings.DeDupeStrSlice(permission.Errors)...)
			continue
		}
		for action, allowed := range permission.Actions {
			if !allowed {
				if missingActions[resource] == nil {
					missingActions[resource] = &missing{
						Actions: make([]string, 0),
					}
				}
				missingActions[resource].Actions = append(missingActions[resource].Actions, action)
				missingActions[resource].PolicyName = permission.PolicyName
			}
		}
	}
	for resource, missing := range missingActions {
		failure := fmt.Sprintf(
			"IAM role %s missing action(s): %s for resource %s from policy %s",
			rule.IamRole, missing.Actions, resource, missing.PolicyName,
		)
		failures = append(failures, failure)
	}
	if len(failures) > 0 {
		state = valid8orv1alpha1.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "One or more required IAM permissions was not found, or a condition was not met"
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

package iam

import (
	"fmt"
	"net/url"
	"strings"

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
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/ptr"
	str_utils "github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/strings"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

type permission struct {
	Actions    map[iamAction]bool
	Condition  *v1alpha1.Condition
	Errors     []string
	PolicyName string
}

type iamAction struct {
	Service string
	Verb    string
}

func (a *iamAction) String() string {
	return fmt.Sprintf("%s:%s", a.Service, a.Verb)
}

func (a *iamAction) IsAdmin() bool {
	return a.Service == constants.IAMWildcard && a.Verb == constants.IAMWildcard
}

type missing struct {
	Actions    []string
	PolicyName string
}

type IamRuleObj interface {
	Name() string
	IAMPolicies() []v1alpha1.PolicyDocument
}

type IAMRuleService struct {
	iamSvc *iam.IAM
	log    logr.Logger
}

func NewIAMRuleService(log logr.Logger, s *session.Session) *IAMRuleService {
	return &IAMRuleService{
		iamSvc: aws.IAMService(s),
		log:    log,
	}
}

// ReconcileIAMRoleRule reconciles an IAM role validation rule from an AWSValidator config
func (s *IAMRuleService) ReconcileIAMRoleRule(nn k8stypes.NamespacedName, rule IamRuleObj) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMRolePolicy)

	// Retrieve all IAM policies attached to the IAM role
	policies, err := s.iamSvc.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
		RoleName: ptr.Ptr(rule.Name()),
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to list policies for IAM role", "role", rule.Name())
		return vr, err
	}

	// Build map of required permissions
	permissions := buildPermissions(rule)

	// Update the permission map for each IAM policy
	context := []string{"role", rule.Name()}
	if err := s.processPolicies(policies.AttachedPolicies, permissions, context); err != nil {
		return vr, err
	}

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

// ReconcileIAMUserRule reconciles an IAM user validation rule from an AWSValidator config
func (s *IAMRuleService) ReconcileIAMUserRule(nn k8stypes.NamespacedName, rule IamRuleObj) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMUserPolicy)

	// Retrieve all IAM policies attached to the IAM user
	policies, err := s.iamSvc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
		UserName: ptr.Ptr(rule.Name()),
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to list policies for IAM user", "name", rule.Name())
		return vr, err
	}

	// Build map of required permissions
	permissions := buildPermissions(rule)

	// Update the permission map for each IAM policy
	context := []string{"user", rule.Name()}
	if err := s.processPolicies(policies.AttachedPolicies, permissions, context); err != nil {
		return vr, err
	}

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

// ReconcileIAMGroupRule reconciles an IAM group validation rule from an AWSValidator config
func (s *IAMRuleService) ReconcileIAMGroupRule(nn k8stypes.NamespacedName, rule IamRuleObj) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMGroupPolicy)

	// Retrieve all IAM policies attached to the IAM user
	policies, err := s.iamSvc.ListAttachedGroupPolicies(&iam.ListAttachedGroupPoliciesInput{
		GroupName: ptr.Ptr(rule.Name()),
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to list policies for IAM group", "name", rule.Name())
		return vr, err
	}

	// Build map of required permissions
	permissions := buildPermissions(rule)

	// Update the permission map for each IAM policy
	context := []string{"group", rule.Name()}
	if err := s.processPolicies(policies.AttachedPolicies, permissions, context); err != nil {
		return vr, err
	}

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

// ReconcileIAMPolicyRule reconciles an IAM policy validation rule from an AWSValidator config
func (s *IAMRuleService) ReconcileIAMPolicyRule(nn k8stypes.NamespacedName, rule IamRuleObj) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMPolicy)

	// Build map of required permissions
	permissions := buildPermissions(rule)

	// Update the permission map for the IAM policy
	context := []string{"policy", rule.Name()}
	policyDocument, err := s.getPolicyDocument(ptr.Ptr(rule.Name()), context)
	if err != nil {
		return vr, err
	}
	updatePermissions(policyDocument, permissions)

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

// processPolicies updates an IAM permission map for each IAM policy in an array of IAM policies attached to a IAM user / group / role
func (s *IAMRuleService) processPolicies(policies []*iam.AttachedPolicy, permissions map[string]*permission, context []string) error {
	for _, p := range policies {
		policyDocument, err := s.getPolicyDocument(p.PolicyArn, context)
		if err != nil {
			return err
		} else if policyDocument == nil {
			continue
		}
		updatePermissions(policyDocument, permissions)
	}
	return nil
}

// getPolicyDocument generates an awspolicy.Policy, given an AWS IAM policy ARN
func (s *IAMRuleService) getPolicyDocument(policyArn *string, context []string) (*awspolicy.Policy, error) {
	// Fetch the IAM policy's policy document
	policyOutput, err := s.iamSvc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: policyArn,
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to get IAM policy", context, "policyArn", policyArn)
		return nil, err
	}
	policyVersionOutput, err := s.iamSvc.GetPolicyVersion(&iam.GetPolicyVersionInput{
		PolicyArn: policyArn,
		VersionId: policyOutput.Policy.DefaultVersionId,
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to get IAM policy version", "policyArn", policyArn, "versionId", policyOutput.Policy.DefaultVersionId)
		return nil, err
	}

	// Parse the policy document
	if policyVersionOutput.PolicyVersion.Document == nil {
		s.log.V(0).Info("Skipping IAM policy with empty permissions", "policyArn", policyArn, "versionId", policyOutput.Policy.DefaultVersionId)
		return nil, nil
	}
	policyUnescaped, err := url.QueryUnescape(*policyVersionOutput.PolicyVersion.Document)
	if err != nil {
		s.log.V(0).Error(err, "failed to decode IAM policy document", "policyArn", policyArn, "versionId", policyOutput.Policy.DefaultVersionId)
		return nil, err
	}
	policyDocument := &awspolicy.Policy{}
	if err := policyDocument.UnmarshalJSON([]byte(policyUnescaped)); err != nil {
		s.log.V(0).Error(err, "failed to unmarshal IAM policy", context, "policyArn", policyArn)
		return nil, err
	}
	return policyDocument, nil
}

// buildValidationResult builds a default ValidationResult for a given validation type
func buildValidationResult(rule IamRuleObj, validationType string) *types.ValidationResult {
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := valid8orv1alpha1.DefaultValidationCondition()
	latestCondition.Message = fmt.Sprintf("All required %s permissions were found", validationType)
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", constants.ValidationRulePrefix, rule.Name())
	latestCondition.ValidationType = validationType
	return &types.ValidationResult{Condition: &latestCondition, State: &state}
}

// buildPermissions builds an IAM permission map from an IAM rule
func buildPermissions(rule IamRuleObj) map[string]*permission {
	permissions := make(map[string]*permission)
	for _, p := range rule.IAMPolicies() {
		for _, s := range p.Statements {
			if s.Effect != "Allow" {
				continue
			}
			for _, r := range s.Resources {
				if permissions[r] == nil {
					permissions[r] = &permission{
						Actions: make(map[iamAction]bool),
						Errors:  make([]string, 0),
					}
				}
				permissions[r].PolicyName = p.Name
				if s.Condition != nil {
					permissions[r].Condition = s.Condition
				}
				for _, action := range s.Actions {
					permissions[r].Actions[toIAMAction(action)] = false
				}
			}
		}
	}
	return permissions
}

func toIAMAction(action string) iamAction {
	if action == constants.IAMWildcard {
		return iamAction{
			Service: action,
			Verb:    action,
		}
	}
	actionParts := strings.Split(action, ":")
	return iamAction{
		Service: actionParts[0],
		Verb:    actionParts[1],
	}
}

// updatePermissions updates an IAM permission map based on the content of an IAM policy
func updatePermissions(policyDocument *awspolicy.Policy, permissions map[string]*permission) {
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
					iamAction := toIAMAction(action)
					permission.Actions[iamAction] = true

					if iamAction.IsAdmin() {
						// mark all permissions found & exit early
						for a := range permission.Actions {
							permission.Actions[a] = true
						}
						return
					}
					if iamAction.Verb == constants.IAMWildcard {
						// mark all permissions for the relevant service as found
						for a := range permission.Actions {
							if a.Service == iamAction.Service {
								permission.Actions[a] = true
							}
						}
					}
				}
			}
		}
	}
}

// computeFailures derives IAM rule failures from an IAM permissions map once it has been fully updated
func computeFailures(rule IamRuleObj, permissions map[string]*permission, vr *types.ValidationResult) {
	failures := make([]string, 0)
	missingActions := make(map[string]*missing)

	for resource, permission := range permissions {
		if len(permission.Errors) > 0 {
			failures = append(failures, str_utils.DeDupeStrSlice(permission.Errors)...)
			continue
		}
		for action, allowed := range permission.Actions {
			if !allowed {
				if missingActions[resource] == nil {
					missingActions[resource] = &missing{
						Actions: make([]string, 0),
					}
				}
				missingActions[resource].Actions = append(missingActions[resource].Actions, action.String())
				missingActions[resource].PolicyName = permission.PolicyName
			}
		}
	}

	for resource, missing := range missingActions {
		failureMsg := fmt.Sprintf(
			"%T %s missing action(s): %s for resource %s from policy %s",
			rule, rule.Name(), missing.Actions, resource, missing.PolicyName,
		)
		failures = append(failures, failureMsg)
	}
	if len(failures) > 0 {
		vr.State = ptr.Ptr(valid8orv1alpha1.ValidationFailed)
		vr.Condition.Failures = failures
		vr.Condition.Message = "One or more required IAM permissions was not found, or a condition was not met"
		vr.Condition.Status = corev1.ConditionFalse
	}
}

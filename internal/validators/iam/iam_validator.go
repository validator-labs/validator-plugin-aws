package iam

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	awspolicy "github.com/L30Bola/aws-policy"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/go-logr/logr"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"

	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/constants"
	str_utils "github.com/spectrocloud-labs/validator-plugin-aws/internal/utils/strings"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	"github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
)

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

type permission struct {
	Actions     map[iamAction]bool
	Condition   *v1alpha1.Condition
	ConditionOk bool
	Errors      []string
	PolicyName  string
	Resource    string
}

type iamRule interface {
	Name() string
	IAMPolicies() []v1alpha1.PolicyDocument
}

type iamApi interface {
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListAttachedGroupPolicies(ctx context.Context, params *iam.ListAttachedGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
}

type IAMRuleService struct {
	log    logr.Logger
	iamSvc iamApi
}

func NewIAMRuleService(log logr.Logger, iamSvc iamApi) *IAMRuleService {
	return &IAMRuleService{
		log:    log,
		iamSvc: iamSvc,
	}
}

// ReconcileIAMRoleRule reconciles an IAM role validation rule from an AWSValidator config
func (s *IAMRuleService) ReconcileIAMRoleRule(rule iamRule) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMRolePolicy)

	// Retrieve all IAM policies attached to the IAM role
	policies, err := s.iamSvc.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: ptr.Ptr(rule.Name()),
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to list policies for IAM role", "role", rule.Name())
		return vr, err
	} else if policies == nil {
		return vr, fmt.Errorf("no policies found for IAM role %s", rule.Name())
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
func (s *IAMRuleService) ReconcileIAMUserRule(rule iamRule) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMUserPolicy)

	// Retrieve all IAM policies attached to the IAM user
	policies, err := s.iamSvc.ListAttachedUserPolicies(context.Background(), &iam.ListAttachedUserPoliciesInput{
		UserName: ptr.Ptr(rule.Name()),
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to list policies for IAM user", "name", rule.Name())
		return vr, err
	} else if policies == nil {
		return vr, fmt.Errorf("no policies found for IAM user %s", rule.Name())
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
func (s *IAMRuleService) ReconcileIAMGroupRule(rule iamRule) (*types.ValidationResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMGroupPolicy)

	// Retrieve all IAM policies attached to the IAM user
	policies, err := s.iamSvc.ListAttachedGroupPolicies(context.Background(), &iam.ListAttachedGroupPoliciesInput{
		GroupName: ptr.Ptr(rule.Name()),
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to list policies for IAM group", "name", rule.Name())
		return vr, err
	} else if policies == nil {
		return vr, fmt.Errorf("no policies found for IAM group %s", rule.Name())
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
func (s *IAMRuleService) ReconcileIAMPolicyRule(rule iamRule) (*types.ValidationResult, error) {

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
	applyPolicy(policyDocument, permissions)

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

// processPolicies updates an IAM permission map for each IAM policy in an array of IAM policies attached to a IAM user / group / role
func (s *IAMRuleService) processPolicies(policies []iamtypes.AttachedPolicy, permissions map[string][]*permission, context []string) error {
	for _, p := range policies {
		policyDocument, err := s.getPolicyDocument(p.PolicyArn, context)
		if err != nil {
			return err
		} else if policyDocument == nil {
			continue
		}
		applyPolicy(policyDocument, permissions)
	}
	return nil
}

// getPolicyDocument generates an awspolicy.Policy, given an AWS IAM policy ARN
func (s *IAMRuleService) getPolicyDocument(policyArn *string, ctx []string) (*awspolicy.Policy, error) {
	// Fetch the IAM policy's policy document
	policyOutput, err := s.iamSvc.GetPolicy(context.Background(), &iam.GetPolicyInput{
		PolicyArn: policyArn,
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to get IAM policy", ctx[0], ctx[1], "policyArn", policyArn)
		return nil, err
	}
	policyVersionOutput, err := s.iamSvc.GetPolicyVersion(context.Background(), &iam.GetPolicyVersionInput{
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
		s.log.V(0).Error(err, "failed to unmarshal IAM policy", ctx[0], ctx[1], "policyArn", policyArn)
		return nil, err
	}
	return policyDocument, nil
}

// buildValidationResult builds a default ValidationResult for a given validation type
func buildValidationResult(rule iamRule, validationType string) *types.ValidationResult {
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = fmt.Sprintf("All required %s permissions were found", validationType)
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.Name())
	latestCondition.ValidationType = validationType
	return &types.ValidationResult{Condition: &latestCondition, State: &state}
}

// buildPermissions builds an IAM permission map from an IAM rule
func buildPermissions(rule iamRule) map[string][]*permission {
	permissions := make(map[string][]*permission)
	for _, p := range rule.IAMPolicies() {
		for _, s := range p.Statements {
			if s.Effect != "Allow" {
				continue
			}
			for _, r := range s.Resources {
				if _, ok := permissions[r]; !ok {
					permissions[r] = make([]*permission, 0)
				}
				resourcePerm := &permission{
					Actions:    make(map[iamAction]bool),
					Errors:     make([]string, 0),
					PolicyName: p.Name,
					Resource:   r,
				}
				if s.Condition != nil {
					resourcePerm.Condition = s.Condition
				}
				for _, action := range s.Actions {
					resourcePerm.Actions[toIAMAction(action)] = false
				}
				permissions[r] = append(permissions[r], resourcePerm)
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

// applyPolicy updates an IAM permission map based on the content of an IAM policy
func applyPolicy(policyDocument *awspolicy.Policy, permissions map[string][]*permission) {
	// mark all actions as allowed per the explicit allows in the policy document
	updateResourcePermissions(policyDocument, permissions, "Allow")
	// override explicit allows with any explicit denies
	updateResourcePermissions(policyDocument, permissions, "Deny")
}

func updateResourcePermissions(policyDocument *awspolicy.Policy, permissions map[string][]*permission, effect string) {
	actionAllowed := effect == "Allow"

	for _, s := range policyDocument.Statements {
		if s.Effect != effect {
			continue
		}
		for _, resource := range s.Resource {
			if resource == constants.IAMWildcard {
				for _, ps := range permissions {
					updatePermissions(s, ps, actionAllowed)
				}
			} else {
				ps, ok := permissions[resource]
				if ok {
					updatePermissions(s, ps, actionAllowed)
				}
			}
		}
	}
}

func updatePermissions(s awspolicy.Statement, permissions []*permission, actionAllowed bool) {
	for _, permission := range permissions {
		if s.Condition != nil && permission.Condition != nil {
			condition, ok := s.Condition[permission.Condition.Type]
			if ok {
				values, ok := condition[permission.Condition.Key]
				if ok {
					allFound := true
					for _, v := range permission.Condition.Values {
						if !slices.Contains(values, v) {
							allFound = false
						}
					}
					if allFound {
						permission.ConditionOk = true
					}
				}
			}
		}
		for _, action := range s.Action {
			iamAction := toIAMAction(action)
			updatePermissionAction(permission, iamAction, actionAllowed)

			if iamAction.IsAdmin() {
				// update all permissions & exit early
				for a := range permission.Actions {
					updatePermissionAction(permission, a, actionAllowed)
				}
				return
			} else if iamAction.Verb == constants.IAMWildcard {
				// update all permissions for the relevant service
				for a := range permission.Actions {
					if a.Service == iamAction.Service {
						updatePermissionAction(permission, a, actionAllowed)
					}
				}
			} else if strings.HasPrefix(iamAction.Verb, constants.IAMWildcard) {
				if strings.HasSuffix(iamAction.Verb, constants.IAMWildcard) {
					// handle actions with a wildcard prefix & suffix, e.g. iam:*Group*
					for a := range permission.Actions {
						if a.Service == iamAction.Service && strings.Contains(a.Verb, iamAction.Verb[1:len(iamAction.Verb)-1]) {
							updatePermissionAction(permission, a, actionAllowed)
						}
					}
				} else {
					// handle actions with a wildcard prefix, e.g. s3:*Buckets
					for a := range permission.Actions {
						if a.Service == iamAction.Service && strings.HasSuffix(a.Verb, iamAction.Verb[1:]) {
							updatePermissionAction(permission, a, actionAllowed)
						}
					}
				}
			} else if strings.HasSuffix(iamAction.Verb, constants.IAMWildcard) {
				// handle actions with a wildcard suffix, e.g. s3:List*
				for a := range permission.Actions {
					if a.Service == iamAction.Service && strings.HasPrefix(a.Verb, iamAction.Verb[:len(iamAction.Verb)-1]) {
						updatePermissionAction(permission, a, actionAllowed)
					}
				}
			}
		}
	}
}

func updatePermissionAction(permission *permission, a iamAction, actionAllowed bool) {
	if _, ok := permission.Actions[a]; ok {
		permission.Actions[a] = actionAllowed
	}
}

// computeFailures derives IAM rule failures from an IAM permissions map once it has been fully updated
func computeFailures(rule iamRule, permissions map[string][]*permission, vr *types.ValidationResult) {
	failures := make([]string, 0)
	missingActions := make(map[string]*missing)

	for resource, resourcePermissions := range permissions {
		for _, permission := range resourcePermissions {
			if len(permission.Errors) > 0 {
				failures = append(failures, str_utils.DeDupeStrSlice(permission.Errors)...)
				continue
			}
			if permission.Condition != nil && !permission.ConditionOk {
				actionNames := make([]string, 0, len(permission.Actions))
				for k := range permission.Actions {
					actionNames = append(actionNames, k.String())
				}
				slices.Sort(actionNames)
				errMsg := fmt.Sprintf(
					"Condition %s not applied to action(s) %s for resource %s from policy %s",
					permission.Condition, actionNames, resource, permission.PolicyName,
				)
				failures = append(failures, errMsg)
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
	}

	for resource, missing := range missingActions {
		failureMsg := fmt.Sprintf(
			"%T %s missing action(s): %s for resource %s from policy %s",
			rule, rule.Name(), missing.Actions, resource, missing.PolicyName,
		)
		failures = append(failures, failureMsg)
	}
	if len(failures) > 0 {
		slices.Sort(failures)
		vr.State = ptr.Ptr(vapi.ValidationFailed)
		vr.Condition.Failures = failures
		vr.Condition.Message = "One or more required IAM permissions was not found, or a condition was not met"
		vr.Condition.Status = corev1.ConditionFalse
	}
}

// Package iam handles IAM validation rule reconciliation.
package iam

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	awspolicy "github.com/L30Bola/aws-policy"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/go-logr/logr"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/pkg/constants"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

// AccountIDFromARNRegex is a regex pattern to extract the Account ID from an ARN.
const AccountIDFromARNRegex = "arn:[a-z]*:[a-z]*::([?<AccountID>\\d{12}$]*):[0-9A-Za-z]*\\/[0-9A-Za-z]*"

var re = regexp.MustCompile(AccountIDFromARNRegex)

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
	Condition   v1alpha1.Condition
	ConditionOk bool
	Errors      []string
	PolicyName  string
	Resource    string
}

type iamRule interface {
	Name() string
	IAMPolicies() []v1alpha1.PolicyDocument
}

type iamAPI interface {
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListAttachedGroupPolicies(ctx context.Context, params *iam.ListAttachedGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	GetUser(ctx context.Context, params *iam.GetUserInput, optFns ...func(*iam.Options)) (*iam.GetUserOutput, error)
	GetGroup(ctx context.Context, params *iam.GetGroupInput, optFns ...func(*iam.Options)) (*iam.GetGroupOutput, error)
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
	GetContextKeysForPrincipalPolicy(ctx context.Context, params *iam.GetContextKeysForPrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error)
}

// RuleService reconciles IAM validation rules.
type RuleService struct {
	log    logr.Logger
	iamSvc iamAPI
}

// NewIAMRuleService creates a new IAMRuleService.
func NewIAMRuleService(log logr.Logger, iamSvc iamAPI) *RuleService {
	return &RuleService{
		log:    log,
		iamSvc: iamSvc,
	}
}

// ReconcileIAMRoleRule reconciles an IAM role validation rule from an AWSValidator config
// nolint:dupl
func (s *RuleService) ReconcileIAMRoleRule(rule iamRule) (*types.ValidationRuleResult, error) {
	var ctxEntries []iamtypes.ContextEntry

	// Build the default ValidationResult for this IAM rule
	vr := validators.BuildValidationResult(
		rule.Name(), resultMessage(constants.ValidationTypeIAMRolePolicy), constants.ValidationTypeIAMRolePolicy,
	)

	role, err := s.iamSvc.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: util.Ptr(rule.Name()),
	})
	if err != nil {
		return vr, err
	}

	policyDocs := rule.IAMPolicies()

	ctxKeys, err := s.iamSvc.GetContextKeysForPrincipalPolicy(context.Background(), &iam.GetContextKeysForPrincipalPolicyInput{
		PolicySourceArn: util.Ptr(*role.Role.Arn),
	})
	if err != nil {
		return vr, err
	}
	if ctxKeys != nil {
		ctxEntries = getContextEntries(s.log, *role.Role.RoleName, *role.Role.RoleId, *role.Role.Arn, ctxKeys.ContextKeyNames)
	}

	scpFailures, err := checkSCP(s.iamSvc, policyDocs, *role.Role.Arn, "role", *role.Role.RoleName, ctxEntries)
	if err != nil {
		return vr, err
	}

	// SCP related failures found. Exit early
	if len(scpFailures) > 0 {
		return getSCPFailedValidationResult(vr, scpFailures), nil
	}

	// Retrieve all IAM policies attached to the IAM role
	policies, err := s.iamSvc.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: util.Ptr(rule.Name()),
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
// nolint:dupl
func (s *RuleService) ReconcileIAMUserRule(rule iamRule) (*types.ValidationRuleResult, error) {
	var ctxEntries []iamtypes.ContextEntry

	// Build the default ValidationResult for this IAM rule
	vr := validators.BuildValidationResult(
		rule.Name(), resultMessage(constants.ValidationTypeIAMUserPolicy), constants.ValidationTypeIAMUserPolicy,
	)

	user, err := s.iamSvc.GetUser(context.Background(), &iam.GetUserInput{
		UserName: util.Ptr(rule.Name()),
	})
	if err != nil {
		return vr, err
	}

	policyDocs := rule.IAMPolicies()

	ctxKeys, err := s.iamSvc.GetContextKeysForPrincipalPolicy(context.Background(), &iam.GetContextKeysForPrincipalPolicyInput{
		PolicySourceArn: util.Ptr(*user.User.Arn),
	})
	if err != nil {
		return vr, err
	}
	if ctxKeys != nil {
		ctxEntries = getContextEntries(s.log, *user.User.UserName, *user.User.UserId, *user.User.Arn, ctxKeys.ContextKeyNames)
	}

	scpFailures, err := checkSCP(s.iamSvc, policyDocs, *user.User.Arn, "user", *user.User.UserName, ctxEntries)
	if err != nil {
		return vr, err
	}

	// SCP related failures found. Exit early
	if len(scpFailures) > 0 {
		return getSCPFailedValidationResult(vr, scpFailures), nil
	}

	// Retrieve all IAM policies attached to the IAM user
	policies, err := s.iamSvc.ListAttachedUserPolicies(context.Background(), &iam.ListAttachedUserPoliciesInput{
		UserName: util.Ptr(rule.Name()),
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

func getAccountIDFromARN(arn string) (string, error) {
	matches := re.FindStringSubmatch(arn)

	if matches == nil || len(matches) < 2 {
		return "", errors.New("error getting org ID from Account ARN")
	}

	//return first captured group - Account ID
	return matches[1], nil
}

func getContextEntries(log logr.Logger, entityName, entityID, entityARN string, contextKeys []string) []iamtypes.ContextEntry {
	var ctxEntries []iamtypes.ContextEntry

	for _, ctxKey := range contextKeys {
		switch ctxKey {
		case "aws:username":
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   util.Ptr("aws:username"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{entityName},
			})
		case "aws:userid":
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   util.Ptr("aws:userid"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{entityID},
			})
		case "aws:PrincipalArn":
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   util.Ptr("aws:PrincipalArn"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{entityARN},
			})
		case "aws:PrincipalAccount":
			accID, err := getAccountIDFromARN(entityARN)
			if err != nil {
				log.V(0).Info("error getting account ID from ARN")
			}
			if accID == "" {
				log.V(0).Info("Account ID is empty. Skip getting context key value for: aws:PrincipalAccount")
				break
			}
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   util.Ptr("aws:PrincipalAccount"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{accID},
			})
		// TODO: Check a way to get aws:PrincipalOrgID on behalf of the user that is being validated
		case "aws:CurrentTime":
			currentTime := time.Now().UTC().Format(time.RFC3339)
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   util.Ptr("aws:CurrentTime"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{currentTime},
			})
		case "aws:EpochTime":
			epochTime := strconv.Itoa(int(time.Now().UTC().Unix()))
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   util.Ptr("aws:EpochTime"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{epochTime},
			})
		default:
			log.V(0).Info("Value for context key not fetched. SCP simulation results might be inaccurate", ctxKey, "")
		}
	}

	return ctxEntries
}

// ReconcileIAMGroupRule reconciles an IAM group validation rule from an AWSValidator config
// nolint:dupl
func (s *RuleService) ReconcileIAMGroupRule(rule iamRule) (*types.ValidationRuleResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := validators.BuildValidationResult(
		rule.Name(), resultMessage(constants.ValidationTypeIAMGroupPolicy), constants.ValidationTypeIAMGroupPolicy,
	)

	group, err := s.iamSvc.GetGroup(context.Background(), &iam.GetGroupInput{
		GroupName: util.Ptr(rule.Name()),
	})
	if err != nil {
		return vr, err
	}

	policyDocs := rule.IAMPolicies()

	scpFailures, err := checkSCP(s.iamSvc, policyDocs, *group.Group.Arn, "group", *group.Group.GroupName, nil)
	if err != nil {
		return vr, err
	}

	// SCP related failures found. Exit early
	if len(scpFailures) > 0 {
		return getSCPFailedValidationResult(vr, scpFailures), nil
	}

	// Retrieve all IAM policies attached to the IAM user
	policies, err := s.iamSvc.ListAttachedGroupPolicies(context.Background(), &iam.ListAttachedGroupPoliciesInput{
		GroupName: util.Ptr(rule.Name()),
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

func getSCPFailedValidationResult(vr *types.ValidationRuleResult, failures []string) *types.ValidationRuleResult {
	vr.State = util.Ptr(vapi.ValidationFailed)
	vr.Condition.Failures = failures
	vr.Condition.Message = "One or more required SCP permissions was not found, or a condition was not met"
	vr.Condition.Status = corev1.ConditionFalse

	return vr
}

// ReconcileIAMPolicyRule reconciles an IAM policy validation rule from an AWSValidator config
func (s *RuleService) ReconcileIAMPolicyRule(rule iamRule) (*types.ValidationRuleResult, error) {

	// Build the default ValidationResult for this IAM rule
	vr := validators.BuildValidationResult(
		rule.Name(), resultMessage(constants.ValidationTypeIAMPolicy), constants.ValidationTypeIAMPolicy,
	)

	// Build map of required permissions
	permissions := buildPermissions(rule)

	// Update the permission map for the IAM policy
	context := []string{"policy", rule.Name()}
	policyDocument, err := s.getPolicyDocument(util.Ptr(rule.Name()), context)
	if err != nil {
		return vr, err
	}
	applyPolicy(policyDocument, permissions)

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

func checkSCP(iamSvc iamAPI, policyDocs []v1alpha1.PolicyDocument, policySourceArn string, policySourceType string, policySourceName string, ctxEntries []iamtypes.ContextEntry) ([]string, error) {
	var scpFailures []string

	for _, doc := range policyDocs {
		for _, statement := range doc.Statements {
			simulationInput := &iam.SimulatePrincipalPolicyInput{
				ActionNames:     statement.Actions,
				PolicySourceArn: util.Ptr(policySourceArn),
				ResourceArns:    statement.Resources,
				ContextEntries:  ctxEntries,
			}

			var marker *string
			var simResults []iamtypes.EvaluationResult
			for {
				simulationInput.Marker = marker

				simOutput, err := iamSvc.SimulatePrincipalPolicy(context.Background(), simulationInput)
				if err != nil {
					return nil, err
				}

				simResults = append(simResults, simOutput.EvaluationResults...)

				if simOutput.IsTruncated {
					marker = simOutput.Marker
					continue
				}
				break
			}

			for _, result := range simResults {
				// Not all simulation results will have this field (ie. when service control policies are not used).
				if result.OrganizationsDecisionDetail == nil {
					continue
				}
				if !result.OrganizationsDecisionDetail.AllowedByOrganizations && result.EvalDecision != "allowed" {
					// append SCP failure
					scpFailures = append(scpFailures, fmt.Sprintf("Action: %s is denied due to an Organization level SCP policy for %s: %s", *result.EvalActionName, policySourceType, policySourceName))
				}
			}
		}
	}

	return scpFailures, nil
}

// processPolicies updates an IAM permission map for each IAM policy in an array of IAM policies attached to a IAM user / group / role
func (s *RuleService) processPolicies(policies []iamtypes.AttachedPolicy, permissions map[string][]*permission, context []string) error {
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
func (s *RuleService) getPolicyDocument(policyArn *string, ctx []string) (*awspolicy.Policy, error) {
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
			if conditionSatisfied(s.Condition, permission.Condition) {
				permission.ConditionOk = true
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

// conditionSatisfied returns true if and only if all conditions on the ruleCondition are found in the policyCondition
func conditionSatisfied(policyCondition awspolicy.Condition, ruleCondition v1alpha1.Condition) bool {
	for rType, rConditionMap := range ruleCondition {
		pConditionMap, ok := policyCondition[rType]
		if !ok {
			return false
		}
		for rKey, rValues := range rConditionMap {
			pValues, ok := pConditionMap[rKey]
			if !ok {
				return false
			}
			for _, rv := range rValues {
				if !slices.Contains(pValues, rv) {
					return false
				}
			}
		}
	}
	return true
}

func updatePermissionAction(permission *permission, a iamAction, actionAllowed bool) {
	if _, ok := permission.Actions[a]; ok {
		permission.Actions[a] = actionAllowed
	}
}

// computeFailures derives IAM rule failures from an IAM permissions map once it has been fully updated
func computeFailures(rule iamRule, permissions map[string][]*permission, vr *types.ValidationRuleResult) {
	failures := make([]string, 0)
	missingActions := make(map[string]*missing)

	for resource, resourcePermissions := range permissions {
		for _, permission := range resourcePermissions {
			if len(permission.Errors) > 0 {
				failures = append(failures, util.DeDupeStrSlice(permission.Errors)...)
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

	// sort the missing actions list
	resources := make([]string, 0, len(missingActions))
	for key := range missingActions {
		resources = append(resources, key)
	}
	sort.Strings(resources)

	for _, resource := range resources {
		actions := missingActions[resource].Actions
		sort.Strings(actions)
		failureMsg := fmt.Sprintf(
			"%T %s missing action(s): %s for resource %s from policy %s",
			rule, rule.Name(), actions, resource, missingActions[resource].PolicyName,
		)
		failures = append(failures, failureMsg)
	}
	if len(failures) > 0 {
		slices.Sort(failures)
		vr.State = util.Ptr(vapi.ValidationFailed)
		vr.Condition.Failures = failures
		vr.Condition.Message = "One or more required IAM permissions was not found, or a condition was not met"
		vr.Condition.Status = corev1.ConditionFalse
	}
}

func resultMessage(validationType string) string {
	return fmt.Sprintf("All required %s permissions were found", validationType)
}

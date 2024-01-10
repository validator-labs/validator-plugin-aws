package iam

import (
	"context"
	"errors"
	"fmt"
	awspolicy "github.com/L30Bola/aws-policy"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/go-logr/logr"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/constants"
	str_utils "github.com/spectrocloud-labs/validator-plugin-aws/internal/utils/strings"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	"github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
)

const AccountIDFromARNRegex = "arn:[a-z]*:[a-z]*::([?<AccountID>\\d{12}$]*):[0-9A-Za-z]*\\/[0-9A-Za-z]*"

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
	Actions    map[iamAction]bool
	Condition  *v1alpha1.Condition
	Errors     []string
	PolicyName string
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
	GetUser(ctx context.Context, params *iam.GetUserInput, optFns ...func(*iam.Options)) (*iam.GetUserOutput, error)
	GetGroup(ctx context.Context, params *iam.GetGroupInput, optFns ...func(*iam.Options)) (*iam.GetGroupOutput, error)
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
	GetContextKeysForPrincipalPolicy(ctx context.Context, params *iam.GetContextKeysForPrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error)
	ListAccountAliases(ctx context.Context, params *iam.ListAccountAliasesInput, optFns ...func(*iam.Options)) (*iam.ListAccountAliasesOutput, error)
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

	role, err := s.iamSvc.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: ptr.Ptr(rule.Name()),
	})

	policyDocs := rule.IAMPolicies()

	ctxKeys, err := s.iamSvc.GetContextKeysForPrincipalPolicy(context.Background(), &iam.GetContextKeysForPrincipalPolicyInput{
		PolicySourceArn: ptr.Ptr(*role.Role.Arn),
	})
	fmt.Println("CtxKeys: ", ctxKeys, err)

	ctxEntries, err := getContextEntries(s.log, *role.Role.RoleName, *role.Role.RoleId, *role.Role.Arn, ctxKeys.ContextKeyNames)
	if err != nil {
		return nil, err
	}

	fmt.Println("CtxEntries: ", ctxEntries)

	scpFailures, err := checkSCP(s.iamSvc, policyDocs, *role.Role.Arn, "role", *role.Role.RoleName, nil)
	if err != nil {
		return vr, err
	}

	// SCP related failures found. Exit early
	if len(scpFailures) > 0 {
		return getSCPFailedValidationResult(vr, scpFailures), nil
	}

	// Retrieve all IAM policies attached to the IAM role
	policies, err := s.iamSvc.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
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
func (s *IAMRuleService) ReconcileIAMUserRule(rule iamRule) (*types.ValidationResult, error) {
	//var ctxEntries []iamtypes.ContextEntry

	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMUserPolicy)

	user, err := s.iamSvc.GetUser(context.Background(), &iam.GetUserInput{
		UserName: ptr.Ptr(rule.Name()),
	})

	policyDocs := rule.IAMPolicies()

	ctxKeys, err := s.iamSvc.GetContextKeysForPrincipalPolicy(context.Background(), &iam.GetContextKeysForPrincipalPolicyInput{
		PolicySourceArn: ptr.Ptr(*user.User.Arn),
	})
	fmt.Println("CtxKeys: ", ctxKeys, err)

	ctxEntries, err := getContextEntries(s.log, *user.User.UserName, *user.User.UserId, *user.User.Arn, ctxKeys.ContextKeyNames)
	if err != nil {
		return nil, err
	}

	fmt.Println("CtxEntries: ", ctxEntries)

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

func getAccountIDFromARN(arn string) (string, error) {
	re := regexp.MustCompile(AccountIDFromARNRegex)
	matches := re.FindStringSubmatch(arn)

	if matches == nil || len(matches) < 2 {
		return "", errors.New("error getting org ID from Account ARN")
	}

	//return first captured group - Account ID
	return matches[1], nil
}

func getContextEntries(log logr.Logger, entityName, entityID, entityARN string, contextKeys []string) ([]iamtypes.ContextEntry, error) {
	var ctxEntries []iamtypes.ContextEntry

	for _, ctxKey := range contextKeys {
		switch ctxKey {
		case "aws:username":
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   ptr.Ptr("aws:username"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{entityName},
			})
		case "aws:userid":
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   ptr.Ptr("aws:userid"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{entityID},
			})
		case "aws:PrincipalArn":
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   ptr.Ptr("aws:PrincipalArn"),
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
				ContextKeyName:   ptr.Ptr("aws:PrincipalAccount"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{accID},
			})
		// TODO: Check a way to get aws:PrincipalOrgID on behalf of the user that is being validated
		case "aws:CurrentTime":
			currentTime := time.Now().UTC().Format(time.RFC3339)
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   ptr.Ptr("aws:CurrentTime"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{currentTime},
			})
		case "aws:EpochTime":
			epochTime := strconv.Itoa(int(time.Now().UTC().Unix()))
			ctxEntries = append(ctxEntries, iamtypes.ContextEntry{
				ContextKeyName:   ptr.Ptr("aws:EpochTime"),
				ContextKeyType:   "string",
				ContextKeyValues: []string{epochTime},
			})
		default:
			log.V(0).Info("Value for context key not fetched. SCP simulation results might be inaccurate", ctxKey, "")
		}
	}

	return ctxEntries, nil
}

// ReconcileIAMGroupRule reconciles an IAM group validation rule from an AWSValidator config
func (s *IAMRuleService) ReconcileIAMGroupRule(rule iamRule) (*types.ValidationResult, error) {
	// Build the default ValidationResult for this IAM rule
	vr := buildValidationResult(rule, constants.ValidationTypeIAMGroupPolicy)

	group, err := s.iamSvc.GetGroup(context.Background(), &iam.GetGroupInput{
		GroupName: ptr.Ptr(rule.Name()),
	})

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

func getSCPFailedValidationResult(vr *types.ValidationResult, failures []string) *types.ValidationResult {
	vr.State = ptr.Ptr(vapi.ValidationFailed)
	vr.Condition.Failures = failures
	vr.Condition.Message = "One or more required SCP permissions was not found, or a condition was not met"
	vr.Condition.Status = corev1.ConditionFalse

	return vr
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
	updatePermissions(policyDocument, permissions)

	// Compute failures and update the latest condition accordingly
	computeFailures(rule, permissions, vr)

	return vr, nil
}

func checkSCP(iamSvc iamApi, policyDocs []v1alpha1.PolicyDocument, policySourceArn string, policySourceType string, policySourceName string, ctxEntries []iamtypes.ContextEntry) ([]string, error) {
	var scpFailures []string

	for _, doc := range policyDocs {
		for _, statement := range doc.Statements {
			simulationInput := &iam.SimulatePrincipalPolicyInput{
				ActionNames:     statement.Actions,
				PolicySourceArn: ptr.Ptr(policySourceArn),
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

			fmt.Println("Sim eval results", simResults)

			for _, result := range simResults {
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
func (s *IAMRuleService) processPolicies(policies []iamtypes.AttachedPolicy, permissions map[string]*permission, context []string) error {
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
func buildPermissions(rule iamRule) map[string]*permission {
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
		// proceed only if access is allowed to resources
		if s.Effect != "Allow" {
			continue
		}

		for _, resource := range s.Resource {
			// for resource, check if the resource already exists in the permission map
			permission, ok := permissions[resource]

			// if the resource already exists in the permission map
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

				// iterate over the actions
				for _, action := range s.Action {
					// iamAction is a service-verb struct
					iamAction := toIAMAction(action)
					permission.Actions[iamAction] = true

					// if both service and verb are '*'
					if iamAction.IsAdmin() {
						// mark all permissions found & exit early
						for a := range permission.Actions {
							permission.Actions[a] = true
						}
						return
					}

					// if verb for that service is '*'
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
func computeFailures(rule iamRule, permissions map[string]*permission, vr *types.ValidationResult) {
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
		vr.State = ptr.Ptr(vapi.ValidationFailed)
		vr.Condition.Failures = failures
		vr.Condition.Message = "One or more required IAM permissions was not found, or a condition was not met"
		vr.Condition.Status = corev1.ConditionFalse
	}
}

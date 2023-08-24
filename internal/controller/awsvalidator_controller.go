/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	awspolicy "github.com/L30Bola/aws-policy"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

const validReasonPrefix string = "validation"

// AwsValidatorReconciler reconciles a AwsValidator object
type AwsValidatorReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=awsvalidators,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=awsvalidators/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=awsvalidators/finalizers,verbs=update

// Reconcile reconciles each rule found in each AWSValidator in the cluster and creates ValidationResults accordingly
func (r *AwsValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.V(0).Info("Reconciling AwsValidator", "name", req.Name, "namespace", req.Namespace)

	validator := &v1alpha1.AwsValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		// ignore not-found errors, since they can't be fixed by an immediate requeue
		if apierrs.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "failed to fetch AwsValidator")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var awsCreds *credentials.Credentials
	var res *ctrl.Result
	if validator.Spec.Auth.SecretName != "" {
		awsCreds, res = r.secretKeyAuth(req, validator)
		if res != nil {
			return *res, nil
		}
	} else if validator.Spec.Auth.ServiceAccountName != "" {
		// TODO: EKS service account auth
		r.Log.V(0).Info("WARNING: service account auth not implemented")
	}

	// get the active validator's validation result
	vr := &valid8orv1alpha1.ValidationResult{}
	nn := types.NamespacedName{
		Name:      fmt.Sprintf("valid8or-plugin-aws-%s", validator.Name),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		res, err := r.handleExistingValidationResult(nn, vr)
		if res != nil {
			return *res, err
		}
	} else {
		if !apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		}
		res, err := r.handleNewValidationResult(nn, vr)
		if res != nil {
			return *res, err
		}
	}

	// execute validation
	session, err := session.NewSession(&aws.Config{
		Credentials: awsCreds,
		MaxRetries:  aws.Int(3),
	})
	if err != nil {
		// allow flow to proceed - better errors will surface subsequently
		r.Log.V(0).Error(err, "failed to establish AWS session")
	}

	for _, rule := range validator.Spec.IamRules {
		if err := r.reconcileIAMRule(nn, rule, session); err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM rule")
		}
	}
	for _, rule := range validator.Spec.TagRules {
		if err := r.reconcileTagRule(nn, rule, session); err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AwsValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AwsValidator{}).
		Complete(r)
}

// secretKeyAuth creates AWS credentials from a secret containing an access key id and secret access key
func (r *AwsValidatorReconciler) secretKeyAuth(req ctrl.Request, validator *v1alpha1.AwsValidator) (*credentials.Credentials, *reconcile.Result) {
	authSecret := &corev1.Secret{}
	nn := types.NamespacedName{Name: validator.Spec.Auth.SecretName, Namespace: req.Namespace}

	if err := r.Get(context.Background(), nn, authSecret); err != nil {
		if apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "auth secret does not exist", "name", validator.Spec.Auth.SecretName, "namespace", req.Namespace)
		} else {
			r.Log.V(0).Error(err, "failed to fetch auth secret")
		}
		r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
		return nil, &ctrl.Result{RequeueAfter: time.Second * 120}
	}

	id, ok := authSecret.Data["AWS_ACCESS_KEY_ID"]
	if !ok {
		r.Log.V(0).Info("Auth secret missing AWS_ACCESS_KEY_ID", "name", validator.Spec.Auth.SecretName, "namespace", req.Namespace)
		r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
		return nil, &ctrl.Result{RequeueAfter: time.Second * 120}
	}

	secretKey, ok := authSecret.Data["AWS_SECRET_ACCESS_KEY"]
	if !ok {
		r.Log.V(0).Info("Auth secret missing AWS_SECRET_ACCESS_KEY", "name", validator.Spec.Auth.SecretName, "namespace", req.Namespace)
		r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
		return nil, &ctrl.Result{RequeueAfter: time.Second * 120}
	}

	return credentials.NewStaticCredentials(string(id), string(secretKey), ""), nil
}

// getAwsServices creates AWS service objects for a specific session and region
func (r *AwsValidatorReconciler) getAwsServices(session *session.Session, region string) (*ec2.EC2, *iam.IAM) {
	config := &aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}
	ec2Svc := ec2.New(session, config)
	iamSvc := iam.New(session, config)
	return ec2Svc, iamSvc
}

// handleExistingValidationResult processes a preexisting validation result for the active validator
func (r *AwsValidatorReconciler) handleExistingValidationResult(nn types.NamespacedName, vr *valid8orv1alpha1.ValidationResult) (*ctrl.Result, error) {
	switch vr.Status.State {

	case valid8orv1alpha1.ValidationInProgress:
		// validations are only left in progress if an unexpected error occurred
		r.Log.V(0).Info("Previous validation failed with unexpected error", "name", nn.Name, "namespace", nn.Namespace)

	case valid8orv1alpha1.ValidationFailed:
		// log validation failure, but continue and retry
		cs := getInvalidConditions(vr.Status.Conditions)
		if len(cs) > 0 {
			for _, c := range cs {
				r.Log.V(0).Info(
					"Validation failed. Retrying.", "name", nn.Name, "namespace", nn.Namespace,
					"validation", c.Reason, "error", c.Message, "failures", c.Failures,
				)
			}
		}

	case valid8orv1alpha1.ValidationSucceeded:
		// log validation success, continue to re-validate
		r.Log.V(0).Info("Previous validation succeeded. Re-validating.", "name", nn.Name, "namespace", nn.Namespace)
	}

	return nil, nil
}

// handleNewValidationResult creates a new validation result for the active validator
func (r *AwsValidatorReconciler) handleNewValidationResult(nn types.NamespacedName, vr *valid8orv1alpha1.ValidationResult) (*ctrl.Result, error) {

	// Create the ValidationResult
	vr.ObjectMeta = metav1.ObjectMeta{
		Name:      nn.Name,
		Namespace: nn.Namespace,
	}
	vr.Spec = valid8orv1alpha1.ValidationResultSpec{
		Plugin: "AWS",
	}
	if err := r.Client.Create(context.Background(), vr, &client.CreateOptions{}); err != nil {
		r.Log.V(0).Error(err, "failed to create ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		return &ctrl.Result{}, err
	}

	// Update the ValidationResult's status
	if err := r.Get(context.Background(), nn, vr); err != nil {
		r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
	}
	vr.Status = valid8orv1alpha1.ValidationResultStatus{
		State: valid8orv1alpha1.ValidationInProgress,
		Conditions: []valid8orv1alpha1.ValidationCondition{
			{
				Reason:             "Created",
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.Time{Time: time.Now()},
			},
		},
	}
	if err := r.Status().Update(context.Background(), vr); err != nil {
		r.Log.V(0).Error(err, "failed to update ValidationResult status", "name", nn.Name, "namespace", nn.Namespace)
		return &ctrl.Result{}, err
	}

	return nil, nil
}

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
func (r *AwsValidatorReconciler) reconcileIAMRule(nn types.NamespacedName, rule v1alpha1.IamRule, s *session.Session) error {
	_, iamSvc := r.getAwsServices(s, "")

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
		r.Log.V(0).Error(err, "failed to list policies for IAM role", "role", rule.IamRole)
		return err
	}
	for _, p := range policies.AttachedPolicies {
		// Fetch the IAM policy's policy document
		policyOutput, err := iamSvc.GetPolicy(&iam.GetPolicyInput{
			PolicyArn: p.PolicyArn,
		})
		if err != nil {
			r.Log.V(0).Error(err, "failed to get IAM policy", "role", rule.IamRole, "policyArn", p.PolicyArn)
			return err
		}
		policyVersionOutput, err := iamSvc.GetPolicyVersion(&iam.GetPolicyVersionInput{
			PolicyArn: p.PolicyArn,
			VersionId: policyOutput.Policy.DefaultVersionId,
		})
		if err != nil {
			r.Log.V(0).Error(err, "failed to get IAM policy version", "policyArn", p.PolicyArn, "versionId", policyOutput.Policy.DefaultVersionId)
			return err
		}

		// Parse the policy document
		if policyVersionOutput.PolicyVersion.Document == nil {
			r.Log.V(0).Info("Skipping IAM policy with empty permissions", "policyArn", p.PolicyArn, "versionId", policyOutput.Policy.DefaultVersionId)
			continue
		}
		policyUnescaped, err := url.QueryUnescape(*policyVersionOutput.PolicyVersion.Document)
		if err != nil {
			r.Log.V(0).Error(err, "failed to decode IAM policy document", "policyArn", p.PolicyArn, "versionId", policyOutput.Policy.DefaultVersionId)
			return err
		}
		policyDocument := &awspolicy.Policy{}
		if err := policyDocument.UnmarshalJSON([]byte(policyUnescaped)); err != nil {
			r.Log.V(0).Error(err, "failed to unmarshal IAM policy", "role", rule.IamRole, "policyArn", p.PolicyArn)
			return err
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
						errMsg := fmt.Sprintf("Resource '%s' missing condition '%s'", resource, permission.Condition)
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
			failures = append(failures, dedupeStrSlice(permission.Errors)...)
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
			"IAM role '%s' missing action(s): %s for resource '%s' from policy '%s",
			rule.IamRole, missing.Actions, resource, missing.PolicyName,
		)
		failures = append(failures, failure)
	}

	// Build the latest condition for this IAM rule
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := defaultValidationCondition()
	latestCondition.Message = "All required IAM permissions were found"
	latestCondition.Reason = fmt.Sprintf("%s-%s", validReasonPrefix, rule.IamRole)

	if len(failures) > 0 {
		state = valid8orv1alpha1.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "One or more required IAM permissions was not found, or a condition was not met"
		latestCondition.Status = corev1.ConditionFalse
	}

	return r.updateValidationResult(nn, latestCondition, state)
}

// reconcileTagRule reconciles an EC2 tagging validation rule from the AWSValidator config
func (r *AwsValidatorReconciler) reconcileTagRule(nn types.NamespacedName, rule v1alpha1.TagRule, s *session.Session) error {
	ec2Svc, _ := r.getAwsServices(s, rule.Region)

	// Build the default latest condition for this tag rule
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := defaultValidationCondition()
	latestCondition.Message = "All required subnet tags were found"
	latestCondition.Reason = fmt.Sprintf("%s-%s-%s", validReasonPrefix, rule.ResourceType, rule.Key)

	switch rule.ResourceType {
	case "subnet":
		// match the tag rule's list of ARNs against the subnets with tag 'rule.Key=rule.ExpectedValue'
		failures := make([]string, 0)
		foundArns := make(map[string]bool)
		subnets, err := ec2Svc.DescribeSubnets(&ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", rule.Key)),
					Values: []*string{aws.String(rule.ExpectedValue)},
				},
			},
		})
		if err != nil {
			r.Log.V(0).Error(err, "failed to describe subnets", "region", rule.Region)
			return err
		}
		for _, s := range subnets.Subnets {
			if s.SubnetArn != nil {
				foundArns[*s.SubnetArn] = true
			}
		}
		for _, arn := range rule.ARNs {
			_, ok := foundArns[arn]
			if !ok {
				failures = append(failures, fmt.Sprintf("Subnet with ARN '%s' missing tag '%s=%s'", arn, rule.Key, rule.ExpectedValue))
			}
		}
		if len(failures) > 0 {
			state = valid8orv1alpha1.ValidationFailed
			latestCondition.Failures = failures
			latestCondition.Message = "One or more required subnet tags was not found"
			latestCondition.Status = corev1.ConditionFalse
		}
	default:
		return fmt.Errorf("unsupported resourceType '%s' for TagRule", rule.ResourceType)
	}

	return r.updateValidationResult(nn, latestCondition, state)
}

// updateValidationResult updates the ValidationResult for the active validation rule
func (r *AwsValidatorReconciler) updateValidationResult(
	nn types.NamespacedName, c valid8orv1alpha1.ValidationCondition, state valid8orv1alpha1.ValidationState,
) error {
	vr := &valid8orv1alpha1.ValidationResult{}
	if err := r.Get(context.Background(), nn, vr); err != nil {
		return fmt.Errorf("failed to get ValidationResult '%s' in namespace '%s': %v", nn.Name, nn.Namespace, err)
	}
	vr.Status.State = state

	idx := getConditionIndexByReason(vr.Status.Conditions, c.Reason)
	if idx == -1 {
		vr.Status.Conditions = append(vr.Status.Conditions, c)
	} else {
		vr.Status.Conditions[idx] = c
	}

	if err := r.Status().Update(context.Background(), vr); err != nil {
		r.Log.V(0).Error(err, "failed to update ValidationResult")
		return err
	}
	r.Log.V(0).Info(
		"Updated ValidationResult", "state", state, "reason", c.Reason,
		"message", c.Message, "failures", c.Failures, "time", c.LastTransitionTime,
	)

	return nil
}

// defaultCondition returns a default validation condition
func defaultValidationCondition() valid8orv1alpha1.ValidationCondition {
	return valid8orv1alpha1.ValidationCondition{
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: time.Now()},
	}
}

// getInvalidConditions filters a ValidationCondition array and returns all conditions corresponding to a failed validation
func getInvalidConditions(conditions []valid8orv1alpha1.ValidationCondition) []valid8orv1alpha1.ValidationCondition {
	invalidConditions := make([]valid8orv1alpha1.ValidationCondition, 0)
	for _, c := range conditions {
		if strings.HasPrefix(c.Reason, validReasonPrefix) && c.Status == corev1.ConditionFalse {
			invalidConditions = append(invalidConditions, c)
		}
	}
	return invalidConditions
}

// getConditionIndexByReason retrieves the index of a condition from a ValidationCondition array matching a specific reason
func getConditionIndexByReason(conditions []valid8orv1alpha1.ValidationCondition, reason string) int {
	for i, c := range conditions {
		if c.Reason == reason {
			return i
		}
	}
	return -1
}

// dedupeStrSlice deduplicates a slices of strings
func dedupeStrSlice(ss []string) []string {
	found := make(map[string]bool)
	l := []string{}
	for _, s := range ss {
		if _, ok := found[s]; !ok {
			found[s] = true
			l = append(l, s)
		}
	}
	return l
}

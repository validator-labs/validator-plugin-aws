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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/iam"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/servicequota"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/tag"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/types"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

// AwsValidatorReconciler reconciles a AwsValidator object
type AwsValidatorReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

type monotonicBool struct {
	ok bool
}

func (m *monotonicBool) Update(ok bool) {
	m.ok = !ok || m.ok
}

//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=awsvalidators,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=awsvalidators/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=awsvalidators/finalizers,verbs=update

// Reconcile reconciles each rule found in each AWSValidator in the cluster and creates ValidationResults accordingly
func (r *AwsValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.V(0).Info("Reconciling AwsValidator", "name", req.Name, "namespace", req.Namespace)

	validator := &v1alpha1.AwsValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		// Ignore not-found errors, since they can't be fixed by an immediate requeue
		if apierrs.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "failed to fetch AwsValidator")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Initialize AWS session
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
	session, err := session.NewSession(&aws.Config{
		Credentials: awsCreds,
		MaxRetries:  aws.Int(3),
	})
	if err != nil {
		// allow flow to proceed - better errors will surface subsequently
		r.Log.V(0).Error(err, "failed to establish AWS session")
	}

	// Get the active validator's validation result
	vr := &valid8orv1alpha1.ValidationResult{}
	nn := k8stypes.NamespacedName{
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

	failed := &monotonicBool{}

	// IAM rules
	for _, rule := range validator.Spec.IamRules {
		validationResult, err := iam.ReconcileIAMRule(nn, rule, session, r.Log)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM rule")
		}
		r.safeUpdateValidationResult(nn, *validationResult, failed)
	}

	// Service Quota rules
	for _, rule := range validator.Spec.ServiceQuotaRules {
		validationResult, err := servicequota.ReconcileServiceQuotaRule(nn, rule, session, r.Log)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Service Quota rule")
		}
		r.safeUpdateValidationResult(nn, *validationResult, failed)
	}

	// Tag rules
	for _, rule := range validator.Spec.TagRules {
		validationResult, err := tag.ReconcileTagRule(nn, rule, session, r.Log)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
		r.safeUpdateValidationResult(nn, *validationResult, failed)
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

// safeUpdateValidationResult updates the overall validation result, ensuring that the overall validation status remains failed if a single rule fails
func (r *AwsValidatorReconciler) safeUpdateValidationResult(nn k8stypes.NamespacedName, validationResult types.ValidationResult, failed *monotonicBool) {
	didFail := validationResult.State == valid8orv1alpha1.ValidationFailed
	failed.Update(didFail)
	if failed.ok && !didFail {
		validationResult.State = valid8orv1alpha1.ValidationFailed
	}
	if err := r.updateValidationResult(nn, validationResult); err != nil {
		r.Log.V(0).Error(err, "failed to update ValidationResult")
	}
}

// secretKeyAuth creates AWS credentials from a secret containing an access key id and secret access key
func (r *AwsValidatorReconciler) secretKeyAuth(req ctrl.Request, validator *v1alpha1.AwsValidator) (*credentials.Credentials, *reconcile.Result) {
	authSecret := &corev1.Secret{}
	nn := k8stypes.NamespacedName{Name: validator.Spec.Auth.SecretName, Namespace: req.Namespace}

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

// handleExistingValidationResult processes a preexisting validation result for the active validator
func (r *AwsValidatorReconciler) handleExistingValidationResult(nn k8stypes.NamespacedName, vr *valid8orv1alpha1.ValidationResult) (*ctrl.Result, error) {
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
					"validation", c.ValidationRule, "error", c.Message, "details", c.Details, "failures", c.Failures,
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
func (r *AwsValidatorReconciler) handleNewValidationResult(nn k8stypes.NamespacedName, vr *valid8orv1alpha1.ValidationResult) (*ctrl.Result, error) {

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
	vr.Status = valid8orv1alpha1.ValidationResultStatus{
		State: valid8orv1alpha1.ValidationInProgress,
	}
	if err := r.Status().Update(context.Background(), vr); err != nil {
		r.Log.V(0).Error(err, "failed to update ValidationResult status", "name", nn.Name, "namespace", nn.Namespace)
		return &ctrl.Result{}, err
	}

	return nil, nil
}

// updateValidationResult updates the ValidationResult for the active validation rule
func (r *AwsValidatorReconciler) updateValidationResult(nn k8stypes.NamespacedName, res types.ValidationResult) error {
	vr := &valid8orv1alpha1.ValidationResult{}
	if err := r.Get(context.Background(), nn, vr); err != nil {
		return fmt.Errorf("failed to get ValidationResult %s in namespace %s: %v", nn.Name, nn.Namespace, err)
	}
	vr.Status.State = res.State

	idx := getConditionIndexByValidationRule(vr.Status.Conditions, res.Condition.ValidationRule)
	if idx == -1 {
		vr.Status.Conditions = append(vr.Status.Conditions, res.Condition)
	} else {
		vr.Status.Conditions[idx] = res.Condition
	}

	if err := r.Status().Update(context.Background(), vr); err != nil {
		r.Log.V(0).Error(err, "failed to update ValidationResult")
		return err
	}
	r.Log.V(0).Info(
		"Updated ValidationResult", "state", res.State, "reason", res.Condition.ValidationRule,
		"message", res.Condition.Message, "details", res.Condition.Details,
		"failures", res.Condition.Failures, "time", res.Condition.LastValidationTime,
	)

	return nil
}

// getInvalidConditions filters a ValidationCondition array and returns all conditions corresponding to a failed validation
func getInvalidConditions(conditions []valid8orv1alpha1.ValidationCondition) []valid8orv1alpha1.ValidationCondition {
	invalidConditions := make([]valid8orv1alpha1.ValidationCondition, 0)
	for _, c := range conditions {
		if strings.HasPrefix(c.ValidationRule, constants.ValidationRulePrefix) && c.Status == corev1.ConditionFalse {
			invalidConditions = append(invalidConditions, c)
		}
	}
	return invalidConditions
}

// getConditionIndexByValidationRule retrieves the index of a condition from a ValidationCondition array matching a specific reason
func getConditionIndexByValidationRule(conditions []valid8orv1alpha1.ValidationCondition, validationRule string) int {
	for i, c := range conditions {
		if c.ValidationRule == validationRule {
			return i
		}
	}
	return -1
}

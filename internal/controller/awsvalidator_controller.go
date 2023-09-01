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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	aws_utils "github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/aws"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/validators/iam"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/validators/servicequota"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/validators/tag"
	v8or "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or/pkg/types"
	v8ores "github.com/spectrocloud-labs/valid8or/pkg/validationresult"
)

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
	iamRuleService := iam.NewIAMRuleService(r.Log, aws_utils.IAMService(session))
	svcQuotaService := servicequota.NewServiceQuotaRuleService(r.Log, session)
	tagRuleService := tag.NewTagRuleService(r.Log, session)

	// Get the active validator's validation result
	vr := &v8or.ValidationResult{}
	nn := ktypes.NamespacedName{
		Name:      fmt.Sprintf("valid8or-plugin-aws-%s", validator.Name),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		res, err := v8ores.HandleExistingValidationResult(nn, vr, r.Log)
		if res != nil {
			return *res, err
		}
	} else {
		if !apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		}
		res, err := v8ores.HandleNewValidationResult(r.Client, constants.PluginCode, nn, vr, r.Log)
		if res != nil {
			return *res, err
		}
	}

	failed := &types.MonotonicBool{}

	// IAM rules
	for _, rule := range validator.Spec.IamRoleRules {
		validationResult, err := iamRuleService.ReconcileIAMRoleRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM role rule")
		}
		v8ores.SafeUpdateValidationResult(r.Client, nn, validationResult, failed, err, r.Log)
	}
	for _, rule := range validator.Spec.IamUserRules {
		validationResult, err := iamRuleService.ReconcileIAMUserRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM user rule")
		}
		v8ores.SafeUpdateValidationResult(r.Client, nn, validationResult, failed, err, r.Log)
	}
	for _, rule := range validator.Spec.IamGroupRules {
		validationResult, err := iamRuleService.ReconcileIAMGroupRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM group rule")
		}
		v8ores.SafeUpdateValidationResult(r.Client, nn, validationResult, failed, err, r.Log)
	}
	for _, rule := range validator.Spec.IamPolicyRules {
		validationResult, err := iamRuleService.ReconcileIAMPolicyRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM policy rule")
		}
		v8ores.SafeUpdateValidationResult(r.Client, nn, validationResult, failed, err, r.Log)
	}

	// Service Quota rules
	for _, rule := range validator.Spec.ServiceQuotaRules {
		validationResult, err := svcQuotaService.ReconcileServiceQuotaRule(nn, rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Service Quota rule")
		}
		v8ores.SafeUpdateValidationResult(r.Client, nn, validationResult, failed, err, r.Log)
	}

	// Tag rules
	for _, rule := range validator.Spec.TagRules {
		validationResult, err := tagRuleService.ReconcileTagRule(nn, rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
		v8ores.SafeUpdateValidationResult(r.Client, nn, validationResult, failed, err, r.Log)
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
	nn := ktypes.NamespacedName{Name: validator.Spec.Auth.SecretName, Namespace: req.Namespace}

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

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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/constants"
	aws_utils "github.com/spectrocloud-labs/validator-plugin-aws/internal/utils/aws"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/validators/iam"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/validators/servicequota"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/validators/tag"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	vres "github.com/spectrocloud-labs/validator/pkg/validationresult"
)

var ErrSecretNameRequired = errors.New("auth.secretName is required")

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
		if !apierrs.IsNotFound(err) {
			r.Log.Error(err, "failed to fetch AwsValidator", "key", req)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Configure AWS environment variable credentials from a secret, if applicable
	if !validator.Spec.Auth.Implicit {
		if validator.Spec.Auth.SecretName == "" {
			r.Log.Error(ErrSecretNameRequired, "failed to reconcile AwsValidator with empty auth.secretName", "key", req)
			return ctrl.Result{}, ErrSecretNameRequired
		}
		if err := r.envFromSecret(validator.Spec.Auth.SecretName, req.Namespace); err != nil {
			r.Log.Error(err, "failed to configure environment from secret")
			return ctrl.Result{}, err
		}
	}

	// Get the active validator's validation result
	vr := &vapi.ValidationResult{}
	nn := ktypes.NamespacedName{
		Name:      validationResultName(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExistingValidationResult(nn, vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		}
		if err := vres.HandleNewValidationResult(r.Client, buildValidationResult(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
	}

	// IAM rules
	awsApi, err := aws_utils.NewAwsApi(r.Log, validator.Spec.Auth, validator.Spec.DefaultRegion)
	if err != nil {
		r.Log.V(0).Error(err, "failed to get AWS client")
	} else {
		iamRuleService := iam.NewIAMRuleService(r.Log, awsApi.IAM)

		for _, rule := range validator.Spec.IamRoleRules {
			validationResult, err := iamRuleService.ReconcileIAMRoleRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM role rule")
			}
			vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
		}
		for _, rule := range validator.Spec.IamUserRules {
			validationResult, err := iamRuleService.ReconcileIAMUserRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM user rule")
			}
			vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
		}
		for _, rule := range validator.Spec.IamGroupRules {
			validationResult, err := iamRuleService.ReconcileIAMGroupRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM group rule")
			}
			vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
		}
		for _, rule := range validator.Spec.IamPolicyRules {
			validationResult, err := iamRuleService.ReconcileIAMPolicyRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM policy rule")
			}
			vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
		}
	}

	// Service Quota rules
	for _, rule := range validator.Spec.ServiceQuotaRules {
		awsApi, err := aws_utils.NewAwsApi(r.Log, validator.Spec.Auth, rule.Region)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Service Quota rule")
			continue
		}
		svcQuotaService := servicequota.NewServiceQuotaRuleService(
			r.Log,
			awsApi.EC2,
			awsApi.EFS,
			awsApi.ELB,
			awsApi.ELBV2,
			awsApi.SQ,
		)
		validationResult, err := svcQuotaService.ReconcileServiceQuotaRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Service Quota rule")
		}
		vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
	}

	// Tag rules
	for _, rule := range validator.Spec.TagRules {
		awsApi, err := aws_utils.NewAwsApi(r.Log, validator.Spec.Auth, rule.Region)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
			continue
		}
		tagRuleService := tag.NewTagRuleService(r.Log, awsApi.EC2)
		validationResult, err := tagRuleService.ReconcileTagRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
		vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// envFromSecret sets environment variables from a secret to configure AWS credentials
func (r *AwsValidatorReconciler) envFromSecret(name, namespace string) error {
	r.Log.Info("Configuring environment from secret", "name", name, "namespace", namespace)

	nn := ktypes.NamespacedName{Name: name, Namespace: namespace}
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), nn, secret); err != nil {
		return err
	}

	for k, v := range secret.Data {
		if err := os.Setenv(k, string(v)); err != nil {
			return err
		}
		r.Log.Info("Set environment variable", "key", k)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AwsValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AwsValidator{}).
		Complete(r)
}

func buildValidationResult(validator *v1alpha1.AwsValidator) *vapi.ValidationResult {
	return &vapi.ValidationResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      validationResultName(validator),
			Namespace: validator.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: validator.APIVersion,
					Kind:       validator.Kind,
					Name:       validator.Name,
					UID:        validator.UID,
					Controller: ptr.Ptr(true),
				},
			},
		},
		Spec: vapi.ValidationResultSpec{
			Plugin:          constants.PluginCode,
			ExpectedResults: validator.Spec.ResultCount(),
		},
	}
}

func validationResultName(validator *v1alpha1.AwsValidator) string {
	return fmt.Sprintf("validator-plugin-aws-%s", validator.Name)
}

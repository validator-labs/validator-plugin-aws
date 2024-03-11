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
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/constants"
	aws_utils "github.com/spectrocloud-labs/validator-plugin-aws/internal/utils/aws"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/validators/iam"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/validators/servicequota"
	"github.com/spectrocloud-labs/validator-plugin-aws/internal/validators/tag"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util"
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
	l := r.Log.V(0).WithValues("name", req.Name, "namespace", req.Namespace)
	l.Info("Reconciling AwsValidator")

	validator := &v1alpha1.AwsValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "failed to fetch AwsValidator")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Configure AWS environment variable credentials from a secret, if applicable
	if !validator.Spec.Auth.Implicit {
		if validator.Spec.Auth.SecretName == "" {
			l.Error(ErrSecretNameRequired, "failed to reconcile AwsValidator with empty auth.secretName")
			return ctrl.Result{}, ErrSecretNameRequired
		}
		if err := r.envFromSecret(validator.Spec.Auth.SecretName, req.Namespace); err != nil {
			l.Error(err, "failed to configure environment from secret")
			return ctrl.Result{}, err
		}
	}

	// Get the active validator's validation result
	vr := &vapi.ValidationResult{}
	p, err := patch.NewHelper(vr, r.Client)
	if err != nil {
		l.Error(err, "failed to create patch helper")
		return ctrl.Result{}, err
	}
	nn := ktypes.NamespacedName{
		Name:      validationResultName(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExistingValidationResult(vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "unexpected error getting ValidationResult")
		}
		vr = buildValidationResult(validator)
		if err := vres.HandleNewValidationResult(ctx, r.Client, p, vr, r.Log); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Always update the expected result count in case the validator's rules have changed
	vr.Spec.ExpectedResults = validator.Spec.ResultCount()

	// IAM rules
	awsApi, err := aws_utils.NewAwsApi(r.Log, validator.Spec.Auth, validator.Spec.DefaultRegion)
	if err != nil {
		r.Log.V(0).Error(err, "failed to get AWS client")
	} else {
		iamRuleService := iam.NewIAMRuleService(r.Log, awsApi.IAM)

		for _, rule := range validator.Spec.IamRoleRules {
			vrr, err := iamRuleService.ReconcileIAMRoleRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM role rule")
			}
			r.safeUpdate(ctx, p, vr, vrr, err)
		}
		for _, rule := range validator.Spec.IamUserRules {
			vrr, err := iamRuleService.ReconcileIAMUserRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM user rule")
			}
			r.safeUpdate(ctx, p, vr, vrr, err)
		}
		for _, rule := range validator.Spec.IamGroupRules {
			vrr, err := iamRuleService.ReconcileIAMGroupRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM group rule")
			}
			r.safeUpdate(ctx, p, vr, vrr, err)
		}
		for _, rule := range validator.Spec.IamPolicyRules {
			vrr, err := iamRuleService.ReconcileIAMPolicyRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM policy rule")
			}
			r.safeUpdate(ctx, p, vr, vrr, err)
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
		vrr, err := svcQuotaService.ReconcileServiceQuotaRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Service Quota rule")
		}
		r.safeUpdate(ctx, p, vr, vrr, err)
	}

	// Tag rules
	for _, rule := range validator.Spec.TagRules {
		awsApi, err := aws_utils.NewAwsApi(r.Log, validator.Spec.Auth, rule.Region)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
			continue
		}
		tagRuleService := tag.NewTagRuleService(r.Log, awsApi.EC2)
		vrr, err := tagRuleService.ReconcileTagRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
		r.safeUpdate(ctx, p, vr, vrr, err)
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

func (r *AwsValidatorReconciler) safeUpdate(ctx context.Context, p vres.Patcher, vr *vapi.ValidationResult, vrr *types.ValidationRuleResult, vrrErr error) {
	vres.SafeUpdateValidationResult(ctx, p, vr, vrr, vrrErr, r.Log)
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
					Controller: util.Ptr(true),
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

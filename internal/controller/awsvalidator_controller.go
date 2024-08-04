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

// Package controller defines a controller for reconciling AWSValidator objects.
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

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/pkg/ami"
	"github.com/validator-labs/validator-plugin-aws/pkg/aws"
	"github.com/validator-labs/validator-plugin-aws/pkg/constants"
	"github.com/validator-labs/validator-plugin-aws/pkg/iam"
	"github.com/validator-labs/validator-plugin-aws/pkg/servicequota"
	"github.com/validator-labs/validator-plugin-aws/pkg/tag"
	validators "github.com/validator-labs/validator-plugin-aws/pkg/validate"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
	vres "github.com/validator-labs/validator/pkg/validationresult"
)

// ErrSecretNameRequired is returned when the auth.secretName field is empty.
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
		if err := vres.HandleNewValidationResult(ctx, r.Client, p, buildValidationResult(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	// Always update the expected result count in case the validator's rules have changed
	vr.Spec.ExpectedResults = validator.Spec.ResultCount()

	resp := types.ValidationResponse{
		ValidationRuleResults: make([]*types.ValidationRuleResult, 0, vr.Spec.ExpectedResults),
		ValidationRuleErrors:  make([]error, 0, vr.Spec.ExpectedResults),
	}

	// AMI rules
	for _, rule := range validator.Spec.AmiRules {
		awsAPI, err := aws.NewAPI(validator.Spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile AMI rule"
			r.Log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name, errMsg, constants.ValidationTypeAmi)
			resp.AddResult(vrr, err)
			continue
		}
		amiRuleService := ami.NewAmiRuleService(r.Log, awsAPI.EC2)
		vrr, err := amiRuleService.ReconcileAmiRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile AMI rule")
		}
		resp.AddResult(vrr, err)
	}

	// IAM rules
	awsAPI, err := aws.NewAPI(validator.Spec.Auth, validator.Spec.DefaultRegion)
	if err != nil {
		r.Log.V(0).Error(err, "failed to get AWS client")
	} else {
		iamRuleService := iam.NewIAMRuleService(r.Log, awsAPI.IAM)

		for _, rule := range validator.Spec.IamRoleRules {
			vrr, err := iamRuleService.ReconcileIAMRoleRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM role rule")
			}
			resp.AddResult(vrr, err)
		}
		for _, rule := range validator.Spec.IamUserRules {
			vrr, err := iamRuleService.ReconcileIAMUserRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM user rule")
			}
			resp.AddResult(vrr, err)
		}
		for _, rule := range validator.Spec.IamGroupRules {
			vrr, err := iamRuleService.ReconcileIAMGroupRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM group rule")
			}
			resp.AddResult(vrr, err)
		}
		for _, rule := range validator.Spec.IamPolicyRules {
			vrr, err := iamRuleService.ReconcileIAMPolicyRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile IAM policy rule")
			}
			resp.AddResult(vrr, err)
		}
	}

	// Service Quota rules
	for _, rule := range validator.Spec.ServiceQuotaRules {
		awsAPI, err := aws.NewAPI(validator.Spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile Service Quota rule"
			r.Log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name, errMsg, constants.ValidationTypeServiceQuota)
			resp.AddResult(vrr, err)
			continue
		}
		svcQuotaService := servicequota.NewServiceQuotaRuleService(
			r.Log,
			awsAPI.EC2,
			awsAPI.EFS,
			awsAPI.ELB,
			awsAPI.ELBV2,
			awsAPI.SQ,
		)
		vrr, err := svcQuotaService.ReconcileServiceQuotaRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Service Quota rule")
		}
		resp.AddResult(vrr, err)
	}

	// Tag rules
	for _, rule := range validator.Spec.TagRules {
		awsAPI, err := aws.NewAPI(validator.Spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile Tag rule"
			r.Log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name, errMsg, constants.ValidationTypeTag)
			resp.AddResult(vrr, err)
			continue
		}
		tagRuleService := tag.NewTagRuleService(r.Log, awsAPI.EC2)
		vrr, err := tagRuleService.ReconcileTagRule(rule)
		if err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
		resp.AddResult(vrr, err)
	}

	// Patch the ValidationResult with the latest ValidationRuleResults
	if err := vres.SafeUpdateValidationResult(ctx, p, vr, resp, r.Log); err != nil {
		return ctrl.Result{}, err
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

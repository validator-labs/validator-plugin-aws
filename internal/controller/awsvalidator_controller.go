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
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/pkg/validate"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vres "github.com/validator-labs/validator/pkg/validationresult"
)

var errInvalidAccessKeyID = errors.New("access key ID is invalid, must be a non-empty string")
var errInvalidSecretAccessKey = errors.New("secret access key is invalid, must be a non-empty string")

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

	// Ensure both AWS env vars are set.
	if err := r.configureAwsAuth(validator.Spec.Auth, req.Namespace, l); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set AWS auth env vars: %w", err)
	}

	// Get the active validator's validation result
	vr := &vapi.ValidationResult{}
	p, err := patch.NewHelper(vr, r.Client)
	if err != nil {
		l.Error(err, "failed to create patch helper")
		return ctrl.Result{}, err
	}
	nn := ktypes.NamespacedName{
		Name:      vres.Name(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExisting(vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "unexpected error getting ValidationResult")
		}
		if err := vres.HandleNew(ctx, r.Client, p, vres.Build(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	// Always update the expected result count in case the validator's rules have changed
	vr.Spec.ExpectedResults = validator.Spec.ResultCount()

	// Validate the rules
	resp := validate.Validate(validator.Spec, r.Log)

	// Patch the ValidationResult with the latest ValidationRuleResults
	if err := vres.SafeUpdate(ctx, p, vr, resp, r.Log); err != nil {
		return ctrl.Result{}, err
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// configureAwsAuth sets environment variables to control AWS authentication. Order of precedence
// for source:
// 1 - Kubernetes secret
// 2 - Specified inline in spec
// Returns an error if env vars couldn't be set for any reason.
func (r *AwsValidatorReconciler) configureAwsAuth(auth v1alpha1.AwsAuth, reqNamespace string, l logr.Logger) error {
	if auth.Implicit {
		l.Info("auth.implicit set to true. Skipping setting AWS env vars.")
		return nil
	}

	if auth.AccessKeyPair == nil {
		auth.AccessKeyPair = &v1alpha1.AccessKeyPair{}
	}

	// If Secret name provided, override any env var values with values from its data.
	if auth.SecretName != "" {
		l.Info("auth.secretName provided. Using Secret as source for any AWS env vars defined in its data.", "secretName", auth.SecretName, "secretNamespace", reqNamespace)
		nn := ktypes.NamespacedName{Name: auth.SecretName, Namespace: reqNamespace}
		secret := &corev1.Secret{}
		if err := r.Get(context.Background(), nn, secret); err != nil {
			return fmt.Errorf("failed to get Secret: %w", err)
		}
		if accessKeyID, ok := secret.Data["AWS_ACCESS_KEY_ID"]; ok {
			l.Info("Using access key ID from Secret.")
			auth.AccessKeyPair.AccessKeyID = string(accessKeyID)
		}
		if secretAccessKey, ok := secret.Data["AWS_SECRET_ACCESS_KEY"]; ok {
			l.Info("Using secret access key from Secret.")
			auth.AccessKeyPair.SecretAccessKey = string(secretAccessKey)
		}
	}

	// Validate values collected from inline config and/or Secret. We can't rely on CRD validation
	// for this because some of the values may have come from a Secret, and there is no way for the
	// Kube API to validate content in its data.
	if auth.AccessKeyPair.AccessKeyID == "" {
		return errInvalidAccessKeyID
	}
	if auth.AccessKeyPair.SecretAccessKey == "" {
		return errInvalidSecretAccessKey
	}

	// Log non-secret data for help with debugging. Don't log the secret access key.
	nonSecretData := map[string]string{
		"accesskeyId": auth.AccessKeyPair.AccessKeyID,
	}
	l.Info("Determined AWS auth data.", "nonSecretData", nonSecretData)

	// Use collected and validated values to set env vars.
	data := map[string]string{
		"AWS_ACCESS_KEY_ID":     auth.AccessKeyPair.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": auth.AccessKeyPair.SecretAccessKey,
	}
	for k, v := range data {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
		r.Log.Info("Set environment variable", "envVar", k)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AwsValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AwsValidator{}).
		Complete(r)
}

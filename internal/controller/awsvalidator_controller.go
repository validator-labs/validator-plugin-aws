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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	validationv1alpha1 "github.com/spectrocloud-labs/aws-validator/api/v1alpha1"
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

func (r *AwsValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.V(0).Info("Reconciling AwsValidator", "name", req.Name, "namespace", req.Namespace)

	validator := &validationv1alpha1.AwsValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		// ignore not-found errors, since they can't be fixed by an immediate requeue
		if apierrs.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "failed to fetch AwsValidator")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var awsCreds *credentials.Credentials
	if validator.Spec.Auth.SecretName != "" {
		authSecret := &corev1.Secret{}
		nn := types.NamespacedName{Name: validator.Spec.Auth.SecretName, Namespace: req.Namespace}
		if err := r.Get(ctx, nn, authSecret); err != nil {
			if apierrs.IsNotFound(err) {
				r.Log.V(0).Error(err, "auth secret does not exist", "name", validator.Spec.Auth.SecretName, "namespace", req.Namespace)
			} else {
				r.Log.V(0).Error(err, "failed to fetch auth secret")
			}
			r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
			return ctrl.Result{RequeueAfter: time.Second * 120}, nil
		}
		id, ok := authSecret.Data["AWS_ACCESS_KEY_ID"]
		if !ok {
			r.Log.V(0).Info("Auth secret missing AWS_ACCESS_KEY_ID", "name", validator.Spec.Auth.SecretName, "namespace", req.Namespace)
			r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
			return ctrl.Result{RequeueAfter: time.Second * 120}, nil
		}
		secretKey, ok := authSecret.Data["AWS_SECRET_ACCESS_KEY"]
		if !ok {
			r.Log.V(0).Info("Auth secret missing AWS_SECRET_ACCESS_KEY", "name", validator.Spec.Auth.SecretName, "namespace", req.Namespace)
			r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
			return ctrl.Result{RequeueAfter: time.Second * 120}, nil
		}
		awsCreds = credentials.NewStaticCredentials(string(id), string(secretKey), "")
	} else if validator.Spec.Auth.ServiceAccountName != "" {
		// TODO: EKS service account auth
		r.Log.V(0).Info("WARNING: service account auth not implemented")
	}

	// get the active validator's validation result
	vr := &valid8orv1alpha1.ValidationResult{}
	nn := types.NamespacedName{
		Name:      fmt.Sprintf("aws-validator-%s", validator.Name),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		// a validation result already exists for the active validator
		switch vr.Status.State {
		case valid8orv1alpha1.ValidationInProgress:
			// we shouldn't get here, since the code isn't async
			r.Log.V(0).Info("Validation running. Requeueing in 30s.", "name", nn.Name, "namespace", nn.Namespace)
			return ctrl.Result{RequeueAfter: time.Second * 30}, nil
		case valid8orv1alpha1.ValidationFailed:
			// log validation failure, but continue and retry
			cs := getInvalidConditions(vr.Status.Conditions)
			if len(cs) > 0 {
				for _, c := range cs {
					r.Log.V(0).Info("Validation failed. Retrying.", "name", nn.Name, "namespace", nn.Namespace, "validation", c.Reason, "error", c.Message)
				}
			}
		case valid8orv1alpha1.ValidationSucceeded:
			// log validation success, continue to re-validate
			r.Log.V(0).Info("Previous validation succeeded. Re-validating.", "name", nn.Name, "namespace", nn.Namespace)
		}
	} else {
		if !apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		}

		// create a new validation result for the active validator
		vr.ObjectMeta = metav1.ObjectMeta{
			Name:      nn.Name,
			Namespace: nn.Namespace,
		}
		vr.Spec = valid8orv1alpha1.ValidationResultSpec{
			Plugin: "AWS",
		}
		if err := r.Client.Create(context.Background(), vr, &client.CreateOptions{}); err != nil {
			r.Log.V(0).Error(err, "failed to create ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
			return ctrl.Result{}, err
		}

		// update its status
		if err := r.Get(ctx, nn, vr); err != nil {
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
			return ctrl.Result{}, err
		}
	}

	// establish AWS sessions
	sess, err := session.NewSession(&aws.Config{
		Credentials: awsCreds,
		MaxRetries:  aws.Int(3),
	})
	if err != nil {
		r.Log.V(0).Error(err, "failed to establish AWS session")
	}
	iamSvc := iam.New(sess, &aws.Config{
		Region: aws.String(validator.Spec.Region),
	})
	ec2Svc := ec2.New(sess, &aws.Config{
		Region: aws.String(validator.Spec.Region),
	})

	// execute validation
	for _, rule := range validator.Spec.IamRules {
		if err := r.ReconcileIAMRule(nn, rule, iamSvc); err != nil {
			r.Log.V(0).Error(err, "failed to reconcile IAM rule")
		}
	}
	for _, rule := range validator.Spec.TagRules {
		if err := r.ReconcileTagRule(rule, ec2Svc); err != nil {
			r.Log.V(0).Error(err, "failed to reconcile Tag rule")
		}
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

func (r *AwsValidatorReconciler) ReconcileIAMRule(nn types.NamespacedName, rule validationv1alpha1.IamRule, iamSvc *iam.IAM) error {
	// build map of required permissions
	permissions := make(map[string]map[string]bool)
	for _, p := range rule.Policies {
		for _, s := range p.Statements {
			if s.Effect != "Allow" {
				continue
			}
			if permissions[s.Resource] == nil {
				permissions[s.Resource] = make(map[string]bool)
			}
			for _, action := range s.Actions {
				permissions[s.Resource][action] = false
			}
		}
	}

	// retrieve existing permissions & update the permission map
	policies, err := iamSvc.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
		RoleName: &rule.IamRole,
	})
	if err != nil {
		r.Log.V(0).Error(err, "failed to list policies for IAM role", "role", rule.IamRole)
		return err
	}
	for _, p := range policies.AttachedPolicies {
		// fetch the IAM policy's policy document
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

		// parse the policy document
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

		for _, s := range policyDocument.Statements {
			if s.Effect != "Allow" {
				continue
			}
			for _, resource := range s.Resource {
				for _, action := range s.Action {
					if _, ok := permissions[resource][action]; ok {
						permissions[resource][action] = true
					}
				}
			}
		}
	}

	// build failure messages, if applicable
	missing := make(map[string][]string)
	for resource, actions := range permissions {
		for action, allowed := range actions {
			if !allowed {
				if missing[resource] == nil {
					missing[resource] = make([]string, 0)
				}
				missing[resource] = append(missing[resource], action)
			}
		}
	}
	failures := make([]string, 0)
	for resource, actions := range missing {
		failures = append(failures, fmt.Sprintf("resource '%s' missing action(s): %s", resource, actions))
	}

	message := "All required IAM permissions were found"
	reason := fmt.Sprintf("%s-%s", validReasonPrefix, rule.IamRole)
	state := valid8orv1alpha1.ValidationSucceeded
	status := corev1.ConditionTrue
	lastTransitionTime := metav1.Time{Time: time.Now()}

	if len(missing) > 0 {
		message = "One or more required IAM permissions was not found"
		state = valid8orv1alpha1.ValidationFailed
		status = corev1.ConditionFalse
	}

	latestCondition := valid8orv1alpha1.ValidationCondition{
		Failures:           failures,
		Message:            message,
		Reason:             reason,
		Status:             status,
		LastTransitionTime: lastTransitionTime,
	}

	// update ValidationResult for the active IAM role
	vr := &valid8orv1alpha1.ValidationResult{}
	if err := r.Get(context.Background(), nn, vr); err != nil {
		return fmt.Errorf("failed to get ValidationResult '%s' in namespace '%s': %v", nn.Name, nn.Namespace, err)
	}
	vr.Status.State = state

	idx := getConditionIndexByReason(vr.Status.Conditions, reason)
	if idx == -1 {
		vr.Status.Conditions = append(vr.Status.Conditions, latestCondition)
	} else {
		vr.Status.Conditions[idx] = latestCondition
	}

	if err := r.Status().Update(context.Background(), vr); err != nil {
		r.Log.V(0).Error(err, "failed to update ValidationResult")
		return err
	}
	r.Log.V(0).Info("Updated ValidationResult", "state", state, "reason", reason, "message", message, "time", lastTransitionTime)
	return nil
}

func (r *AwsValidatorReconciler) ReconcileTagRule(rule validationv1alpha1.TagRule, ec2Svc *ec2.EC2) error {
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AwsValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&validationv1alpha1.AwsValidator{}).
		Complete(r)
}

func getInvalidConditions(conditions []valid8orv1alpha1.ValidationCondition) []valid8orv1alpha1.ValidationCondition {
	invalidConditions := make([]valid8orv1alpha1.ValidationCondition, 0)
	for _, c := range conditions {
		if strings.HasPrefix(c.Reason, validReasonPrefix) && c.Status == corev1.ConditionFalse {
			invalidConditions = append(invalidConditions, c)
		}
	}
	return invalidConditions
}

func getConditionIndexByReason(conditions []valid8orv1alpha1.ValidationCondition, reason string) int {
	for i, c := range conditions {
		if c.Reason == reason {
			return i
		}
	}
	return -1
}

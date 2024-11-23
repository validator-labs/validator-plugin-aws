package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vres "github.com/validator-labs/validator/pkg/validationresult"
	//+kubebuilder:scaffold:imports
)

const awsValidatorName = "aws-validator"

var _ = Describe("AWSValidator controller", Ordered, func() {

	BeforeEach(func() {
		// toggle true/false to enable/disable the AWSValidator controller specs
		if false {
			Skip("skipping")
		}
	})

	dummyPolicy := v1alpha1.PolicyDocument{
		Name:    "test",
		Version: "2012-10-17",
		Statements: []v1alpha1.StatementEntry{
			{
				Effect:    "Allow",
				Actions:   []string{"ec2:DescribeInstances"},
				Resources: []string{"*"},
			},
		},
	}

	val := &v1alpha1.AwsValidator{
		ObjectMeta: metav1.ObjectMeta{
			Name:      awsValidatorName,
			Namespace: validatorNamespace,
		},
		Spec: v1alpha1.AwsValidatorSpec{
			Auth: v1alpha1.AwsAuth{
				Implicit: true,
			},
			DefaultRegion: "us-west-1",
			AmiRules: []v1alpha1.AmiRule{
				{
					RuleName: "AMIRule",
					AmiIDs:   []string{"ami-12345678"},
					Region:   "us-west-2",
				},
			},
			IamRoleRules: []v1alpha1.IamRoleRule{
				{
					IamRoleName: "IAMRole",
					Policies:    []v1alpha1.PolicyDocument{dummyPolicy},
				},
			},
			IamGroupRules: []v1alpha1.IamGroupRule{
				{
					IamGroupName: "IAMGroup",
					Policies:     []v1alpha1.PolicyDocument{dummyPolicy},
				},
			},
			IamUserRules: []v1alpha1.IamUserRule{
				{
					IamUserName: "IAMUser",
					Policies:    []v1alpha1.PolicyDocument{dummyPolicy},
				},
			},
			IamPolicyRules: []v1alpha1.IamPolicyRule{
				{
					IamPolicyARN: "IAMPolicyArn",
					Policies:     []v1alpha1.PolicyDocument{dummyPolicy},
				},
			},
			ServiceQuotaRules: []v1alpha1.ServiceQuotaRule{
				{
					RuleName:    "ServiceQuotaRule",
					Region:      "us-west-1",
					ServiceCode: "ec2",
					ServiceQuotas: []v1alpha1.ServiceQuota{
						{
							Name:   "dummy-quota",
							Buffer: 1,
						},
					},
				},
			},
			TagRules: []v1alpha1.TagRule{
				{
					Key:           "foo",
					ExpectedValue: "bar",
					Region:        "us-west-1",
					ResourceType:  "subnet",
					ARNs:          []string{""},
				},
			},
		},
	}

	vr := &vapi.ValidationResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vres.Name(val),
			Namespace: validatorNamespace,
		},
	}
	vrKey := types.NamespacedName{Name: vres.Name(val), Namespace: validatorNamespace}

	It("Should create a ValidationResult and update its Status with a failed condition", func() {
		By("By creating a new AWSValidator")
		ctx := context.Background()

		Expect(k8sClient.Create(ctx, val)).Should(Succeed())

		// Wait for the ValidationResult to be created
		Eventually(func() error {
			return k8sClient.Get(ctx, vrKey, vr)
		}, timeout, interval).Should(Succeed(), "ValidationResult was never created")

		// Wait for ValidationResult to eventually have expected status
		Eventually(func() error {
			if err := k8sClient.Get(ctx, vrKey, vr); err != nil {
				return fmt.Errorf("failed to get ValidationResult")
			}
			stateOk := vr.Status.State == vapi.ValidationFailed
			// for this kind of failure, we expect one "dummy rule" condition that communicates the failure to the user reading the ValidationResult
			expectedNumConditions := len(vr.Status.ValidationConditions) == 1
			if !stateOk {
				return fmt.Errorf("state not OK")
			}
			if !expectedNumConditions {
				return fmt.Errorf("unexpected number of conditions in ValidationResult")
			}
			return nil
		}, timeout, interval).Should(Succeed(), "ValidationResult never reached expected state")
	})
})

func Test_AwsValidatorReconciler_authFromSecret(t *testing.T) {
	logger := logr.Logger{}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme) // Add corev1 scheme for fake client

	tests := []struct {
		name           string
		auth           v1alpha1.AwsAuth
		secret         *corev1.Secret
		expectedAuth   v1alpha1.AwsAuth
		expectedError  error
		expectOverride bool
	}{
		{
			name: "Skips looking for Secret and overriding inline config when implicit auth is enabled",
			auth: v1alpha1.AwsAuth{Implicit: true},
			expectedAuth: v1alpha1.AwsAuth{
				Implicit: true,
			},
		},
		{
			name:         "Skips looking for Secret and overriding inline config when no secret name is specified",
			auth:         v1alpha1.AwsAuth{},
			expectedAuth: v1alpha1.AwsAuth{},
		},
		{
			name: "Returns an error when Secret is not found",
			auth: v1alpha1.AwsAuth{
				SecretName: "nonexistent-secret",
			},
			expectedAuth: v1alpha1.AwsAuth{
				SecretName: "nonexistent-secret",
			},
			expectedError: fmt.Errorf("failed to get Secret: secrets \"nonexistent-secret\" not found"),
		},
		{
			name: "Returns an error when Secret is missing key for access key ID",
			auth: v1alpha1.AwsAuth{
				SecretName: "aws-secret",
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			expectedAuth: v1alpha1.AwsAuth{
				SecretName: "aws-secret",
			},
			expectedError: fmt.Errorf("Key AWS_ACCESS_KEY_ID missing from Secret"),
		},
		{
			name: "Returns an error when Secret is missing key for secret access key",
			auth: v1alpha1.AwsAuth{
				SecretName: "aws-secret",
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"AWS_ACCESS_KEY_ID": []byte("access-key-id"),
				},
			},
			expectedAuth: v1alpha1.AwsAuth{
				SecretName: "aws-secret",
				Credentials: &v1alpha1.Credentials{
					AccessKeyID: "access-key-id",
				},
			},
			expectedError: fmt.Errorf("Key AWS_SECRET_ACCESS_KEY missing from Secret"),
		},
		{
			name: "Overrides inline config when implicit auth is not enabled, a secret name is specified, the Secret is found, and the Secret contains all required auth data",
			auth: v1alpha1.AwsAuth{SecretName: "aws-secret"},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"AWS_ACCESS_KEY_ID":     []byte("access-key-id"),
					"AWS_SECRET_ACCESS_KEY": []byte("secret-access-key"),
				},
			},
			expectedAuth: v1alpha1.AwsAuth{
				SecretName: "aws-secret",
				Credentials: &v1alpha1.Credentials{
					AccessKeyID:     "access-key-id",
					SecretAccessKey: "secret-access-key",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up fake client and reconciler
			objects := []runtime.Object{}
			if tt.secret != nil {
				tt.secret.ObjectMeta.Name = tt.auth.SecretName
				tt.secret.ObjectMeta.Namespace = "default"
				objects = append(objects, tt.secret)
			}
			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			reconciler := AwsValidatorReconciler{
				Client: client,
			}

			// Assert auth data augmented by secret or not.
			result, err := reconciler.authFromSecret(tt.auth, "default", logger)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedAuth, result)
			}
		})
	}
}

package controller

import (
	"context"
	"fmt"
	"maps"
	"os"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

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

		// Wait for the ValidationResult's Status to be updated
		Eventually(func() bool {
			if err := k8sClient.Get(ctx, vrKey, vr); err != nil {
				return false
			}
			stateOk := vr.Status.State == vapi.ValidationFailed
			allFailed := len(vr.Status.ValidationConditions) == val.Spec.ResultCount()
			return stateOk && allFailed
		}, timeout, interval).Should(BeTrue(), "failed to create a ValidationResult")
	})
})

func Test_AwsValidatorReconciler_configureAwsAuth(t *testing.T) {
	type args struct {
		auth         v1alpha1.AwsAuth
		reqNamespace string
		l            logr.Logger
	}
	tests := []struct {
		name        string
		m           *AwsValidatorReconciler
		args        args
		wantErr     bool
		wantEnvVars map[string]string
	}{
		{
			name: "Sets env vars given inline auth config",
			m:    &AwsValidatorReconciler{},
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "b",
						SessionToken:    ptr.To("c"),
					},
				},
			},
			wantErr: false,
			wantEnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "a",
				"AWS_SECRET_ACCESS_KEY": "b",
				"AWS_SESSION_TOKEN":     "c",
			},
		},
		{
			name: "Error for invalid access key ID",
			m:    &AwsValidatorReconciler{},
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "",
						SecretAccessKey: "b",
						SessionToken:    ptr.To("c"),
					},
				},
			},
			wantErr: true,
			wantEnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "",
				"AWS_SECRET_ACCESS_KEY": "",
				"AWS_SESSION_TOKEN":     "",
			},
		},
		{
			name: "Error for invalid secret access key",
			m:    &AwsValidatorReconciler{},
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "",
						SessionToken:    ptr.To("c"),
					},
				},
			},
			wantErr: true,
			wantEnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "",
				"AWS_SECRET_ACCESS_KEY": "",
				"AWS_SESSION_TOKEN":     "",
			},
		},
		{
			name: "No error for missing session token",
			m:    &AwsValidatorReconciler{},
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "b",
						SessionToken:    nil,
					},
				},
			},
			wantErr: false,
			wantEnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "a",
				"AWS_SECRET_ACCESS_KEY": "b",
				"AWS_SESSION_TOKEN":     "",
			},
		},
		{
			name: "Error for invalid session token",
			m:    &AwsValidatorReconciler{},
			args: args{
				auth: v1alpha1.AwsAuth{
					Credentials: &v1alpha1.Credentials{
						AccessKeyID:     "a",
						SecretAccessKey: "b",
						SessionToken:    ptr.To(""),
					},
				},
			},
			wantErr: true,
			wantEnvVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "",
				"AWS_SECRET_ACCESS_KEY": "",
				"AWS_SESSION_TOKEN":     "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the current environment variables to restore them later
			originalEnv := make(map[string]string)
			for k := range tt.wantEnvVars {
				originalEnv[k] = os.Getenv(k)
			}

			// Clean up and reset environment variables after the test
			defer func() {
				for k, v := range originalEnv {
					if v == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, v)
					}
				}
			}()

			r := &AwsValidatorReconciler{}
			if err := r.configureAwsAuth(tt.args.auth, tt.args.reqNamespace, tt.args.l); (err != nil) != tt.wantErr {
				t.Errorf("AwsValidatorReconciler.configureAwsAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := checkEnvVars(tt.wantEnvVars); err != nil {
				t.Error(err)
			}
		})
	}
}

func checkEnvVars(expected map[string]string) error {
	for k := range maps.Keys(expected) {
		if v := os.Getenv(k); v != expected[k] {
			return fmt.Errorf("env var %s = %s; expected %s", k, v, expected[k])
		}
	}
	return nil
}

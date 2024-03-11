package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
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
					Name:        "ServiceQuotaRule",
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
			Name:      validationResultName(val),
			Namespace: validatorNamespace,
		},
	}
	vrKey := types.NamespacedName{Name: validationResultName(val), Namespace: validatorNamespace}

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

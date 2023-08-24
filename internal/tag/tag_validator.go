package tag

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/aws"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/types"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

// ReconcileTagRule reconciles an EC2 tagging validation rule from the AWSValidator config
func ReconcileTagRule(nn k8stypes.NamespacedName, rule v1alpha1.TagRule, s *session.Session, log logr.Logger) (*types.ValidationResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)

	// Build the default latest condition for this tag rule
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := valid8orv1alpha1.DefaultValidationCondition()
	latestCondition.Message = "All required subnet tags were found"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s-%s", constants.ValidationRulePrefix, rule.ResourceType, rule.Key)

	switch rule.ResourceType {
	case "subnet":
		// match the tag rule's list of ARNs against the subnets with tag 'rule.Key=rule.ExpectedValue'
		failures := make([]string, 0)
		foundArns := make(map[string]bool)
		subnets, err := ec2Svc.DescribeSubnets(&ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String(fmt.Sprintf("tag:%s", rule.Key)),
					Values: []*string{aws.String(rule.ExpectedValue)},
				},
			},
		})
		if err != nil {
			log.V(0).Error(err, "failed to describe subnets", "region", rule.Region)
			return nil, err
		}
		for _, s := range subnets.Subnets {
			if s.SubnetArn != nil {
				foundArns[*s.SubnetArn] = true
			}
		}
		for _, arn := range rule.ARNs {
			_, ok := foundArns[arn]
			if !ok {
				failures = append(failures, fmt.Sprintf("Subnet with ARN %s missing tag %s=%s", arn, rule.Key, rule.ExpectedValue))
			}
		}
		if len(failures) > 0 {
			state = valid8orv1alpha1.ValidationFailed
			latestCondition.Failures = failures
			latestCondition.Message = "One or more required subnet tags was not found"
			latestCondition.Status = corev1.ConditionFalse
		}
	default:
		return nil, fmt.Errorf("unsupported resourceType %s for TagRule", rule.ResourceType)
	}

	validationResult := &types.ValidationResult{Condition: latestCondition, State: state}
	return validationResult, nil
}

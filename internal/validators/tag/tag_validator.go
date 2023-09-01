package tag

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	v8or "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
	v8orconstants "github.com/spectrocloud-labs/valid8or/pkg/constants"
	v8ortypes "github.com/spectrocloud-labs/valid8or/pkg/types"
	"github.com/spectrocloud-labs/valid8or/pkg/util/ptr"
)

type tagApi interface {
	DescribeSubnets(input *ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error)
}

type TagRuleService struct {
	log    logr.Logger
	tagSvc tagApi
}

func NewTagRuleService(log logr.Logger, tagSvc tagApi) *TagRuleService {
	return &TagRuleService{
		log:    log,
		tagSvc: tagSvc,
	}
}

// ReconcileTagRule reconciles an EC2 tagging validation rule from the AWSValidator config
func (s *TagRuleService) ReconcileTagRule(rule v1alpha1.TagRule) (*v8ortypes.ValidationResult, error) {

	// Build the default latest condition for this tag rule
	state := v8or.ValidationSucceeded
	latestCondition := v8or.DefaultValidationCondition()
	latestCondition.Message = "All required subnet tags were found"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s-%s", v8orconstants.ValidationRulePrefix, rule.ResourceType, rule.Key)
	latestCondition.ValidationType = constants.ValidationTypeTag
	validationResult := &v8ortypes.ValidationResult{Condition: &latestCondition, State: &state}

	switch rule.ResourceType {
	case "subnet":
		// match the tag rule's list of ARNs against the subnets with tag 'rule.Key=rule.ExpectedValue'
		failures := make([]string, 0)
		foundArns := make(map[string]bool)
		subnets, err := s.tagSvc.DescribeSubnets(&ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{
				{
					Name:   ptr.Ptr(fmt.Sprintf("tag:%s", rule.Key)),
					Values: []*string{ptr.Ptr(rule.ExpectedValue)},
				},
			},
		})
		if err != nil {
			s.log.V(0).Error(err, "failed to describe subnets", "region", rule.Region)
			return validationResult, err
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
			state = v8or.ValidationFailed
			latestCondition.Failures = failures
			latestCondition.Message = "One or more required subnet tags was not found"
			latestCondition.Status = corev1.ConditionFalse
		}
	default:
		return nil, fmt.Errorf("unsupported resourceType %s for TagRule", rule.ResourceType)
	}

	return validationResult, nil
}

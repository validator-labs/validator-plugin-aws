// Package tag handles EC2 tag validation rule reconciliation.
package tag

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/pkg/constants"
	"github.com/validator-labs/validator-plugin-aws/pkg/validate"
)

type tagAPI interface {
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
}

// RuleService reconciles EC2 tag validation rules.
type RuleService struct {
	log    logr.Logger
	tagSvc tagAPI
}

// NewTagRuleService creates a new TagRuleService.
func NewTagRuleService(log logr.Logger, tagSvc tagAPI) *RuleService {
	return &RuleService{
		log:    log,
		tagSvc: tagSvc,
	}
}

// ReconcileTagRule reconciles an EC2 tagging validation rule from the AWSValidator config
func (s *RuleService) ReconcileTagRule(rule v1alpha1.TagRule) (*vapitypes.ValidationRuleResult, error) {

	msg := fmt.Sprintf("All required %s tags were found", rule.ResourceType)
	vr := validate.BuildValidationResult(rule.Name, msg, constants.ValidationTypeTag)

	switch rule.ResourceType {
	case "subnet":
		// match the tag rule's list of ARNs against the subnets with tag 'rule.Key=rule.ExpectedValue'
		failures := make([]string, 0)
		foundArns := make(map[string]bool)
		subnets, err := s.tagSvc.DescribeSubnets(context.Background(), &ec2.DescribeSubnetsInput{
			Filters: []ec2types.Filter{
				{
					Name:   util.Ptr(fmt.Sprintf("tag:%s", rule.Key)),
					Values: []string{rule.ExpectedValue},
				},
			},
		})
		if err != nil {
			s.log.V(0).Error(err, "failed to describe subnets", "region", rule.Region)
			return vr, err
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
			state := vapi.ValidationFailed
			vr.State = &state
			vr.Condition.Failures = failures
			vr.Condition.Message = "One or more required subnet tags was not found"
			vr.Condition.Status = corev1.ConditionFalse
		}
	default:
		return nil, fmt.Errorf("unsupported resourceType %s for TagRule", rule.ResourceType)
	}

	return vr, nil
}

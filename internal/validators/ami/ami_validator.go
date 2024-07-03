package ami

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/internal/constants"
	stringutils "github.com/validator-labs/validator-plugin-aws/internal/utils/strings"
)

type amiApi interface {
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

type AmiRuleService struct {
	log    logr.Logger
	amiSvc amiApi
}

func NewAmiRuleService(log logr.Logger, amiSvc amiApi) *AmiRuleService {
	return &AmiRuleService{
		log:    log,
		amiSvc: amiSvc,
	}
}

// ReconcileAmiRule reconciles an AMI validation rule from the AWSValidator config
func (s *AmiRuleService) ReconcileAmiRule(rule v1alpha1.AmiRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default latest condition for this AMI rule
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = "All required AMIs were found"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, stringutils.Sanitize(rule.Name))
	latestCondition.ValidationType = constants.ValidationTypeAmi
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	// Describe AMIs matching the rule's ID list in the rule's region
	input := &ec2.DescribeImagesInput{
		ImageIds: rule.AmiIds,
		Filters:  []ec2types.Filter{},
		Owners:   rule.Owners,
	}
	for _, f := range rule.Filters {
		filter := ec2types.Filter{
			Name:   util.Ptr(f.Key),
			Values: f.Values,
		}
		if f.IsTag {
			filter.Name = util.Ptr(fmt.Sprintf("tag:%s", f.Key))
		}
		input.Filters = append(input.Filters, filter)
	}
	images, err := s.amiSvc.DescribeImages(context.Background(), input)
	if err != nil {
		s.log.V(0).Error(err, "failed to describe images", "region", rule.Region)
		return validationResult, err
	}

	// Check if all required AMIs were found
	foundImages := make(map[string]bool)
	for _, s := range images.Images {
		if s.ImageId != nil {
			foundImages[*s.ImageId] = true
		}
	}

	// Add failures to the validation result if any required AMIs were not found
	failures := make([]string, 0)
	for _, id := range rule.AmiIds {
		_, ok := foundImages[id]
		if !ok {
			failures = append(failures, fmt.Sprintf("AMI with ID %s not found in region %s", id, rule.Region))
		}
	}
	if len(failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "One or more required AMIs was not found"
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

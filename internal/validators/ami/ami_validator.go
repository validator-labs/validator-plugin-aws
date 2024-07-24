// Package ami handles AMI validation rule reconciliation.
package ami

import (
	"context"
	"fmt"
	"strings"

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
)

type amiAPI interface {
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

// RuleService reconciles AMI validation rules.
type RuleService struct {
	log    logr.Logger
	amiSvc amiAPI
}

// NewAmiRuleService creates a new AmiRuleService.
func NewAmiRuleService(log logr.Logger, amiSvc amiAPI) *RuleService {
	return &RuleService{
		log:    log,
		amiSvc: amiSvc,
	}
}

// ReconcileAmiRule reconciles an AMI validation rule from the AWSValidator config.
func (s *RuleService) ReconcileAmiRule(rule v1alpha1.AmiRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default latest condition for this AMI rule
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = "All required AMIs were found"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, util.Sanitize(rule.Name))
	latestCondition.ValidationType = constants.ValidationTypeAmi
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	// Describe AMIs matching the rule. There should be at least one.
	input := &ec2.DescribeImagesInput{
		ImageIds: rule.AmiIDs,
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

	// Add a failure to the validation result if the AMI was not found
	failures := make([]string, 0)
	if len(images.Images) == 0 {
		failures = append(failures,
			fmt.Sprintf("AMI not found. Region: %s. DescribeImagesInput{%s}", rule.Region, prettyPrintDescribeImagesInput(input)),
		)
	}
	if len(failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "One or more required AMIs was not found"
		latestCondition.Status = corev1.ConditionFalse
	}

	// Update validation result details with each AMI found
	for _, i := range images.Images {
		var id, name, source string
		if i.ImageId != nil {
			id = *i.ImageId
		}
		if i.Name != nil {
			name = *i.Name
		}
		if i.ImageLocation != nil {
			source = *i.ImageLocation
		}
		latestCondition.Details = append(latestCondition.Details,
			fmt.Sprintf("Found AMI; ID: '%s'; Name: '%s'; Source: '%s'", id, name, source),
		)
	}

	return validationResult, nil
}

// prettyPrintDescribeImagesInput returns a string representation of the DescribeImagesInput.
// Because the AWS SDK has no struct tags and dumping their structs is extremely ugly, we have to do this manually.
func prettyPrintDescribeImagesInput(input *ec2.DescribeImagesInput) string {
	var b strings.Builder
	if len(input.ImageIds) > 0 {
		b.WriteString(fmt.Sprintf("ImageIds: [%v]", strings.Join(input.ImageIds, ", ")))
	}
	if len(input.Owners) > 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(fmt.Sprintf("Owners: [%v]", strings.Join(input.Owners, ", ")))
	}
	if len(input.Filters) > 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString("Filters: [")
		for i, f := range input.Filters {
			b.WriteString(fmt.Sprintf("{%s: %s}", *f.Name, f.Values))
			if i < len(input.Filters)-1 {
				b.WriteString(", ")
			}
		}
		b.WriteString("]")
	}
	return b.String()
}

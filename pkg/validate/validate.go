// Package validate defines functions that are common across all validation areas.
package validate

import (
	"github.com/go-logr/logr"

	"github.com/validator-labs/validator/pkg/types"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/pkg/aws"
	"github.com/validator-labs/validator-plugin-aws/pkg/constants"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators/ami"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators/iam"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators/servicequota"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators/tag"
)

// Validate validates the AwsValidatorSpec and returns a ValidationResponse.
func Validate(spec v1alpha1.AwsValidatorSpec, log logr.Logger) types.ValidationResponse {
	resp := types.ValidationResponse{
		ValidationRuleResults: make([]*types.ValidationRuleResult, 0, spec.ResultCount()),
		ValidationRuleErrors:  make([]error, 0, spec.ResultCount()),
	}

	// AMI rules
	for _, rule := range spec.AmiRules {
		awsAPI, err := aws.NewAPI(spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile AMI rule"
			log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name, errMsg, constants.ValidationTypeAmi)
			resp.AddResult(vrr, err)
			continue
		}
		amiRuleService := ami.NewAmiRuleService(log, awsAPI.EC2)
		vrr, err := amiRuleService.ReconcileAmiRule(rule)
		if err != nil {
			log.V(0).Error(err, "failed to reconcile AMI rule")
		}
		resp.AddResult(vrr, err)
	}

	// IAM rules
	awsAPI, err := aws.NewAPI(spec.Auth, spec.DefaultRegion)
	if err != nil {
		log.V(0).Error(err, "failed to get AWS client")
	} else {
		iamRuleService := iam.NewIAMRuleService(log, awsAPI.IAM)

		for _, rule := range spec.IamRoleRules {
			vrr, err := iamRuleService.ReconcileIAMRoleRule(rule)
			if err != nil {
				log.V(0).Error(err, "failed to reconcile IAM role rule")
			}
			resp.AddResult(vrr, err)
		}
		for _, rule := range spec.IamUserRules {
			vrr, err := iamRuleService.ReconcileIAMUserRule(rule)
			if err != nil {
				log.V(0).Error(err, "failed to reconcile IAM user rule")
			}
			resp.AddResult(vrr, err)
		}
		for _, rule := range spec.IamGroupRules {
			vrr, err := iamRuleService.ReconcileIAMGroupRule(rule)
			if err != nil {
				log.V(0).Error(err, "failed to reconcile IAM group rule")
			}
			resp.AddResult(vrr, err)
		}
		for _, rule := range spec.IamPolicyRules {
			vrr, err := iamRuleService.ReconcileIAMPolicyRule(rule)
			if err != nil {
				log.V(0).Error(err, "failed to reconcile IAM policy rule")
			}
			resp.AddResult(vrr, err)
		}
	}

	// Service Quota rules
	for _, rule := range spec.ServiceQuotaRules {
		awsAPI, err := aws.NewAPI(spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile Service Quota rule"
			log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name, errMsg, constants.ValidationTypeServiceQuota)
			resp.AddResult(vrr, err)
			continue
		}
		svcQuotaService := servicequota.NewServiceQuotaRuleService(
			log,
			awsAPI.EC2,
			awsAPI.EFS,
			awsAPI.ELB,
			awsAPI.ELBV2,
			awsAPI.SQ,
		)
		vrr, err := svcQuotaService.ReconcileServiceQuotaRule(rule)
		if err != nil {
			log.V(0).Error(err, "failed to reconcile Service Quota rule")
		}
		resp.AddResult(vrr, err)
	}

	// Tag rules
	for _, rule := range spec.TagRules {
		awsAPI, err := aws.NewAPI(spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile Tag rule"
			log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name, errMsg, constants.ValidationTypeTag)
			resp.AddResult(vrr, err)
			continue
		}
		tagRuleService := tag.NewTagRuleService(log, awsAPI.EC2)
		vrr, err := tagRuleService.ReconcileTagRule(rule)
		if err != nil {
			log.V(0).Error(err, "failed to reconcile Tag rule")
		}
		resp.AddResult(vrr, err)
	}

	return resp
}

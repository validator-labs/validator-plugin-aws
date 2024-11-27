// Package validate defines functions that are common across all validation areas.
package validate

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vconstants "github.com/validator-labs/validator/pkg/constants"

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

	vrr := buildValidationResult()

	if err := validateAuth(spec.Auth); err != nil {
		resp.AddResult(vrr, fmt.Errorf("AWS SDK auth data invalid: %w", err))
		return resp
	}

	if err := configureAuth(spec.Auth, log); err != nil {
		resp.AddResult(vrr, fmt.Errorf("failed to configure auth for AWS SDK: %w", err))
		return resp
	}

	// AMI rules
	for _, rule := range spec.AmiRules {
		awsAPI, err := aws.NewAPI(spec.Auth, rule.Region)
		if err != nil {
			errMsg := "Failed to reconcile AMI rule"
			log.V(0).Error(err, errMsg)
			vrr := validators.BuildValidationResult(rule.Name(), errMsg, constants.ValidationTypeAmi)
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
			vrr := validators.BuildValidationResult(rule.Name(), errMsg, constants.ValidationTypeServiceQuota)
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
			vrr := validators.BuildValidationResult(rule.Name(), errMsg, constants.ValidationTypeTag)
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

// Validates the inline auth. The data here could have not passed through kube-apiserver, so we need
// to validate here instead of relying on CRD validation.
func validateAuth(auth v1alpha1.AwsAuth) error {
	if auth.Credentials == nil {
		auth.Credentials = &v1alpha1.Credentials{}
	}

	var validationErrors []error

	if auth.Credentials.AccessKeyID == "" {
		validationErrors = append(validationErrors, errors.New("access key ID is invalid, must be a non-empty string"))
	}
	if auth.Credentials.SecretAccessKey == "" {
		validationErrors = append(validationErrors, errors.New("secret access key is invalid, must be a non-empty string"))
	}

	if auth.MaxAttempts != nil && *auth.MaxAttempts < 0 {
		validationErrors = append(validationErrors, fmt.Errorf("invalid max retries setting (%d), must be gte 0", *auth.MaxAttempts))
	}

	if len(validationErrors) > 0 {
		return errors.Join(validationErrors...)
	}
	return nil
}

// Sets environment variables needed by the AWS SDK from the inline auth. The inline auth is
// assumed to have already been validated.
func configureAuth(auth v1alpha1.AwsAuth, log logr.Logger) error {
	if auth.Implicit {
		log.Info("auth.implicit set to true. Skipping setting AWS_ env vars.")
		return nil
	}

	// Log non-secret data for help with debugging. Don't log the client secret.
	nonSecretData := map[string]string{
		"accessKeyId": auth.Credentials.AccessKeyID,
	}
	if auth.MaxAttempts != nil {
		nonSecretData["maxAttempts"] = fmt.Sprintf("%d", *auth.MaxAttempts)
	}
	log.Info("Determined AWS auth and SDK config data.", "nonSecretData", nonSecretData)

	// Use collected and validated values to set env vars.
	data := map[string]string{
		"AWS_ACCESS_KEY_ID":     auth.Credentials.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": auth.Credentials.SecretAccessKey,
	}
	data["AWS_MAX_ATTEMPTS"] = fmt.Sprintf("%d", constants.RetryMaxAttemptsDefault)
	if auth.MaxAttempts != nil {
		data["AWS_MAX_ATTEMPTS"] = fmt.Sprintf("%d", *auth.MaxAttempts)
	}
	for k, v := range data {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
		log.Info("Set environment variable", "envVar", k)
	}

	return nil
}

// buildValidationResult is used to build a validation result to use before rules have been
// evaluated (e.g. when we need to report a failure experienced while preparing to evaluate rules).
func buildValidationResult() *types.ValidationRuleResult {
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = "Initialization succeeded"
	latestCondition.ValidationRule = fmt.Sprintf(
		"%s-%s",
		vconstants.ValidationRulePrefix, constants.PluginCode,
	)
	latestCondition.ValidationType = constants.PluginCode

	return &types.ValidationRuleResult{Condition: &latestCondition, State: &state}
}

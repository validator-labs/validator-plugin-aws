// Package constants contains AWS plugin constants.
package constants

const (
	// PluginCode is the code for the AWS plugin.
	PluginCode string = "AWS"

	// ValidationTypeAmi is the validation type for AMIs.
	ValidationTypeAmi string = "aws-ami"

	// ValidationTypeIAMRolePolicy is the validation type for IAM role policies.
	ValidationTypeIAMRolePolicy string = "aws-iam-role-policy"

	// ValidationTypeIAMUserPolicy is the validation type for IAM user policies.
	ValidationTypeIAMUserPolicy string = "aws-iam-user-policy"

	// ValidationTypeIAMGroupPolicy is the validation type for IAM group policies.
	ValidationTypeIAMGroupPolicy string = "aws-iam-group-policy"

	// ValidationTypeIAMPolicy is the validation type for IAM policies.
	ValidationTypeIAMPolicy string = "aws-iam-policy"

	// ValidationTypeServiceQuota is the validation type for service quotas.
	ValidationTypeServiceQuota string = "aws-service-quota"

	// ValidationTypeTag is the validation type for tags.
	ValidationTypeTag string = "aws-tag"

	// IAMWildcard is the wildcard used in IAM policies.
	IAMWildcard string = "*"

	// RetryMaxAttemptsDefault is the default we use for the max retries setting of the AWS SDK.
	// It's greater than the SDK's default.
	RetryMaxAttemptsDefault int = 25
)

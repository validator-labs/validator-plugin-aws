package constants

const (
	ValidationRulePrefix string = "validation"

	ValidationTypeIAMRolePolicy  string = "aws-iam-role-policy"
	ValidationTypeIAMUserPolicy  string = "aws-iam-user-policy"
	ValidationTypeIAMGroupPolicy string = "aws-iam-group-policy"
	ValidationTypeIAMPolicy      string = "aws-iam-policy"
	ValidationTypeServiceQuota   string = "aws-service-quota"
	ValidationTypeTag            string = "aws-tag"

	IAMWildcard string = "*"
)

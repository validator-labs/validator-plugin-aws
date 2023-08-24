package servicequota

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/servicequotas"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/aws"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/types"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

var quotaUsageFuncs map[string]func(string, *session.Session, logr.Logger) (float64, error) = map[string]func(string, *session.Session, logr.Logger) (float64, error){
	// EC2
	"EC2-VPC Elastic IPs": elasticIPsByRegion,
	"Public AMIs":         nil,
	// EFS
	"File systems per account": nil,
	// ELB
	"Application Load Balancers per Region": nil,
	"Classic Load Balancers per Region":     nil,
	// VPC
	"VPCs per Region":                    vpcsByRegion,
	"Subnets per VPC":                    nil,
	"NAT gateways per Availability Zone": nil,
	"Network interfaces per Region":      nil,
	"Internet gateways per Region":       nil,
}

// ReconcileServiceQuotaRule reconciles an AWS service quota validation rule from the AWSValidator config
func ReconcileServiceQuotaRule(nn k8stypes.NamespacedName, rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.ValidationResult, error) {
	sqSvc := aws.ServiceQuotasService(s, rule.Region)

	// Build the default latest condition for this tag rule
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := valid8orv1alpha1.DefaultValidationCondition()
	latestCondition.Details = make([]string, 0)
	latestCondition.Message = "Usage for all service quotas is below specified buffer"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", constants.ValidationRulePrefix, rule.ServiceCode)

	// Fetch the quota by service code & name & compare against usage
	failures := make([]string, 0)

	for _, ruleQuota := range rule.ServiceQuotas {
		var quota *servicequotas.ServiceQuota
		err := sqSvc.ListServiceQuotasPages(&servicequotas.ListServiceQuotasInput{
			ServiceCode: &rule.ServiceCode,
		}, func(page *servicequotas.ListServiceQuotasOutput, lastPage bool) bool {
			for _, q := range page.Quotas {
				if q != nil && q.QuotaName != nil && *q.QuotaName == ruleQuota.Name {
					quota = q
					return false
				}
			}
			return true
		})
		if err != nil || quota == nil {
			log.V(0).Error(err, "failed to get service quota", "region", rule.Region, "serviceCode", rule.ServiceCode, "quotaName", ruleQuota.Name)
			return nil, err
		}
		usage, err := quotaUsageFuncs[ruleQuota.Name](rule.Region, s, log)
		if err != nil {
			log.V(0).Error(err, "failed to get usage for service quota", "region", rule.Region, "serviceCode", rule.ServiceCode, "quotaName", ruleQuota.Name)
			return nil, err
		}
		if quota.Value != nil {
			remainder := *quota.Value - usage
			if remainder < float64(ruleQuota.Buffer) {
				failures = append(failures, fmt.Sprintf(
					"Remaining quota %d, less than buffer %d, for service %s and quota %s",
					int(remainder), ruleQuota.Buffer, rule.ServiceCode, ruleQuota.Name,
				))
			}
			quotaDetail := fmt.Sprintf("Usage for quota %s: %d", ruleQuota.Name, int(usage))
			latestCondition.Details = append(latestCondition.Details, quotaDetail)
		}
	}
	if len(failures) > 0 {
		state = valid8orv1alpha1.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "Usage for one or more service quotas exceeded the specified buffer"
		latestCondition.Status = corev1.ConditionFalse
	}

	validationResult := &types.ValidationResult{Condition: latestCondition, State: state}
	return validationResult, nil
}

// elasticIPsByRegion determines the number of EC2-VPC Elastic IPs in use in a particular AWS region
func elasticIPsByRegion(region string, s *session.Session, log logr.Logger) (float64, error) {
	ec2Svc := aws.EC2Service(s, region)
	output, err := ec2Svc.DescribeAddresses(&ec2.DescribeAddressesInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get elastic IPs", "region", region)
		return -1, err
	}
	var usage float64
	for _, a := range output.Addresses {
		if a != nil && a.AssociationId != nil {
			usage++
		}
	}
	return usage, nil
}

// vpcsByRegion determines the number of VPCs in a particular AWS region
func vpcsByRegion(region string, s *session.Session, log logr.Logger) (float64, error) {
	ec2Svc := aws.EC2Service(s, region)
	output, err := ec2Svc.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get VPCs", "region", region)
		return -1, err
	}
	var usage float64
	for _, v := range output.Vpcs {
		if v != nil {
			usage++
		}
	}
	return usage, nil
}

package servicequota

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/efs"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/servicequotas"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/spectrocloud-labs/valid8or-plugin-aws/api/v1alpha1"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/constants"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/types"
	"github.com/spectrocloud-labs/valid8or-plugin-aws/internal/utils/aws"
	valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"
)

// quotaUsageFuncs maps AWS service quota names to functions that compute the usage and/or maximum usage for each service (maximum if the quota is broken out by VPC, AZ, etc.)
var quotaUsageFuncs map[string]func(v1alpha1.ServiceQuotaRule, *session.Session, logr.Logger) (*types.UsageResult, error) = map[string]func(v1alpha1.ServiceQuotaRule, *session.Session, logr.Logger) (*types.UsageResult, error){
	// EC2
	"EC2-VPC Elastic IPs": elasticIPsPerRegion,
	"Public AMIs":         publicAMIsPerRegion,
	// EFS
	"File systems per account": filesystemsPerRegion,
	// ELB
	"Application Load Balancers per Region": albsPerRegion,
	"Classic Load Balancers per Region":     clbsPerRegion,
	"Network Load Balancers per Region":     nlbsPerRegion,
	// VPC
	"Internet gateways per Region":       igsPerRegion,
	"Network interfaces per Region":      nicsPerRegion,
	"VPCs per Region":                    vpcsPerRegion,
	"Subnets per VPC":                    subnetsPerVpc,
	"NAT gateways per Availability Zone": natGatewaysPerAz,
}

// ReconcileServiceQuotaRule reconciles an AWS service quota validation rule from the AWSValidator config
func ReconcileServiceQuotaRule(nn k8stypes.NamespacedName, rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.ValidationResult, error) {
	sqSvc := aws.ServiceQuotasService(s, rule.Region)

	// Build the default latest condition for this tag rule
	state := valid8orv1alpha1.ValidationSucceeded
	latestCondition := valid8orv1alpha1.DefaultValidationCondition()
	latestCondition.Message = "Usage for all service quotas is below specified buffer"
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", constants.ValidationRulePrefix, rule.ServiceCode)
	latestCondition.ValidationType = constants.ValidationTypeServiceQuota
	validationResult := &types.ValidationResult{Condition: &latestCondition, State: state}

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
			return validationResult, err
		}
		usageResult, err := quotaUsageFuncs[ruleQuota.Name](rule, s, log)
		if err != nil {
			log.V(0).Error(err, "failed to get usage for service quota", "region", rule.Region, "serviceCode", rule.ServiceCode, "quotaName", ruleQuota.Name)
			return validationResult, err
		}
		if quota.Value != nil {
			remainder := *quota.Value - usageResult.MaxUsage
			if remainder < float64(ruleQuota.Buffer) {
				failureMsg := fmt.Sprintf(
					"Remaining quota %d, less than buffer %d, for service %s and quota %s",
					int(remainder), ruleQuota.Buffer, rule.ServiceCode, ruleQuota.Name,
				)
				failures = append(failures, failureMsg)
			}
			quotaDetail := fmt.Sprintf(
				"%s: quota: %d, buffer: %d, max. usage: %d, max. usage entity: %s",
				ruleQuota.Name, int(*quota.Value), ruleQuota.Buffer, int(usageResult.MaxUsage), usageResult.Description,
			)
			latestCondition.Details = append(latestCondition.Details, quotaDetail)
		}
	}

	if len(failures) > 0 {
		state = valid8orv1alpha1.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "Usage for one or more service quotas exceeded the specified buffer"
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

// EC2

// elasticIPsPerRegion determines the number of elastic IPs in use in a region
func elasticIPsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)
	output, err := ec2Svc.DescribeAddresses(&ec2.DescribeAddressesInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get elastic IPs", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, a := range output.Addresses {
		if a != nil && a.AssociationId != nil {
			usage++
		}
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// publicAMIsPerRegion determines the number of public AMIs in use in a region
func publicAMIsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)
	output, err := ec2Svc.DescribeImages(&ec2.DescribeImagesInput{
		ExecutableUsers: []*string{aws.String("self")},
	})
	if err != nil {
		log.V(0).Error(err, "failed to get public AMIs", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, i := range output.Images {
		if i != nil {
			usage++
		}
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// EFS

// filesystemsPerRegion determines the number of EFS filesystems in use in a region
func filesystemsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	efsSvc := aws.EFSService(s, rule.Region)
	output, err := efsSvc.DescribeFileSystems(&efs.DescribeFileSystemsInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get EFS filesystems", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, f := range output.FileSystems {
		if f != nil {
			usage++
		}
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// ELB

// albsPerRegion determines the number of application load balancers in use in a region
func albsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	elbv2Svc := aws.ELBv2Service(s, rule.Region)
	var usage float64
	err := elbv2Svc.DescribeLoadBalancersPages(
		&elbv2.DescribeLoadBalancersInput{},
		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
			for _, lb := range page.LoadBalancers {
				if lb != nil && lb.Type != nil && *lb.Type == elbv2.LoadBalancerTypeEnumApplication {
					usage++
				}
			}
			return false
		},
	)
	if err != nil {
		log.V(0).Error(err, "failed to get application load balancers", "region", rule.Region)
		return nil, err
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// clbsPerRegion determines the number of classic load balancers in use in a region
func clbsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	elbSvc := aws.ELBService(s, rule.Region)
	var usage float64
	err := elbSvc.DescribeLoadBalancersPages(
		&elb.DescribeLoadBalancersInput{},
		func(page *elb.DescribeLoadBalancersOutput, lastPage bool) bool {
			for _, lb := range page.LoadBalancerDescriptions {
				if lb != nil {
					usage++
				}
			}
			return false
		},
	)
	if err != nil {
		log.V(0).Error(err, "failed to get classic load balancers", "region", rule.Region)
		return nil, err
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// nlbsPerRegion determines the number of network load balancers in use in a region
func nlbsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	elbv2Svc := aws.ELBv2Service(s, rule.Region)
	var usage float64
	err := elbv2Svc.DescribeLoadBalancersPages(
		&elbv2.DescribeLoadBalancersInput{},
		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
			for _, lb := range page.LoadBalancers {
				if lb != nil && lb.Type != nil && *lb.Type == elbv2.LoadBalancerTypeEnumNetwork {
					usage++
				}
			}
			return false
		},
	)
	if err != nil {
		log.V(0).Error(err, "failed to get network load balancers", "region", rule.Region)
		return nil, err
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// VPC

// igsPerRegion determines the number of internet gateways in use in a region
func igsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)
	output, err := ec2Svc.DescribeInternetGateways(&ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get internet gateways", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, g := range output.InternetGateways {
		if g != nil {
			usage++
		}
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// nicsPerRegion determines the number of network interfaces in use in a region
func nicsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)
	output, err := ec2Svc.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get network interfaces", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, n := range output.NetworkInterfaces {
		if n != nil && n.Association != nil {
			usage++
		}
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// vpcsPerRegion determines the number of VPCs in a region
func vpcsPerRegion(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)
	output, err := ec2Svc.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get VPCs", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, v := range output.Vpcs {
		if v != nil {
			usage++
		}
	}
	return &types.UsageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// subnetsPerVpc determines the maximum number of subnets in any VPC across all VPCs in a region
func subnetsPerVpc(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)
	output, err := ec2Svc.DescribeSubnets(&ec2.DescribeSubnetsInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get subnets", "region", rule.Region)
		return nil, err
	}

	usage := types.UsageMap{}
	for _, v := range output.Subnets {
		if v != nil && v.VpcId != nil {
			usage[*v.VpcId]++
		}
	}
	return usage.Max(), nil
}

// natGatewaysPerAz determines the maximum number of NAT gateways in any availability zone across all availability zones in a region
func natGatewaysPerAz(rule v1alpha1.ServiceQuotaRule, s *session.Session, log logr.Logger) (*types.UsageResult, error) {
	ec2Svc := aws.EC2Service(s, rule.Region)

	subnetOutput, err := ec2Svc.DescribeSubnets(&ec2.DescribeSubnetsInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get subnets", "region", rule.Region)
		return nil, err
	}

	usage := types.UsageMap{}
	subnetToAzMap := make(map[string]string, 0)
	for _, s := range subnetOutput.Subnets {
		if s.SubnetId != nil && s.AvailabilityZone != nil {
			subnetToAzMap[*s.SubnetId] = *s.AvailabilityZone
			usage[*s.AvailabilityZone] = 0
		}
	}

	natGatewayOutput, err := ec2Svc.DescribeNatGateways(&ec2.DescribeNatGatewaysInput{})
	if err != nil {
		log.V(0).Error(err, "failed to get availability zones", "region", rule.Region)
		return nil, err
	}
	for _, v := range natGatewayOutput.NatGateways {
		if v != nil && v.SubnetId != nil {
			az, ok := subnetToAzMap[*v.SubnetId]
			if ok {
				usage[az]++
			}
		}
	}
	return usage.Max(), nil
}

// Package servicequota handles ServiceQuota validation rule reconciliation.
package servicequota

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	sqtypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapitypes "github.com/validator-labs/validator/pkg/types"

	"github.com/validator-labs/validator-plugin-aws/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-aws/pkg/constants"
	"github.com/validator-labs/validator-plugin-aws/pkg/validators"
)

type ec2API interface {
	DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeInternetGateways(ctx context.Context, params *ec2.DescribeInternetGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeNatGateways(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
}

type efsAPI interface {
	DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
}

type elbAPI interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancing.DescribeLoadBalancersInput, ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancersOutput, error)
}

type elbv2API interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
}

type sqAPI interface {
	ListServiceQuotas(context.Context, *servicequotas.ListServiceQuotasInput, ...func(*servicequotas.Options)) (*servicequotas.ListServiceQuotasOutput, error)
}

// RuleService reconciles ServiceQuota validation rules.
type RuleService struct {
	log      logr.Logger
	ec2Svc   ec2API
	efsSvc   efsAPI
	elbSvc   elbAPI
	elbv2Svc elbv2API
	sqSvc    sqAPI
}

// NewServiceQuotaRuleService creates a new RuleService.
func NewServiceQuotaRuleService(log logr.Logger, ec2Svc ec2API, efsSvc efsAPI, elbSvc elbAPI, elbv2Svc elbv2API, sqSvc sqAPI) *RuleService {
	return &RuleService{
		log:      log,
		ec2Svc:   ec2Svc,
		efsSvc:   efsSvc,
		elbSvc:   elbSvc,
		elbv2Svc: elbv2Svc,
		sqSvc:    sqSvc,
	}
}

// execQuotaUsageFunc maps AWS service quota names to functions that compute the usage and/or maximum usage for each service (maximum if the quota is broken out by VPC, AZ, etc.)
func (s *RuleService) execQuotaUsageFunc(quotaName string, rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	switch quotaName {
	// EC2
	case "EC2-VPC Elastic IPs":
		return s.elasticIPsPerRegion(rule)
	case "Public AMIs":
		return s.publicAMIsPerRegion(rule)
	// EFS
	case "File systems per account":
		return s.filesystemsPerRegion(rule)
	// ELB
	case "Application Load Balancers per Region":
		return s.albsPerRegion(rule)
	case "Classic Load Balancers per Region":
		return s.clbsPerRegion(rule)
	case "Network Load Balancers per Region":
		return s.nlbsPerRegion(rule)
	// VPC
	case "Internet gateways per Region":
		return s.igsPerRegion(rule)
	case "Network interfaces per Region":
		return s.nicsPerRegion(rule)
	case "VPCs per Region":
		return s.vpcsPerRegion(rule)
	case "Subnets per VPC":
		return s.subnetsPerVpc(rule)
	case "NAT gateways per Availability Zone":
		return s.natGatewaysPerAz(rule)
	default:
		return nil, fmt.Errorf("invalid service quota name: %s", rule.ServiceCode)
	}
}

// ReconcileServiceQuotaRule reconciles an AWS service quota validation rule from the AWSValidator config
func (s *RuleService) ReconcileServiceQuotaRule(rule v1alpha1.ServiceQuotaRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default latest condition for this service quota rule
	vr := validators.BuildValidationResult(
		rule.Name(), "Usage for all service quotas is below specified buffer", constants.ValidationTypeServiceQuota,
	)

	// Fetch the quota by service code & name & compare against usage
	failures := make([]string, 0)

	sqPager := servicequotas.NewListServiceQuotasPaginator(s.sqSvc, &servicequotas.ListServiceQuotasInput{
		ServiceCode: &rule.ServiceCode,
	})

	quotaMap := make(map[string]sqtypes.ServiceQuota, 0)
	for sqPager.HasMorePages() {
		page, err := sqPager.NextPage(context.Background())
		if err != nil {
			s.log.V(0).Error(err, "failed to get service quotas", "region", rule.Region, "serviceCode", rule.ServiceCode)
			return vr, err
		}
		for _, q := range page.Quotas {
			if q.QuotaName != nil {
				quotaMap[*q.QuotaName] = q
			}
		}
	}

	for _, ruleQuota := range rule.ServiceQuotas {
		usageResult, err := s.execQuotaUsageFunc(ruleQuota.Name, rule)
		if err != nil {
			s.log.V(0).Error(err, "failed to get usage for service quota", "region", rule.Region, "serviceCode", rule.ServiceCode, "quotaName", ruleQuota.Name)
			return vr, err
		}

		quota, ok := quotaMap[ruleQuota.Name]
		if !ok {
			s.log.V(0).Info("failed to get service quota", "region", rule.Region, "serviceCode", rule.ServiceCode, "quotaName", ruleQuota.Name)
			continue
		}

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
		vr.Condition.Details = append(vr.Condition.Details, quotaDetail)
	}

	if len(failures) > 0 {
		state := vapi.ValidationFailed
		vr.State = &state
		vr.Condition.Failures = failures
		vr.Condition.Message = "Usage for one or more service quotas exceeded the specified buffer"
		vr.Condition.Status = corev1.ConditionFalse
	}

	return vr, nil
}

// EC2

// elasticIPsPerRegion determines the number of elastic IPs in use in a region
func (s *RuleService) elasticIPsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.ec2Svc.DescribeAddresses(context.Background(), &ec2.DescribeAddressesInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get elastic IPs", "region", rule.Region)
		return nil, err
	}

	var usage float64
	for _, a := range output.Addresses {
		if a.AssociationId != nil {
			usage++
		}
	}
	return &usageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// publicAMIsPerRegion determines the number of public AMIs in use in a region
func (s *RuleService) publicAMIsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.ec2Svc.DescribeImages(context.Background(), &ec2.DescribeImagesInput{
		ExecutableUsers: []string{"self"},
	})
	if err != nil {
		s.log.V(0).Error(err, "failed to get public AMIs", "region", rule.Region)
		return nil, err
	}
	return &usageResult{Description: rule.Region, MaxUsage: float64(len(output.Images))}, nil
}

// EFS

// filesystemsPerRegion determines the number of EFS filesystems in use in a region
func (s *RuleService) filesystemsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.efsSvc.DescribeFileSystems(context.Background(), &efs.DescribeFileSystemsInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get EFS filesystems", "region", rule.Region)
		return nil, err
	}
	return &usageResult{Description: rule.Region, MaxUsage: float64(len(output.FileSystems))}, nil
}

// ELB

// albsPerRegion determines the number of application load balancers in use in a region
func (s *RuleService) albsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	var usage float64
	lbPager := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(s.elbv2Svc, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for lbPager.HasMorePages() {
		page, err := lbPager.NextPage(context.Background())
		if err != nil {
			s.log.V(0).Error(err, "failed to get application load balancers", "region", rule.Region)
			return nil, err
		}
		for _, lb := range page.LoadBalancers {
			if lb.Type == elbv2types.LoadBalancerTypeEnumApplication {
				usage++
			}
		}
	}
	return &usageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// clbsPerRegion determines the number of classic load balancers in use in a region
func (s *RuleService) clbsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	var usage float64
	lbPager := elasticloadbalancing.NewDescribeLoadBalancersPaginator(s.elbSvc, &elasticloadbalancing.DescribeLoadBalancersInput{})
	for lbPager.HasMorePages() {
		page, err := lbPager.NextPage(context.Background())
		if err != nil {
			s.log.V(0).Error(err, "failed to get classic load balancers", "region", rule.Region)
			return nil, err
		}
		usage += float64(len(page.LoadBalancerDescriptions))
	}
	return &usageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// nlbsPerRegion determines the number of network load balancers in use in a region
func (s *RuleService) nlbsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	var usage float64
	lbPager := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(s.elbv2Svc, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for lbPager.HasMorePages() {
		page, err := lbPager.NextPage(context.Background())
		if err != nil {
			s.log.V(0).Error(err, "failed to get network load balancers", "region", rule.Region)
			return nil, err
		}
		for _, lb := range page.LoadBalancers {
			if lb.Type == elbv2types.LoadBalancerTypeEnumNetwork {
				usage++
			}
		}
	}
	return &usageResult{Description: rule.Region, MaxUsage: usage}, nil
}

// VPC

// igsPerRegion determines the number of internet gateways in use in a region
func (s *RuleService) igsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.ec2Svc.DescribeInternetGateways(context.Background(), &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get internet gateways", "region", rule.Region)
		return nil, err
	}
	return &usageResult{Description: rule.Region, MaxUsage: float64(len(output.InternetGateways))}, nil
}

// nicsPerRegion determines the number of network interfaces in use in a region
func (s *RuleService) nicsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.ec2Svc.DescribeNetworkInterfaces(context.Background(), &ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get network interfaces", "region", rule.Region)
		return nil, err
	}
	return &usageResult{Description: rule.Region, MaxUsage: float64(len(output.NetworkInterfaces))}, nil
}

// vpcsPerRegion determines the number of VPCs in a region
func (s *RuleService) vpcsPerRegion(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.ec2Svc.DescribeVpcs(context.Background(), &ec2.DescribeVpcsInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get VPCs", "region", rule.Region)
		return nil, err
	}
	return &usageResult{Description: rule.Region, MaxUsage: float64(len(output.Vpcs))}, nil
}

// subnetsPerVpc determines the maximum number of subnets in any VPC across all VPCs in a region
func (s *RuleService) subnetsPerVpc(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	output, err := s.ec2Svc.DescribeSubnets(context.Background(), &ec2.DescribeSubnetsInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get subnets", "region", rule.Region)
		return nil, err
	}

	usage := usageMap{}
	for _, v := range output.Subnets {
		if v.VpcId != nil {
			usage[*v.VpcId]++
		}
	}
	return usage.Max(), nil
}

// natGatewaysPerAz determines the maximum number of NAT gateways in any availability zone across all availability zones in a region
func (s *RuleService) natGatewaysPerAz(rule v1alpha1.ServiceQuotaRule) (*usageResult, error) {
	subnetOutput, err := s.ec2Svc.DescribeSubnets(context.Background(), &ec2.DescribeSubnetsInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get subnets", "region", rule.Region)
		return nil, err
	}

	usage := usageMap{}
	subnetToAzMap := make(map[string]string, 0)
	for _, s := range subnetOutput.Subnets {
		if s.SubnetId != nil && s.AvailabilityZone != nil {
			subnetToAzMap[*s.SubnetId] = *s.AvailabilityZone
			usage[*s.AvailabilityZone] = 0
		}
	}

	natGatewayOutput, err := s.ec2Svc.DescribeNatGateways(context.Background(), &ec2.DescribeNatGatewaysInput{})
	if err != nil {
		s.log.V(0).Error(err, "failed to get availability zones", "region", rule.Region)
		return nil, err
	}
	for _, v := range natGatewayOutput.NatGateways {
		if v.SubnetId != nil {
			az, ok := subnetToAzMap[*v.SubnetId]
			if ok {
				usage[az]++
			}
		}
	}
	return usage.Max(), nil
}

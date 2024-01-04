package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-aws/api/v1alpha1"
)

type AwsApi struct {
	IAM   *iam.Client
	EC2   *ec2.Client
	EFS   *efs.Client
	ELB   *elasticloadbalancing.Client
	ELBV2 *elasticloadbalancingv2.Client
	SQ    *servicequotas.Client
}

// NewAwsApi creates an AwsApi object that aggregates AWS service clients
func NewAwsApi(log logr.Logger, auth v1alpha1.AwsAuth, region string) (*AwsApi, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithDefaultRegion(region))
	if err != nil {
		return nil, err
	}
	if auth.StsAuth != nil {
		awsStsConfig(&cfg, auth.StsAuth)
	}
	return &AwsApi{
		IAM:   iam.NewFromConfig(cfg),
		EC2:   ec2.NewFromConfig(cfg),
		EFS:   efs.NewFromConfig(cfg),
		ELB:   elasticloadbalancing.NewFromConfig(cfg),
		ELBV2: elasticloadbalancingv2.NewFromConfig(cfg),
		SQ:    servicequotas.NewFromConfig(cfg),
	}, nil
}

func awsStsConfig(cfg *aws.Config, auth *v1alpha1.AwsSTSAuth) {
	creds := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(*cfg), auth.RoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.Duration = time.Duration(auth.DurationSeconds) * time.Second
		o.RoleSessionName = auth.RoleSessionName
		if auth.ExternalId != "" {
			o.ExternalID = &auth.ExternalId
		}
	})
	cfg.Credentials = aws.NewCredentialsCache(creds)
}

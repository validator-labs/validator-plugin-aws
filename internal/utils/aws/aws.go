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
func NewAwsApi(log logr.Logger, validator *v1alpha1.AwsValidator) (*AwsApi, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithDefaultRegion(validator.Spec.DefaultRegion))
	if err != nil {
		return nil, err
	}

	if validator.Spec.Auth.StsAuth.RoleArn != "" {

		creds := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), validator.Spec.Auth.StsAuth.RoleArn, func(o *stscreds.AssumeRoleOptions) {
			o.Duration = time.Duration(validator.Spec.Auth.StsAuth.DurationSeconds) * time.Second
			o.RoleSessionName = validator.Spec.Auth.StsAuth.RoleSessionName

			if validator.Spec.Auth.StsAuth.ExternalId != "" {
				o.ExternalID = &validator.Spec.Auth.StsAuth.ExternalId
			}

		})

		cfg.Credentials = aws.NewCredentialsCache(creds)
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

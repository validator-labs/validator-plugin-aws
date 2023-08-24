package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/servicequotas"
)

// IAMService creates an AWS IAM service object for a specific session
func IAMService(session *session.Session) *iam.IAM {
	return iam.New(session, &aws.Config{})
}

// EC2Service creates an AWS EC2 service object for a specific session and region
func EC2Service(session *session.Session, region string) *ec2.EC2 {
	config := &aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}
	return ec2.New(session, config)
}

// ServiceQuotasService creates an AWS service quotas service object for a specific session and region
func ServiceQuotasService(session *session.Session, region string) *servicequotas.ServiceQuotas {
	config := &aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}
	return servicequotas.New(session, config)
}

// String wraps aws.String
func String(s string) *string {
	return aws.String(s)
}

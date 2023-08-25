package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/efs"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elbv2"
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

// EFSService creates an AWS EFS service object for a specific session and region
func EFSService(session *session.Session, region string) *efs.EFS {
	config := &aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}
	return efs.New(session, config)
}

// ELBService creates an AWS ELB service object for a specific session and region
func ELBService(session *session.Session, region string) *elb.ELB {
	config := &aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}
	return elb.New(session, config)
}

// ELBv2Service creates an AWS ELBv2 service object for a specific session and region
func ELBv2Service(session *session.Session, region string) *elbv2.ELBV2 {
	config := &aws.Config{}
	if region != "" {
		config.Region = aws.String(region)
	}
	return elbv2.New(session, config)
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

/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/validator-labs/validator/pkg/plugins"
	"github.com/validator-labs/validator/pkg/validationrule"

	"github.com/validator-labs/validator-plugin-aws/pkg/constants"
)

// AwsValidatorSpec defines the desired state of AwsValidator
type AwsValidatorSpec struct {
	Auth          AwsAuth `json:"auth,omitempty" yaml:"auth,omitempty"`
	DefaultRegion string  `json:"defaultRegion" yaml:"defaultRegion"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="AmiRules must have unique names",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	AmiRules []AmiRule `json:"amiRules,omitempty" yaml:"amiRules,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="IamRoleRules must have unique IamRoleNames",rule="self.all(e, size(self.filter(x, x.iamRoleName == e.iamRoleName)) == 1)"
	IamRoleRules []IamRoleRule `json:"iamRoleRules,omitempty" yaml:"iamRoleRules,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="IamUserRules must have unique IamUserNames",rule="self.all(e, size(self.filter(x, x.iamUserName == e.iamUserName)) == 1)"
	IamUserRules []IamUserRule `json:"iamUserRules,omitempty" yaml:"iamUserRules,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="IamGroupRules must have unique IamGroupNames",rule="self.all(e, size(self.filter(x, x.iamGroupName == e.iamGroupName)) == 1)"
	IamGroupRules []IamGroupRule `json:"iamGroupRules,omitempty" yaml:"iamGroupRules,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="IamPolicyRules must have unique ARNs",rule="self.all(e, size(self.filter(x, x.iamPolicyArn == e.iamPolicyArn)) == 1)"
	IamPolicyRules []IamPolicyRule `json:"iamPolicyRules,omitempty" yaml:"iamPolicyRules,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="ServiceQuotaRules must have unique names",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	ServiceQuotaRules []ServiceQuotaRule `json:"serviceQuotaRules,omitempty" yaml:"serviceQuotaRules,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="TagRules must have unique names",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	TagRules []TagRule `json:"tagRules,omitempty" yaml:"tagRules,omitempty"`
}

var _ plugins.PluginSpec = (*AwsValidatorSpec)(nil)

// PluginCode returns the network validator's plugin code.
func (s AwsValidatorSpec) PluginCode() string {
	return constants.PluginCode
}

// ResultCount returns the number of validation results expected for an AwsValidatorSpec.
func (s AwsValidatorSpec) ResultCount() int {
	return len(s.AmiRules) + len(s.IamGroupRules) + len(s.IamPolicyRules) + len(s.IamRoleRules) +
		len(s.IamUserRules) + len(s.ServiceQuotaRules) + len(s.TagRules)
}

// AwsAuth defines authentication configuration for an AwsValidator.
type AwsAuth struct {
	// If true, the AwsValidator will use the AWS SDK's default credential chain to authenticate.
	// Set to true if using node instance IAM role or IAM roles for Service Accounts.
	Implicit bool `json:"implicit" yaml:"implicit"`
	// Name of a Secret in the same namespace as the AwsValidator that contains AWS credentials.
	// The secret data's keys and values are expected to align with valid AWS environment variable credentials,
	// per the options defined in https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#environment-variables.
	SecretName string `json:"secretName,omitempty" yaml:"secretName,omitempty"`
	// The credentials to use when running in direct mode. If provided, fields Implicit and SecretName are ignored.
	Credentials *Credentials `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	// STS authentication properties (optional)
	StsAuth *AwsSTSAuth `json:"stsAuth,omitempty" yaml:"stsAuth,omitempty"`
}

// Credentials is the credentials to use when running in direct mode.
type Credentials struct {
	// The access key ID of an access key pair.
	AccessKeyID string `json:"accessKeyId" yaml:"accessKeyId"`
	// The secret access key of an access key pair.
	SecretAccessKey string `json:"secretAccessKey" yaml:"secretAccessKey"`
}

// AwsSTSAuth defines AWS STS authentication configuration for an AwsValidator.
type AwsSTSAuth struct {
	// The Amazon Resource Name (ARN) of the role to assume.
	RoleArn string `json:"roleArn" yaml:"roleArn"`
	// An identifier for the assumed role session.
	RoleSessionName string `json:"roleSessionName" yaml:"roleSessionName"`
	// The duration, in seconds, of the role session.
	// +kubebuilder:default=3600
	// +kubebuilder:validation:Minimum=900
	// +kubebuilder:validation:Maximum=43200
	DurationSeconds int `json:"durationSeconds" yaml:"durationSeconds"`
	// A unique identifier that might be required when you assume a role in another account.
	ExternalID string `json:"externalId,omitempty" yaml:"externalId,omitempty"`
}

// AmiRule ensures that an EC2 AMI exists in a particular region.
// AMIs can be matched by any combination of ID, owner, and filter(s).
// Each AmiRule is intended to match a single AMI, as an AmiRule is considered successful if at least one AMI is found.
// Refer to https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImages.html for more information.
type AmiRule struct {
	validationrule.ManuallyNamed `json:",inline" yaml:",omitempty"`

	RuleName string   `json:"name" yaml:"name"`
	AmiIDs   []string `json:"amiIds,omitempty" yaml:"amiIds,omitempty"`
	Filters  []Filter `json:"filters,omitempty" yaml:"filters,omitempty"`
	Owners   []string `json:"owners,omitempty" yaml:"owners,omitempty"`
	Region   string   `json:"region" yaml:"region"`
}

var _ validationrule.Interface = (*AmiRule)(nil)

// Name returns the name of the AmiRule.
func (r AmiRule) Name() string {
	return r.RuleName
}

// SetName sets the name of the AmiRule.
func (r *AmiRule) SetName(name string) {
	r.RuleName = name
}

// Filter defines a filter to apply to an AWS API query.
type Filter struct {
	Key    string   `json:"key" yaml:"key"`
	Values []string `json:"values" yaml:"values"`
	IsTag  bool     `json:"isTag,omitempty" yaml:"isTag,omitempty"`
}

// IamRoleRule compares the IAM permissions associated with an IAM role against an expected permission set.
type IamRoleRule struct {
	validationrule.AutomaticallyNamed `json:",inline" yaml:",omitempty"`

	IamRoleName string           `json:"iamRoleName" yaml:"iamRoleName"`
	Policies    []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

var _ validationrule.Interface = (*IamRoleRule)(nil)

// Name returns the name of an IamRoleRule.
func (r IamRoleRule) Name() string {
	return r.IamRoleName
}

// IAMPolicies returns the IAM policies associated with an IamRoleRule.
func (r IamRoleRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

// IamUserRule compares the IAM permissions associated with an IAM user against an expected permission set.
type IamUserRule struct {
	validationrule.AutomaticallyNamed `json:",inline" yaml:",omitempty"`

	IamUserName string           `json:"iamUserName" yaml:"iamUserName"`
	Policies    []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

var _ validationrule.Interface = (*IamUserRule)(nil)

// Name returns the name of an IamUserRule.
func (r IamUserRule) Name() string {
	return r.IamUserName
}

// IAMPolicies returns the IAM policies associated with an IamUserRule.
func (r IamUserRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

// IamGroupRule compares the IAM permissions associated with an IAM group against an expected permission set.
type IamGroupRule struct {
	validationrule.AutomaticallyNamed `json:",inline" yaml:",omitempty"`

	IamGroupName string           `json:"iamGroupName" yaml:"iamGroupName"`
	Policies     []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

var _ validationrule.Interface = (*IamGroupRule)(nil)

// Name returns the name of an IamGroupRule.
func (r IamGroupRule) Name() string {
	return r.IamGroupName
}

// IAMPolicies returns the IAM policies associated with an IamGroupRule.
func (r IamGroupRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

// IamPolicyRule compares the IAM permissions associated with an IAM policy against an expected permission set.
type IamPolicyRule struct {
	validationrule.AutomaticallyNamed `json:",inline" yaml:",omitempty"`

	IamPolicyARN string           `json:"iamPolicyArn" yaml:"iamPolicyArn"`
	Policies     []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

var _ validationrule.Interface = (*IamPolicyRule)(nil)

// Name returns the name of an IamPolicyRule.
func (r IamPolicyRule) Name() string {
	return r.IamPolicyARN
}

// IAMPolicies returns the IAM policies associated with an IamPolicyRule.
func (r IamPolicyRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

// PolicyDocument defines an IAM policy document.
type PolicyDocument struct {
	Name       string           `json:"name" yaml:"name"`
	Version    string           `json:"version" yaml:"version"`
	Statements []StatementEntry `json:"statements" yaml:"statements"`
}

// StatementEntry defines an IAM policy statement.
type StatementEntry struct {
	Condition Condition `json:"condition,omitempty" yaml:"condition,omitempty"`
	Effect    string    `json:"effect" yaml:"effect"`
	Actions   []string  `json:"actions" yaml:"actions"`
	Resources []string  `json:"resources" yaml:"resources"`
}

// Condition defines an IAM policy condition.
type Condition map[string]map[string][]string

// String returns a string representation of an IAM Condition.
func (c Condition) String() string {
	sb := strings.Builder{}
	for k, v := range c {
		sb.WriteString(fmt.Sprintf("%s: ", k))

		for subk, subv := range v {
			sb.WriteString(fmt.Sprintf("%s=%s; ", subk, subv))
		}
	}
	return sb.String()
}

// ServiceQuotaRule ensures that AWS service quotas are within a particular threshold.
type ServiceQuotaRule struct {
	validationrule.ManuallyNamed `json:",inline" yaml:",omitempty"`

	RuleName      string         `json:"name" yaml:"name"`
	Region        string         `json:"region" yaml:"region"`
	ServiceCode   string         `json:"serviceCode" yaml:"serviceCode"`
	ServiceQuotas []ServiceQuota `json:"serviceQuotas" yaml:"serviceQuotas"`
}

var _ validationrule.Interface = (*ServiceQuotaRule)(nil)

// Name returns the name of the ServiceQuotaRule.
func (r ServiceQuotaRule) Name() string {
	return r.RuleName
}

// SetName sets the name of the ServiceQuotaRule.
func (r *ServiceQuotaRule) SetName(name string) {
	r.RuleName = name
}

// ServiceQuota defines an AWS service quota and an associated buffer.
type ServiceQuota struct {
	Name   string `json:"name" yaml:"name"`
	Buffer int    `json:"buffer" yaml:"buffer"`
}

// TagRule ensures that the tags associated with a particular AWS resource match an expected tag set.
type TagRule struct {
	validationrule.ManuallyNamed `json:",inline" yaml:",omitempty"`

	RuleName      string   `json:"name" yaml:"name"`
	Key           string   `json:"key" yaml:"key"`
	ExpectedValue string   `json:"expectedValue" yaml:"expectedValue"`
	Region        string   `json:"region" yaml:"region"`
	ResourceType  string   `json:"resourceType" yaml:"resourceType"`
	ARNs          []string `json:"arns" yaml:"arns"`
}

var _ validationrule.Interface = (*TagRule)(nil)

// Name returns the name of the ServiceQuotaRule.
func (r TagRule) Name() string {
	return r.RuleName
}

// SetName sets the name of the ServiceQuotaRule.
func (r *TagRule) SetName(name string) {
	r.RuleName = name
}

// AwsValidatorStatus defines the observed state of AwsValidator
type AwsValidatorStatus struct{}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AwsValidator is the Schema for the awsvalidators API
type AwsValidator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AwsValidatorSpec   `json:"spec,omitempty"`
	Status AwsValidatorStatus `json:"status,omitempty"`
}

// GetKind returns the AWS validator's kind.
func (v AwsValidator) GetKind() string {
	return reflect.TypeOf(v).Name()
}

// PluginCode returns the AWS validator's plugin code.
func (v AwsValidator) PluginCode() string {
	return v.Spec.PluginCode()
}

// ResultCount returns the number of validation results expected for an AwsValidator.
func (v AwsValidator) ResultCount() int {
	return v.Spec.ResultCount()
}

//+kubebuilder:object:root=true

// AwsValidatorList contains a list of AwsValidator
type AwsValidatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AwsValidator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AwsValidator{}, &AwsValidatorList{})
}

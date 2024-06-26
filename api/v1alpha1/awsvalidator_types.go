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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AwsValidatorSpec defines the desired state of AwsValidator
type AwsValidatorSpec struct {
	Auth          AwsAuth `json:"auth,omitempty" yaml:"auth,omitempty"`
	DefaultRegion string  `json:"defaultRegion" yaml:"defaultRegion"`
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

func (s AwsValidatorSpec) ResultCount() int {
	return len(s.IamGroupRules) + len(s.IamPolicyRules) + len(s.IamRoleRules) + len(s.IamUserRules) +
		len(s.ServiceQuotaRules) + len(s.TagRules)
}

type AwsAuth struct {
	// If true, the AwsValidator will use the AWS SDK's default credential chain to authenticate.
	// Set to true if using node instance IAM role or IAM roles for Service Accounts.
	Implicit bool `json:"implicit" yaml:"implicit"`
	// Name of a Secret in the same namespace as the AwsValidator that contains AWS credentials.
	// The secret data's keys and values are expected to align with valid AWS environment variable credentials,
	// per the options defined in https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#environment-variables.
	SecretName string `json:"secretName,omitempty" yaml:"secretName,omitempty"`
	// STS authentication properties (optional)
	StsAuth *AwsSTSAuth `json:"stsAuth,omitempty" yaml:"stsAuth,omitempty"`
}

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
	ExternalId string `json:"externalId,omitempty" yaml:"externalId,omitempty"`
}

type IamRoleRule struct {
	IamRoleName string           `json:"iamRoleName" yaml:"iamRoleName"`
	Policies    []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

func (r IamRoleRule) Name() string {
	return r.IamRoleName
}

func (r IamRoleRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

type IamUserRule struct {
	IamUserName string           `json:"iamUserName" yaml:"iamUserName"`
	Policies    []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

func (r IamUserRule) Name() string {
	return r.IamUserName
}

func (r IamUserRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

type IamGroupRule struct {
	IamGroupName string           `json:"iamGroupName" yaml:"iamGroupName"`
	Policies     []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

func (r IamGroupRule) Name() string {
	return r.IamGroupName
}

func (r IamGroupRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

type IamPolicyRule struct {
	IamPolicyARN string           `json:"iamPolicyArn" yaml:"iamPolicyArn"`
	Policies     []PolicyDocument `json:"iamPolicies" yaml:"iamPolicies"`
}

func (r IamPolicyRule) Name() string {
	return r.IamPolicyARN
}

func (r IamPolicyRule) IAMPolicies() []PolicyDocument {
	return r.Policies
}

type PolicyDocument struct {
	Name       string           `json:"name" yaml:"name"`
	Version    string           `json:"version" yaml:"version"`
	Statements []StatementEntry `json:"statements" yaml:"statements"`
}

type StatementEntry struct {
	Condition Condition `json:"condition,omitempty" yaml:"condition,omitempty"`
	Effect    string    `json:"effect" yaml:"effect"`
	Actions   []string  `json:"actions" yaml:"actions"`
	Resources []string  `json:"resources" yaml:"resources"`
}

type Condition map[string]map[string][]string

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

type ServiceQuotaRule struct {
	Name          string         `json:"name" yaml:"name"`
	Region        string         `json:"region" yaml:"region"`
	ServiceCode   string         `json:"serviceCode" yaml:"serviceCode"`
	ServiceQuotas []ServiceQuota `json:"serviceQuotas" yaml:"serviceQuotas"`
}

type ServiceQuota struct {
	Name   string `json:"name" yaml:"name"`
	Buffer int    `json:"buffer" yaml:"buffer"`
}

type TagRule struct {
	Name          string   `json:"name" yaml:"name"`
	Key           string   `json:"key" yaml:"key"`
	ExpectedValue string   `json:"expectedValue" yaml:"expectedValue"`
	Region        string   `json:"region" yaml:"region"`
	ResourceType  string   `json:"resourceType" yaml:"resourceType"`
	ARNs          []string `json:"arns" yaml:"arns"`
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

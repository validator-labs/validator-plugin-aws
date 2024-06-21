//go:build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AwsAuth) DeepCopyInto(out *AwsAuth) {
	*out = *in
	if in.StsAuth != nil {
		in, out := &in.StsAuth, &out.StsAuth
		*out = new(AwsSTSAuth)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AwsAuth.
func (in *AwsAuth) DeepCopy() *AwsAuth {
	if in == nil {
		return nil
	}
	out := new(AwsAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AwsSTSAuth) DeepCopyInto(out *AwsSTSAuth) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AwsSTSAuth.
func (in *AwsSTSAuth) DeepCopy() *AwsSTSAuth {
	if in == nil {
		return nil
	}
	out := new(AwsSTSAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AwsValidator) DeepCopyInto(out *AwsValidator) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AwsValidator.
func (in *AwsValidator) DeepCopy() *AwsValidator {
	if in == nil {
		return nil
	}
	out := new(AwsValidator)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AwsValidator) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AwsValidatorList) DeepCopyInto(out *AwsValidatorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AwsValidator, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AwsValidatorList.
func (in *AwsValidatorList) DeepCopy() *AwsValidatorList {
	if in == nil {
		return nil
	}
	out := new(AwsValidatorList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AwsValidatorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AwsValidatorSpec) DeepCopyInto(out *AwsValidatorSpec) {
	*out = *in
	in.Auth.DeepCopyInto(&out.Auth)
	if in.IamRoleRules != nil {
		in, out := &in.IamRoleRules, &out.IamRoleRules
		*out = make([]IamRoleRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.IamUserRules != nil {
		in, out := &in.IamUserRules, &out.IamUserRules
		*out = make([]IamUserRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.IamGroupRules != nil {
		in, out := &in.IamGroupRules, &out.IamGroupRules
		*out = make([]IamGroupRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.IamPolicyRules != nil {
		in, out := &in.IamPolicyRules, &out.IamPolicyRules
		*out = make([]IamPolicyRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.ServiceQuotaRules != nil {
		in, out := &in.ServiceQuotaRules, &out.ServiceQuotaRules
		*out = make([]ServiceQuotaRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.TagRules != nil {
		in, out := &in.TagRules, &out.TagRules
		*out = make([]TagRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AwsValidatorSpec.
func (in *AwsValidatorSpec) DeepCopy() *AwsValidatorSpec {
	if in == nil {
		return nil
	}
	out := new(AwsValidatorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AwsValidatorStatus) DeepCopyInto(out *AwsValidatorStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AwsValidatorStatus.
func (in *AwsValidatorStatus) DeepCopy() *AwsValidatorStatus {
	if in == nil {
		return nil
	}
	out := new(AwsValidatorStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in Condition) DeepCopyInto(out *Condition) {
	{
		in := &in
		*out = make(Condition, len(*in))
		for key, val := range *in {
			var outVal map[string][]string
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = make(map[string][]string, len(*in))
				for key, val := range *in {
					var outVal []string
					if val == nil {
						(*out)[key] = nil
					} else {
						inVal := (*in)[key]
						in, out := &inVal, &outVal
						*out = make([]string, len(*in))
						copy(*out, *in)
					}
					(*out)[key] = outVal
				}
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Condition.
func (in Condition) DeepCopy() Condition {
	if in == nil {
		return nil
	}
	out := new(Condition)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IamGroupRule) DeepCopyInto(out *IamGroupRule) {
	*out = *in
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]PolicyDocument, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IamGroupRule.
func (in *IamGroupRule) DeepCopy() *IamGroupRule {
	if in == nil {
		return nil
	}
	out := new(IamGroupRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IamPolicyRule) DeepCopyInto(out *IamPolicyRule) {
	*out = *in
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]PolicyDocument, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IamPolicyRule.
func (in *IamPolicyRule) DeepCopy() *IamPolicyRule {
	if in == nil {
		return nil
	}
	out := new(IamPolicyRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IamRoleRule) DeepCopyInto(out *IamRoleRule) {
	*out = *in
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]PolicyDocument, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IamRoleRule.
func (in *IamRoleRule) DeepCopy() *IamRoleRule {
	if in == nil {
		return nil
	}
	out := new(IamRoleRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IamUserRule) DeepCopyInto(out *IamUserRule) {
	*out = *in
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]PolicyDocument, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IamUserRule.
func (in *IamUserRule) DeepCopy() *IamUserRule {
	if in == nil {
		return nil
	}
	out := new(IamUserRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyDocument) DeepCopyInto(out *PolicyDocument) {
	*out = *in
	if in.Statements != nil {
		in, out := &in.Statements, &out.Statements
		*out = make([]StatementEntry, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyDocument.
func (in *PolicyDocument) DeepCopy() *PolicyDocument {
	if in == nil {
		return nil
	}
	out := new(PolicyDocument)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceQuota) DeepCopyInto(out *ServiceQuota) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceQuota.
func (in *ServiceQuota) DeepCopy() *ServiceQuota {
	if in == nil {
		return nil
	}
	out := new(ServiceQuota)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceQuotaRule) DeepCopyInto(out *ServiceQuotaRule) {
	*out = *in
	if in.ServiceQuotas != nil {
		in, out := &in.ServiceQuotas, &out.ServiceQuotas
		*out = make([]ServiceQuota, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceQuotaRule.
func (in *ServiceQuotaRule) DeepCopy() *ServiceQuotaRule {
	if in == nil {
		return nil
	}
	out := new(ServiceQuotaRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StatementEntry) DeepCopyInto(out *StatementEntry) {
	*out = *in
	if in.Condition != nil {
		in, out := &in.Condition, &out.Condition
		*out = make(Condition, len(*in))
		for key, val := range *in {
			var outVal map[string][]string
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = make(map[string][]string, len(*in))
				for key, val := range *in {
					var outVal []string
					if val == nil {
						(*out)[key] = nil
					} else {
						inVal := (*in)[key]
						in, out := &inVal, &outVal
						*out = make([]string, len(*in))
						copy(*out, *in)
					}
					(*out)[key] = outVal
				}
			}
			(*out)[key] = outVal
		}
	}
	if in.Actions != nil {
		in, out := &in.Actions, &out.Actions
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StatementEntry.
func (in *StatementEntry) DeepCopy() *StatementEntry {
	if in == nil {
		return nil
	}
	out := new(StatementEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TagRule) DeepCopyInto(out *TagRule) {
	*out = *in
	if in.ARNs != nil {
		in, out := &in.ARNs, &out.ARNs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TagRule.
func (in *TagRule) DeepCopy() *TagRule {
	if in == nil {
		return nil
	}
	out := new(TagRule)
	in.DeepCopyInto(out)
	return out
}

//go:build !ignore_autogenerated

/*
Copyright 2025.

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

package v1beta1

import (
	"encoding/json"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaCommonSpec) DeepCopyInto(out *GrafanaCommonSpec) {
	*out = *in
	out.ResyncPeriod = in.ResyncPeriod
	if in.InstanceSelector != nil {
		in, out := &in.InstanceSelector, &out.InstanceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaCommonSpec.
func (in *GrafanaCommonSpec) DeepCopy() *GrafanaCommonSpec {
	if in == nil {
		return nil
	}
	out := new(GrafanaCommonSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaCommonStatus) DeepCopyInto(out *GrafanaCommonStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	in.LastResync.DeepCopyInto(&out.LastResync)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaCommonStatus.
func (in *GrafanaCommonStatus) DeepCopy() *GrafanaCommonStatus {
	if in == nil {
		return nil
	}
	out := new(GrafanaCommonStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaDatasource) DeepCopyInto(out *GrafanaDatasource) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaDatasource.
func (in *GrafanaDatasource) DeepCopy() *GrafanaDatasource {
	if in == nil {
		return nil
	}
	out := new(GrafanaDatasource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GrafanaDatasource) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaDatasourceInternal) DeepCopyInto(out *GrafanaDatasourceInternal) {
	*out = *in
	if in.IsDefault != nil {
		in, out := &in.IsDefault, &out.IsDefault
		*out = new(bool)
		**out = **in
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(bool)
		**out = **in
	}
	if in.OrgID != nil {
		in, out := &in.OrgID, &out.OrgID
		*out = new(int64)
		**out = **in
	}
	if in.Editable != nil {
		in, out := &in.Editable, &out.Editable
		*out = new(bool)
		**out = **in
	}
	if in.JSONData != nil {
		in, out := &in.JSONData, &out.JSONData
		*out = make(json.RawMessage, len(*in))
		copy(*out, *in)
	}
	if in.SecureJSONData != nil {
		in, out := &in.SecureJSONData, &out.SecureJSONData
		*out = make(json.RawMessage, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaDatasourceInternal.
func (in *GrafanaDatasourceInternal) DeepCopy() *GrafanaDatasourceInternal {
	if in == nil {
		return nil
	}
	out := new(GrafanaDatasourceInternal)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaDatasourceList) DeepCopyInto(out *GrafanaDatasourceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GrafanaDatasource, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaDatasourceList.
func (in *GrafanaDatasourceList) DeepCopy() *GrafanaDatasourceList {
	if in == nil {
		return nil
	}
	out := new(GrafanaDatasourceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GrafanaDatasourceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaDatasourceSpec) DeepCopyInto(out *GrafanaDatasourceSpec) {
	*out = *in
	in.GrafanaCommonSpec.DeepCopyInto(&out.GrafanaCommonSpec)
	if in.Datasource != nil {
		in, out := &in.Datasource, &out.Datasource
		*out = new(GrafanaDatasourceInternal)
		(*in).DeepCopyInto(*out)
	}
	if in.Plugins != nil {
		in, out := &in.Plugins, &out.Plugins
		*out = make(PluginList, len(*in))
		copy(*out, *in)
	}
	if in.ValuesFrom != nil {
		in, out := &in.ValuesFrom, &out.ValuesFrom
		*out = make([]ValueFrom, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaDatasourceSpec.
func (in *GrafanaDatasourceSpec) DeepCopy() *GrafanaDatasourceSpec {
	if in == nil {
		return nil
	}
	out := new(GrafanaDatasourceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaDatasourceStatus) DeepCopyInto(out *GrafanaDatasourceStatus) {
	*out = *in
	in.GrafanaCommonStatus.DeepCopyInto(&out.GrafanaCommonStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaDatasourceStatus.
func (in *GrafanaDatasourceStatus) DeepCopy() *GrafanaDatasourceStatus {
	if in == nil {
		return nil
	}
	out := new(GrafanaDatasourceStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GrafanaPlugin) DeepCopyInto(out *GrafanaPlugin) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GrafanaPlugin.
func (in *GrafanaPlugin) DeepCopy() *GrafanaPlugin {
	if in == nil {
		return nil
	}
	out := new(GrafanaPlugin)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in PluginList) DeepCopyInto(out *PluginList) {
	{
		in := &in
		*out = make(PluginList, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PluginList.
func (in PluginList) DeepCopy() PluginList {
	if in == nil {
		return nil
	}
	out := new(PluginList)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in PluginMap) DeepCopyInto(out *PluginMap) {
	{
		in := &in
		*out = make(PluginMap, len(*in))
		for key, val := range *in {
			var outVal []GrafanaPlugin
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = make(PluginList, len(*in))
				copy(*out, *in)
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PluginMap.
func (in PluginMap) DeepCopy() PluginMap {
	if in == nil {
		return nil
	}
	out := new(PluginMap)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ValueFrom) DeepCopyInto(out *ValueFrom) {
	*out = *in
	in.ValueFrom.DeepCopyInto(&out.ValueFrom)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ValueFrom.
func (in *ValueFrom) DeepCopy() *ValueFrom {
	if in == nil {
		return nil
	}
	out := new(ValueFrom)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ValueFromSource) DeepCopyInto(out *ValueFromSource) {
	*out = *in
	if in.ConfigMapKeyRef != nil {
		in, out := &in.ConfigMapKeyRef, &out.ConfigMapKeyRef
		*out = new(v1.ConfigMapKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.SecretKeyRef != nil {
		in, out := &in.SecretKeyRef, &out.SecretKeyRef
		*out = new(v1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ValueFromSource.
func (in *ValueFromSource) DeepCopy() *ValueFromSource {
	if in == nil {
		return nil
	}
	out := new(ValueFromSource)
	in.DeepCopyInto(out)
	return out
}

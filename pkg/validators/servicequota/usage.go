package servicequota

import "sort"

// usageResult describes the maximum usage for an arbitrary category.
type usageResult struct {
	Description string
	MaxUsage    float64
}

// usageMap maps categories to their usage.
type usageMap map[string]float64

// Max returns a usageResult describing the category with the maximum usage within a UsageMap
func (u usageMap) Max() *usageResult {
	var maxUsage float64
	var maxUsageKey string

	keys := make([]string, 0, len(u))
	for k := range u {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := u[k]
		if v > maxUsage {
			maxUsage = v
			maxUsageKey = k
		}
	}
	return &usageResult{Description: maxUsageKey, MaxUsage: maxUsage}
}

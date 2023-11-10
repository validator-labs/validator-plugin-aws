package types

import "sort"

// UsageResult describes the maximum usage for an arbitrary category
type UsageResult struct {
	Description string
	MaxUsage    float64
}

// UsageMap maps categories to their usage
type UsageMap map[string]float64

// Max returns a UsageResult describing the category with the maximum usage within a UsageMap
func (u UsageMap) Max() *UsageResult {
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
	return &UsageResult{Description: maxUsageKey, MaxUsage: maxUsage}
}

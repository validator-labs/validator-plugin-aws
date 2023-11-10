package types

import (
	"reflect"
	"testing"
)

func TestMax(t *testing.T) {
	cs := []struct {
		name     string
		usageMap UsageMap
		expected UsageResult
	}{
		{
			name: "Pass basic",
			usageMap: UsageMap{
				"a": 1.0,
				"b": 2.0,
				"c": 3.0,
			},
			expected: UsageResult{
				Description: "c",
				MaxUsage:    3.0,
			},
		},
		{
			name: "Pass lexigraphic",
			usageMap: UsageMap{
				"us-east-2c": 1.0,
				"us-east-2a": 1.0,
				"us-east-2b": 1.0,
			},
			expected: UsageResult{
				Description: "us-east-2a",
				MaxUsage:    1.0,
			},
		},
	}
	for _, c := range cs {
		res := c.usageMap.Max()
		if !reflect.DeepEqual(*res, c.expected) {
			t.Errorf("expected (%+v), got (%+v)", c.expected, *res)
		}
	}
}

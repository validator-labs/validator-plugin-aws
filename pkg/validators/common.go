// Package validators defines validators for different categories of AWS validation rules.
package validators

import (
	"fmt"

	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/constants"
	"github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

// BuildValidationResult builds a default ValidationResult for a given validation type.
func BuildValidationResult(name, msg, validationType string) *types.ValidationRuleResult {
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = msg
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", constants.ValidationRulePrefix, util.Sanitize(name))
	latestCondition.ValidationType = validationType
	return &types.ValidationRuleResult{Condition: &latestCondition, State: &state}
}

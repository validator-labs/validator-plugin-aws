package types

import valid8orv1alpha1 "github.com/spectrocloud-labs/valid8or/api/v1alpha1"

type ValidationResult struct {
	Condition valid8orv1alpha1.ValidationCondition
	State     valid8orv1alpha1.ValidationState
}

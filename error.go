package idx

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ErrorResponse struct {
	ErrorCode        string                   `json:"errorCode,omitempty"`
	ErrorSummary     string                   `json:"errorSummary,omitempty"`
	ErrorLink        string                   `json:"errorLink,omitempty"`
	ErrorId          string                   `json:"errorId,omitempty"`
	ErrorCauses      []map[string]interface{} `json:"errorCauses,omitempty"`
	ErrorType        string                   `json:"error,omitempty"`
	ErrorDescription string                   `json:"error_description,omitempty"`
	raw              []byte
}

func (e *ErrorResponse) UnmarshalJSON(data []byte) error {
	type localIDX ErrorResponse
	if err := json.Unmarshal(data, (*localIDX)(e)); err != nil {
		return err
	}
	e.raw = data
	return nil
}

func (e *ErrorResponse) Error() string {
	if e == nil {
		return ""
	}
	if e.ErrorType != "" {
		return fmt.Sprintf("the API returned an error: %s", e.ErrorDescription)
	} else if e.ErrorSummary != "" {
		formattedErr := fmt.Sprintf("the API returned an error: %s", e.ErrorSummary)
		if len(e.ErrorCauses) > 0 {
			causes := make([]string, len(e.ErrorCauses))
			for i := range e.ErrorCauses {
				for key, val := range e.ErrorCauses[i] {
					causes[i] = fmt.Sprintf("%s: %v", key, val)
				}
			}
			formattedErr = fmt.Sprintf("%s. Causes: %s", formattedErr, strings.Join(causes, ", "))
		}
		return formattedErr
	}
	return string(e.raw)
}

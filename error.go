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
	ErrorID          string                   `json:"errorId,omitempty"`
	ErrorCauses      []map[string]interface{} `json:"errorCauses,omitempty"`
	ErrorType        string                   `json:"error,omitempty"`
	ErrorDescription string                   `json:"error_description,omitempty"`
	Version          string                   `json:"version"`
	Message          Message                  `json:"messages"`
	raw              []byte
}

func (e *ErrorResponse) UnmarshalJSON(data []byte) error {
	type localIDX ErrorResponse
	if err := json.Unmarshal(data, (*localIDX)(e)); err != nil {
		return fmt.Errorf("failed to unmarshal ErrorResponse: %w", err)
	}
	e.raw = data
	return nil
}

func (e *ErrorResponse) Error() string {
	f := "the API returned an error: %s"
	switch {
	case e == nil:
		return ""
	case e.ErrorType != "":
		return fmt.Sprintf(f, e.ErrorDescription)
	case len(e.ErrorCauses) > 0:
		causes := make([]string, len(e.ErrorCauses))
		for i := range e.ErrorCauses {
			for key, val := range e.ErrorCauses[i] {
				causes[i] = fmt.Sprintf("%s: %v", key, val)
			}
		}
		return fmt.Sprintf(f+". Causes: %s", e.ErrorSummary, strings.Join(causes, ", "))
	case len(e.Message.Values) > 0:
		messages := make([]string, len(e.Message.Values))
		for i := range e.Message.Values {
			messages[i] = e.Message.Values[i].Message
		}
		return fmt.Sprintf(f, strings.Join(messages, ","))
	}
	return fmt.Sprintf(f, string(e.raw))
}

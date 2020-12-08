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
	Messages         struct {
		Type  string `json:"type"`
		Value []struct {
			Message string `json:"message"`
			I18N    struct {
				Key string `json:"key"`
			} `json:"i18n"`
			Class string `json:"class"`
		} `json:"value"`
	} `json:"messages"`
	raw []byte
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
	case len(e.Messages.Value) > 0:
		messages := make([]string, len(e.Messages.Value))
		for i := range e.Messages.Value {
			messages[i] = e.Messages.Value[i].Message
		}
		return fmt.Sprintf(f, strings.Join(messages, ","))
	}
	return fmt.Sprintf(f, string(e.raw))
}

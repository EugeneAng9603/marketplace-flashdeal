package httputil

import "time"

type HttpError struct {
	Method       string    `json:"method,omitempty"`
	URL          string    `json:"url,omitempty"`
	StatusCode   int       `json:"status_code,omitempty"`
	Message      string    `json:"message,omitempty"`
	ResponseBody string    `json:"response_body,omitempty"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
}

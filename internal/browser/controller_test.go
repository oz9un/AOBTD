package browser

import (
	"errors"
	"testing"
)

func TestBrowserConnectionClosed(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{errors.New("write tcp 127.0.0.1:53548->127.0.0.1:53546: use of closed network connection"), true},
		{errors.New("websocket: close 1006 unexpected EOF"), true},
		{errors.New("read: connection reset by peer"), true},
		{errors.New("selector not found"), false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := browserConnectionClosed(tt.err); got != tt.want {
			t.Fatalf("browserConnectionClosed(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

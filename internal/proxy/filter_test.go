package proxy

import "testing"

func TestShouldFilterDropsSocketIOTransportNoise(t *testing.T) {
	cases := []string{
		"http://target.example/socket.io/?EIO=4&transport=polling&t=abc",
		"http://target.example/admin/socket.io/?EIO=4&transport=websocket&sid=abc",
	}
	for _, raw := range cases {
		if !ShouldFilter(raw, "text/plain", 32) {
			t.Fatalf("ShouldFilter(%q) = false, want true for Socket.IO transport noise", raw)
		}
	}
}

func TestShouldFilterKeepsApplicationAPI(t *testing.T) {
	if ShouldFilter("http://target.example/api/users?role=admin", "application/json", 256) {
		t.Fatal("application JSON API should not be filtered")
	}
}

func TestShouldFilterClosesStylesheetsAtCaptureTime(t *testing.T) {
	for _, fixture := range []struct {
		rawURL, contentType string
	}{
		{"https://target.example/static/main.css", "text/plain"},
		{"https://target.example/assets/theme", "text/css; charset=utf-8"},
	} {
		if !ShouldFilter(fixture.rawURL, fixture.contentType, 4096) {
			t.Fatalf("stylesheet entered downstream analysis queues: %+v", fixture)
		}
	}
	if ShouldFilter("https://target.example/static/app.js", "application/javascript", 4096) {
		t.Fatal("JavaScript was hidden from the JS analyzer with stylesheet traffic")
	}
}

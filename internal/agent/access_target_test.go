package agent

import "testing"

func TestIDORTargetLooksOwnedObject(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "owned order path",
			raw:  "https://example.test/api/orders/{id}",
			want: true,
		},
		{
			name: "owned memory query",
			raw:  "https://example.test/rest/memories/?UserId={id}",
			want: true,
		},
		{
			name: "public challenge metadata rejected",
			raw:  "https://example.test/api/Challenges/?id={id}",
			want: false,
		},
		{
			name: "inventory quantity rejected",
			raw:  "https://example.test/api/Quantitys/{id}",
			want: false,
		},
		{
			name: "docs endpoint rejected",
			raw:  "https://example.test/api-docs/{id}",
			want: false,
		},
		{
			name: "hyphenated application configuration rejected",
			raw:  "https://example.test/rest/admin/application-configuration/{id}",
			want: false,
		},
		{
			name: "public upload asset rejected",
			raw:  "https://example.test/assets/public/images/uploads/{id}.php?filename={filename}",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := idorTargetLooksOwnedObject(tt.raw); got != tt.want {
				t.Fatalf("idorTargetLooksOwnedObject(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestFollowUpTargetLooksGroundedRejectsSyntheticExamples(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"https://example.test/api/orders/1", true},
		{"https://example.test/api/SomeFormSubmitEndpoint", false},
		{"https://example.test/api/rest_captcha", false},
		{"https://example.test/api/user_profile", true},
		{"https://example.test/assets/public/images/uploads/shell.php", false},
		{"https://example.test/assets/public/images/uploads/..%2F..%2Fetc%2Fpasswd", false},
	}
	for _, tt := range tests {
		if got := followUpTargetLooksGrounded(tt.raw); got != tt.want {
			t.Fatalf("followUpTargetLooksGrounded(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestFollowUpTargetsPublicStaticAsset(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"https://example.test/assets/app.js", true},
		{"https://example.test/assets/public/images/uploads/{filename}", true},
		{"https://example.test/api/files/123", false},
		{"https://example.test/api/orders/123", false},
	}
	for _, tt := range tests {
		if got := followUpTargetsPublicStaticAsset(tt.raw); got != tt.want {
			t.Fatalf("followUpTargetsPublicStaticAsset(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

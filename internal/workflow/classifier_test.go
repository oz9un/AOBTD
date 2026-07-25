package workflow

import "testing"

func TestClassifyAreaGeneralBusinessWorkflows(t *testing.T) {
	tests := []struct {
		text        string
		wantArea    Area
		minPriority int
		description string
	}{
		{"/api/users/123", AreaAPI, 7, "API routes stay visible as API surface"},
		{"/login", AreaAuthentication, 10, "auth is high priority"},
		{"/admin/panel", AreaAdmin, 9, "admin is high priority"},
		{"/account/settings", AreaAccount, 7, "account settings are identity-sensitive"},
		{"/upload/avatar", AreaUpload, 8, "uploads deserve deeper analysis"},
		{"/checkout/place-order", AreaTransaction, 9, "orders are business transactions"},
		{"/booking/reservation/confirm", AreaTransaction, 9, "booking is a generic transaction, not e-commerce-only"},
		{"/billing/invoices", AreaFinancial, 9, "billing is financial"},
		{"/coupons/redeem", AreaValueTransfer, 8, "coupons are value transfer"},
		{"/messages/inbox", AreaMessaging, 6, "messaging often exposes user data"},
		{"/support/tickets", AreaSupport, 5, "support/ticketing is a workflow"},
		{"/products/42", AreaCatalog, 3, "catalog is lower priority unless other signals exist"},
		{"/assets/app.js", AreaStatic, 1, "static assets are low priority"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			gotArea, gotPriority := ClassifyArea(tt.text)
			if gotArea != tt.wantArea || gotPriority < tt.minPriority {
				t.Fatalf("ClassifyArea(%q)=(%q,%d), want %q with priority >= %d",
					tt.text, gotArea, gotPriority, tt.wantArea, tt.minPriority)
			}
		})
	}
}

func TestClassifyControlGeneralBusinessRisk(t *testing.T) {
	tests := []struct {
		text string
		want ControlRisk
	}{
		{"Log in", ControlSafe},
		{"Search products", ControlSafe},
		{"Continue", ControlSafe},
		{"Close search", ControlChrome},
		{"Show the shopping cart", ControlChrome},
		{"Pay now", ControlFinancial},
		{"Transfer balance", ControlFinancial},
		{"Refund customer", ControlFinancial},
		{"Place order", ControlSensitiveStateChange},
		{"Confirm booking", ControlSensitiveStateChange},
		{"Make reservation", ControlSensitiveStateChange},
		{"Siparişi Onayla", ControlSensitiveStateChange},
		{"Ödeme yap", ControlFinancial},
		{"Kupon kullan", ControlSensitiveStateChange},
		{"Delete account", ControlDestructive},
		{"Reset password", ControlDestructive},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if got := ClassifyControl(tt.text); got != tt.want {
				t.Fatalf("ClassifyControl(%q)=%q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

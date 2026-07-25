package workflow

import "strings"

// Area is a coarse, domain-agnostic business function label.
//
// These labels intentionally describe what a workflow does rather than what
// industry the target belongs to. For example, a marketplace "order", a travel
// "booking", and a SaaS "subscription change" are all sensitive business
// transactions even though only one of them is classic e-commerce.
type Area string

const (
	AreaAuthentication Area = "authentication"
	AreaAdmin          Area = "admin"
	AreaAccount        Area = "account"
	AreaSearch         Area = "search"
	AreaUpload         Area = "file_handling"
	AreaAPI            Area = "api"
	AreaCatalog        Area = "catalog"
	AreaTransaction    Area = "transaction"
	AreaFinancial      Area = "financial"
	AreaValueTransfer  Area = "value_transfer"
	AreaMessaging      Area = "messaging"
	AreaSupport        Area = "support"
	AreaStatic         Area = "static"
	AreaGeneral        Area = "general"
)

// ControlRisk describes whether an automatically clicked control is safe for
// reconnaissance or should be left for a human-approved active test.
type ControlRisk string

const (
	ControlSafe                 ControlRisk = "safe"
	ControlChrome               ControlRisk = "chrome"
	ControlDestructive          ControlRisk = "destructive"
	ControlFinancial            ControlRisk = "financial"
	ControlSensitiveStateChange ControlRisk = "sensitive_state_change"
)

// ClassifyArea returns the likely business area and a security-priority score.
func ClassifyArea(text string) (Area, int) {
	normalized := normalize(text)

	switch {
	case containsAny(normalized,
		"/login", "/signin", "/sign-in", "/auth", "/oauth", "/sso",
		"/register", "/signup", "/sign-up", "/password", "/forgot", "/reset",
		"login", "sign in", "authentication"):
		return AreaAuthentication, 10
	case containsAny(normalized,
		"/admin", "/dashboard", "/manage", "/management", "/panel", "/console",
		"/backoffice", "/moderator", "/staff"):
		return AreaAdmin, 9
	case containsAny(normalized,
		"/payment", "/pay", "/billing", "/invoice", "/wallet", "/balance",
		"/transfer", "/withdraw", "/payout", "/refund", "/charge", "/subscription"):
		return AreaFinancial, 9
	case containsAny(normalized,
		"/checkout", "/cart", "/basket", "/order", "/orders", "/booking",
		"/reservation", "/appointment", "/purchase", "/checkout"):
		return AreaTransaction, 9
	case containsAny(normalized,
		"/coupon", "/promo", "/promotion", "/discount", "/gift", "/voucher",
		"/reward", "/loyalty", "/campaign"):
		return AreaValueTransfer, 8
	case containsAny(normalized, "/upload", "/import", "/file", "/files", "/attachment", "/avatar"):
		return AreaUpload, 8
	case containsAny(normalized, "/support", "/help", "/contact", "/faq", "/case"):
		return AreaSupport, 5
	case containsAny(normalized,
		"/message", "/messages", "/chat", "/comment", "/review", "/notification",
		"/inbox", "/ticket"):
		return AreaMessaging, 6
	case containsAny(normalized, "/api/", "/rest/", "/graphql", "/rpc/", "/v1/", "/v2/"):
		return AreaAPI, 7
	case containsAny(normalized,
		"/account", "/profile", "/settings", "/preferences", "/user", "/users",
		"/tenant", "/organization", "/organisation", "/team"):
		return AreaAccount, 7
	case containsAny(normalized, "/search", "/query", "/find", "/filter", "/lookup"):
		return AreaSearch, 6
	case containsAny(normalized, "/product", "/item", "/catalog", "/category", "/listing", "/content", "/article"):
		return AreaCatalog, 3
	case containsAny(normalized, "/static", "/assets", "/css", "/js", "/img", "/image", "/fonts"):
		return AreaStatic, 1
	default:
		return AreaGeneral, 4
	}
}

// ClassifyControl returns the automation risk of a visible UI control.
func ClassifyControl(text string) ControlRisk {
	normalized := normalize(text)
	if normalized == "" {
		return ControlChrome
	}

	for _, phrase := range []string{
		"delete account", "close account", "cancel account", "disable account",
		"delete", "remove", "drop", "destroy", "erase",
		"reset password", "change password",
		"logout", "log out", "sign out",
	} {
		if strings.Contains(normalized, phrase) {
			return ControlDestructive
		}
	}

	for _, phrase := range []string{
		"pay", "payment", "billing", "invoice", "wallet", "top up", "transfer",
		"withdraw", "payout", "refund", "charge", "subscription", "öde", "odeme", "ödeme",
	} {
		if strings.Contains(normalized, phrase) {
			return ControlFinancial
		}
	}

	for _, phrase := range []string{
		"checkout", "check out", "place order", "complete order", "confirm order",
		"submit order", "buy now", "purchase", "book now", "confirm booking",
		"make reservation", "confirm reservation", "siparişi onayla", "satın al",
		"sepeti onayla",
	} {
		if strings.Contains(normalized, phrase) {
			return ControlSensitiveStateChange
		}
	}

	for _, phrase := range []string{
		"apply coupon", "redeem", "kupon kullan", "apply promo", "use voucher",
		"claim reward",
	} {
		if strings.Contains(normalized, phrase) {
			return ControlSensitiveStateChange
		}
	}

	for _, phrase := range []string{
		"close", "cancel", "dismiss", "back", "menu", "sidenav", "hamburger",
		"open search", "close search",
		"cart", "basket", "sepet", "account", "hesabım", "profile", "profil",
		"notifications", "help", "yardım",
	} {
		if strings.Contains(normalized, phrase) {
			return ControlChrome
		}
	}

	return ControlSafe
}

func normalize(text string) string {
	return strings.ToLower(strings.Join(strings.Fields(text), " "))
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

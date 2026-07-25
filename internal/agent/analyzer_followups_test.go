package agent

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestHarvestFollowUpsConvertsReadOnlyLogicToQueryProbe(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"inputs":[{"name":"fields","location":"query"}],
		"follow_ups":[
			{"action":"probe_logic","url":"https://example.test/whoami?fields=id","field":"fields","test_values":["id","password"],"reason":"query experiment"},
			{"action":"probe_logic","url":"https://example.test/feedback","field":"UserId","test_values":["1","2"],"reason":"implicit query experiment"}
		]
	}`, "GET /whoami")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 {
		t.Fatalf("queued tasks = %+v, want two query probes", tasks)
	}
	var task store.FollowUp
	for _, candidate := range tasks {
		if candidate.Params["param"] == "fields" {
			task = candidate
			break
		}
	}
	if task.Action != "probe_param" {
		t.Fatalf("action = %q, want probe_param", task.Action)
	}
	if got := task.Params["param"]; got != "fields" {
		t.Fatalf("param = %#v, want fields", got)
	}
	values, ok := task.Params["values"].([]any)
	if !ok || len(values) != 2 || values[1] != "password" {
		t.Fatalf("values = %#v, want [id password]", task.Params["values"])
	}
	var second store.FollowUp
	for _, candidate := range tasks {
		if candidate.Params["param"] == "UserId" {
			second = candidate
			break
		}
	}
	if second.Action != "probe_param" {
		t.Fatalf("second action = %q, want probe_param", second.Action)
	}
	if got := second.Params["param"]; got != "UserId" {
		t.Fatalf("second param = %#v, want UserId", got)
	}
}

func TestHarvestFollowUpsRejectsAccessControlParamProbeOnPublicMetaTarget(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"probe_param","url":"https://example.test/rest/admin/application-configuration/1","param":"id","values":["1","2"],"reason":"Check for IDOR or unauthorized access by varying the id parameter"},
			{"action":"probe_param","url":"https://example.test/api/orders/1","param":"id","values":["1","2"],"reason":"Check for IDOR or unauthorized access by varying the id parameter"}
		]
	}`, "GET /admin/config")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only the owned-object probe", tasks)
	}
	if tasks[0].URL != "https://example.test/api/orders/1" {
		t.Fatalf("queued URL = %q, want orders probe", tasks[0].URL)
	}
}

func TestHarvestFollowUpsRejectsActiveProbeOnPublicStaticAsset(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"probe_param","url":"https://example.test/assets/public/images/uploads/test.php","param":"id","values":["../../etc/passwd","shell.php"],"reason":"Try file traversal and shell variants"},
			{"action":"fetch","url":"https://example.test/assets/public/images/uploads/shell.php","reason":"Fetch a guessed shell name"},
			{"action":"probe_param","url":"https://example.test/api/orders/1","param":"id","values":["1","2"],"reason":"Check order access control"}
		]
	}`, "GET /assets/public/images/uploads/cat.png")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only business-object probe", tasks)
	}
	if tasks[0].URL != "https://example.test/api/orders/1" {
		t.Fatalf("queued URL = %q, want order probe", tasks[0].URL)
	}
}

func TestHarvestFollowUpsRejectsTokenBusinessLogicProbe(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"POST",
		"follow_ups":[
			{"action":"probe_logic","url":"https://example.test/login.php","field":"user_token","test_values":["abc","def"],"reason":"try changing token"},
			{"action":"probe_param","url":"https://example.test/reset?csrf=abc","param":"csrf","values":["x","y"],"reason":"try csrf query"},
			{"action":"probe_logic","url":"https://example.test/orders","field":"quantity","test_values":["-1","999"],"reason":"business rule"}
		]
	}`, "POST /login.php")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only non-token business probe", tasks)
	}
	if tasks[0].Action != "probe_logic" || tasks[0].Params["field"] != "quantity" {
		t.Fatalf("queued task = %+v, want quantity probe_logic", tasks[0])
	}
}

func TestHarvestFollowUpsRejectsAlreadyObservedFetch(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  "GET",
			URL:     "https://example.test/vulnerabilities/sqli/",
			Host:    "example.test",
			Path:    "/vulnerabilities/sqli/",
			Headers: map[string]string{},
		},
		Response: types.CapturedResponse{
			StatusCode: 200,
			Headers:    map[string]string{},
		},
	}); err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"fetch","url":"https://example.test/vulnerabilities/sqli/","reason":"follow redirect"},
			{"action":"fetch","url":"https://example.test/vulnerabilities/exec/","reason":"new page"}
		]
	}`, "GET /vulnerabilities/sqli")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only unobserved fetch", tasks)
	}
	if tasks[0].URL != "https://example.test/vulnerabilities/exec/" {
		t.Fatalf("queued URL = %q, want exec fetch", tasks[0].URL)
	}
}

func TestHarvestFollowUpsRejectsPayloadBearingFetch(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"fetch","url":"https://example.test/search?q=<script>alert(1)</script>","reason":"try XSS with fetch"},
			{"action":"fetch","url":"https://example.test/docs?file=..%2f..%2fetc%2fpasswd","reason":"try traversal with fetch"},
			{"action":"visit","url":"https://example.test/search?q=<script>alert(1)</script>","reason":"DOM visit"},
			{"action":"fetch","url":"https://example.test/api/profile","reason":"ordinary fetch"}
		]
	}`, "GET /search")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 {
		t.Fatalf("queued tasks = %+v, want visit payload plus ordinary fetch", tasks)
	}
	seen := map[string]bool{}
	for _, task := range tasks {
		seen[task.Action+" "+task.URL] = true
	}
	if !seen["visit https://example.test/search?q=<script>alert(1)</script>"] {
		t.Fatalf("payload visit was not retained: %+v", tasks)
	}
	if !seen["fetch https://example.test/api/profile"] {
		t.Fatalf("ordinary fetch was not retained: %+v", tasks)
	}
}

func TestHarvestFollowUpsRejectsBenchmarkMetadataTargets(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"fetch","url":"https://example.test/VulnerableApp/scanner","reason":"read scanner index"},
			{"action":"probe_param","url":"https://example.test/VulnerableApp/scanner/benchmark","param":"url","values":["https://evil.test"],"reason":"benchmark endpoint probe"},
			{"action":"fetch","url":"https://example.test/VulnerableApp/allEndPointJson","reason":"read all endpoints"},
			{"action":"fetch","url":"https://example.test/VulnerableApp/CommandInjection/LEVEL_1","reason":"real lesson endpoint"}
		]
	}`, "GET /VulnerableApp/scanner")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only real lesson endpoint", tasks)
	}
	if tasks[0].URL != "https://example.test/VulnerableApp/CommandInjection/LEVEL_1" {
		t.Fatalf("queued URL = %q", tasks[0].URL)
	}
}

func TestHarvestFollowUpsRejectsIncompleteProbes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"POST",
		"follow_ups":[
			{"action":"probe_param","param":"seg","values":["LDAPInjectionVulnerability","*"],"reason":"missing url"},
			{"action":"probe_param","url":"https://example.test/api/search","param":"q","reason":"missing values"},
			{"action":"probe_param","url":"https://example.test/api/search","values":["1","2"],"reason":"missing param"},
			{"action":"probe_logic","url":"https://example.test/orders","field":"quantity","test_values":["-1","999"],"reason":"valid business probe"},
			{"action":"probe_logic","url":"https://example.test/orders","field":"method_override","reason":"missing test values"},
			{"action":"probe_logic","url":"https://example.test/orders","test_values":["1","2"],"reason":"missing field"}
		]
	}`, "POST /orders")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only complete probe_logic", tasks)
	}
	if tasks[0].Action != "probe_logic" || tasks[0].Params["field"] != "quantity" {
		t.Fatalf("queued task = %+v", tasks[0])
	}
}

func TestHarvestFollowUpsRejectsIDORWithoutIDPlaceholder(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"probe_idor","url_template":"https://example.test/api/users","values":["admin","guest"],"field":"username","reason":"missing placeholder"},
			{"action":"probe_idor","url_template":"https://example.test/api/users/{id}","values":["1","2"],"reason":"owned object"}
		]
	}`, "GET /api/users")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only placeholder IDOR probe", tasks)
	}
	if tasks[0].URL != "https://example.test/api/users/{id}" {
		t.Fatalf("queued task = %+v", tasks[0])
	}
}

func TestHarvestFollowUpsRejectsTransportLogicProbes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"POST",
		"follow_ups":[
			{"action":"probe_logic","url":"https://example.test/upload","field":"method_override","test_values":["PUT","DELETE"],"reason":"method override"},
			{"action":"probe_logic","url":"https://example.test/upload","field":"Content-Type","test_values":["text/html"],"reason":"header fuzz"},
			{"action":"probe_logic","url":"https://example.test/orders","field":"quantity","test_values":["-1","999"],"reason":"business rule"}
		]
	}`, "POST /upload")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only quantity logic probe", tasks)
	}
	if tasks[0].Params["field"] != "quantity" {
		t.Fatalf("queued task = %+v", tasks[0])
	}
}

func TestHarvestFollowUpsRejectsExecutableUploadParamProbe(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"POST",
		"follow_ups":[
			{"action":"probe_param","url":"https://example.test/upload","param":"filename","values":["test.jsp","shell.php","test.svg"],"reason":"try web shell upload"},
			{"action":"probe_param","url":"https://example.test/api/orders/1","param":"id","values":["1","2"],"reason":"business object"}
		]
	}`, "POST /upload")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("queued tasks = %+v, want only business object probe", tasks)
	}
	if tasks[0].URL != "https://example.test/api/orders/1" {
		t.Fatalf("queued task = %+v", tasks[0])
	}
}

func TestHarvestFollowUpsRejectsPlaceholderFetch(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "followups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &AnalyzerAgent{
		db:     db,
		scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	analyzer.harvestFollowUps(`{
		"method":"GET",
		"follow_ups":[
			{"action":"fetch","url":"https://example.test/rest/continue-code/apply/{continueCode}","reason":"try placeholder fetch"},
			{"action":"probe_idor","url_template":"https://example.test/api/orders/{id}","values":["1","2"],"reason":"probe owned object"},
			{"action":"fetch","url":"https://example.test/rest/user/whoami","reason":"concrete fetch"}
		]
	}`, "GET /continue-code")

	tasks, err := db.ListFollowUps(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 {
		t.Fatalf("queued tasks = %+v, want IDOR probe plus concrete fetch", tasks)
	}
	for _, task := range tasks {
		if strings.Contains(task.URL, "{continueCode}") {
			t.Fatalf("placeholder fetch was queued: %+v", task)
		}
	}
}

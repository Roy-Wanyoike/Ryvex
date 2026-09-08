package state

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func subSpec(over map[string]any) map[string]any {
	spec := map[string]any{
		"url":      "https://example.test/hook",
		"subjects": []any{"ryvex.resource.acme.>", "ryvex.resource.acme.deployment.created"},
	}
	for k, v := range over {
		spec[k] = v
	}
	return spec
}

func TestParseSubscriptionSpecDefaults(t *testing.T) {
	got, err := ParseSubscriptionSpec(subSpec(nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.URL != "https://example.test/hook" {
		t.Errorf("URL = %q", got.URL)
	}
	if !got.Active {
		t.Error("Active should default to true")
	}
	if got.MaxRetries != DefSubscriptionRetries {
		t.Errorf("MaxRetries = %d, want default %d", got.MaxRetries, DefSubscriptionRetries)
	}
	if len(got.Subjects) != 2 {
		t.Errorf("Subjects = %v", got.Subjects)
	}
}

func TestParseSubscriptionSpecExplicit(t *testing.T) {
	got, err := ParseSubscriptionSpec(subSpec(map[string]any{
		"active":      false,
		"max_retries": float64(0),
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Active {
		t.Error("Active = true, want false")
	}
	if got.MaxRetries != 0 {
		t.Errorf("MaxRetries = %d, want 0", got.MaxRetries)
	}
}

func TestParseSubscriptionSpecInvalid(t *testing.T) {
	cases := []struct {
		name    string
		spec    map[string]any
		inField string // substring expected in the validation message
	}{
		{"missing url", map[string]any{"subjects": []any{"ryvex.resource.a.>"}}, "spec.url"},
		{"empty url", subSpec(map[string]any{"url": ""}), "spec.url"},
		{"non-string url", subSpec(map[string]any{"url": 42}), "spec.url"},
		{"not a url", subSpec(map[string]any{"url": "not a url"}), "spec.url"},
		{"wrong scheme", subSpec(map[string]any{"url": "ftp://example.test/hook"}), "spec.url"},
		{"no host", subSpec(map[string]any{"url": "http:///hook"}), "spec.url"},
		{"missing subjects", map[string]any{"url": "https://example.test/hook"}, "spec.subjects"},
		{"subjects not array", subSpec(map[string]any{"subjects": "ryvex.resource.a.>"}), "spec.subjects"},
		{"empty subjects", subSpec(map[string]any{"subjects": []any{}}), "spec.subjects"},
		{"too many subjects", subSpec(map[string]any{"subjects": manySubjects(17)}), "spec.subjects"},
		{"bad charset", subSpec(map[string]any{"subjects": []any{"ryvex.resource.a b.>"}}), "spec.subjects"},
		{"empty segment", subSpec(map[string]any{"subjects": []any{"ryvex..resource"}}), "spec.subjects"},
		{"trailing dot", subSpec(map[string]any{"subjects": []any{"ryvex.resource."}}), "spec.subjects"},
		{"mid > wildcard", subSpec(map[string]any{"subjects": []any{"ryvex.>.resource"}}), "spec.subjects"},
		{"non-string subject", subSpec(map[string]any{"subjects": []any{7}}), "spec.subjects"},
		{"active not bool", subSpec(map[string]any{"active": "yes"}), "spec.active"},
		{"negative retries", subSpec(map[string]any{"max_retries": float64(-1)}), "spec.max_retries"},
		{"retries too big", subSpec(map[string]any{"max_retries": float64(11)}), "spec.max_retries"},
		{"retries fractional", subSpec(map[string]any{"max_retries": 1.5}), "spec.max_retries"},
		{"retries not number", subSpec(map[string]any{"max_retries": "5"}), "spec.max_retries"},
		{"nil spec", nil, "spec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSubscriptionSpec(tc.spec)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("error %T not *ValidationError: %v", err, err)
			}
			if !strings.Contains(ve.Message, tc.inField) && !strings.Contains(ve.Field, tc.inField) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.inField)
			}
		})
	}
}

func manySubjects(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("ryvex.resource.org%d.>", i)
	}
	return out
}

func TestValidBusPattern(t *testing.T) {
	valid := []string{
		"ryvex.resource.acme.>",
		"ryvex.resource.acme.deployment.created",
		"ryvex.resource.*.*.created",
		">",
		"a",
		"a-b.c-d",                              // hyphen allowed by charset
		"ryvex.resource.acme.app.v1,2.created", // comma allowed by charset
	}
	for _, p := range valid {
		if !ValidBusPattern(p) {
			t.Errorf("ValidBusPattern(%q) = false, want true", p)
		}
	}
	invalid := []string{"", "a..b", ".a", "a.", "ryvex .resource", "ryvex.>.a", "sp ace"}
	for _, p := range invalid {
		if ValidBusPattern(p) {
			t.Errorf("ValidBusPattern(%q) = true, want false", p)
		}
	}
}

func TestSubscriptionResourceCRUD(t *testing.T) {
	st := NewStore()

	// Valid subscription is stored and reconcilable like any kind.
	created, err := st.CreateResource(&Resource{
		Kind: KindSubscription, Org: "acme", Project: "ops", Env: "prod",
		Name: "hooks", Spec: subSpec(nil),
	}, WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Generation != 1 || created.Status.Phase != PhasePending {
		t.Errorf("unexpected stored doc: %+v", created)
	}

	// Kind matching through the scope-addressed face stays intact.
	got, err := st.GetByLogicalKey("acme", "ops", "prod", "Subscription", "hooks")
	if err != nil {
		t.Fatalf("get by logical key: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %q, want %q", got.ID, created.ID)
	}

	// Invalid specs are rejected at the door (create and update).
	bad := []map[string]any{
		subSpec(map[string]any{"url": "ftp://x.test/hook"}),
		subSpec(map[string]any{"subjects": []any{}}),
		subSpec(map[string]any{"max_retries": float64(99)}),
	}
	for i, spec := range bad {
		_, err := st.CreateResource(&Resource{
			Kind: KindSubscription, Org: "acme", Project: "ops", Env: "prod",
			Name: fmt.Sprintf("bad%d", i), Spec: spec,
		}, WriteOptions{Actor: "test"})
		if !errors.Is(err, ErrValidation) {
			t.Errorf("create bad spec %d: err = %v, want ErrValidation", i, err)
		}
	}
	_, err = st.UpdateResource(created.ID, func(cur *Resource) error {
		cur.Spec = subSpec(map[string]any{"subjects": []any{"not ok"}})
		return nil
	}, UpdateOptions{WriteOptions: WriteOptions{Actor: "test"}})
	if !errors.Is(err, ErrValidation) {
		t.Errorf("update to invalid spec: err = %v, want ErrValidation", err)
	}

	// Spec update that survives validation bumps the generation.
	updated, err := st.UpdateResource(created.ID, func(cur *Resource) error {
		cur.Spec = subSpec(map[string]any{"active": false})
		return nil
	}, UpdateOptions{WriteOptions: WriteOptions{Actor: "test"}})
	if err != nil {
		t.Fatalf("valid update: %v", err)
	}
	if updated.Generation != 2 {
		t.Errorf("generation = %d, want 2", updated.Generation)
	}
}

func TestStoreAppendAudit(t *testing.T) {
	st := NewStore()
	e := st.AppendAudit(AuditEntry{
		Actor:      "webhook-dispatcher",
		Action:     "webhook_delivered",
		ResourceID: "r-x",
		Kind:       KindSubscription,
		LogicalKey: "acme/ops/prod/Subscription/hooks",
		Reason:     "ryvex.resource.acme.application.created attempt 1/6",
	})
	if e.ID == "" || e.Time.IsZero() {
		t.Fatalf("AppendAudit did not fill ID/Time: %+v", e)
	}
	if e.Time.Location() != time.UTC {
		t.Errorf("audit time %v not UTC", e.Time)
	}
	got := st.ListAudit(AuditOptions{Org: "acme", Kind: KindSubscription, Limit: 10})
	if len(got) != 1 || got[0].ID != e.ID {
		t.Fatalf("ListAudit = %+v, want the appended entry", got)
	}
	if got[0].Action != "webhook_delivered" || got[0].Reason == "" {
		t.Errorf("stored entry wrong: %+v", got[0])
	}
}

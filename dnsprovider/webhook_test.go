package dnsprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookPutAndDelete(t *testing.T) {
	type request struct {
		method string
		auth   string
		body   map[string]string
	}
	requests := make(chan request, 4)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding webhook body: %v", err)
		}
		requests <- request{method: r.Method, auth: r.Header.Get("Authorization"), body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer hs.Close()

	provider, err := NewWebhook(hs.URL, "s3cret")
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	if err := provider.PutTXT(context.Background(), "_acme-challenge.example.com", "token"); err != nil {
		t.Fatalf("PutTXT: %v", err)
	}
	if err := provider.DeleteTXT(context.Background(), "_acme-challenge.example.com"); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}

	put := <-requests
	if put.method != http.MethodPost || put.auth != "Bearer s3cret" {
		t.Errorf("put request = %+v", put)
	}
	if put.body["action"] != "put" || put.body["name"] != "_acme-challenge.example.com" ||
		put.body["type"] != "TXT" || put.body["value"] != "token" {
		t.Errorf("put body = %v", put.body)
	}

	del := <-requests
	if del.body["action"] != "delete" || del.body["name"] != "_acme-challenge.example.com" {
		t.Errorf("delete body = %v", del.body)
	}
	if _, ok := del.body["value"]; ok {
		t.Errorf("delete body carries a value: %v", del.body)
	}
}

func TestWebhookRejectsErrorStatus(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer hs.Close()

	provider, err := NewWebhook(hs.URL, "")
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	if err := provider.PutTXT(context.Background(), "_acme-challenge.example.com", "token"); err == nil {
		t.Fatal("PutTXT succeeded despite a 403 response")
	}
}

func TestNewWebhookURLValidation(t *testing.T) {
	for _, tt := range []struct {
		url     string
		wantErr bool
	}{
		{"https://dns.example.com/update", false},
		{"http://127.0.0.1:8080/update", false},
		{"http://localhost:8080/update", false},
		{"http://dns.example.com/update", true}, // credentials over plain http
		{"ftp://dns.example.com/update", true},
		{"", true},
	} {
		_, err := NewWebhook(tt.url, "token")
		if (err != nil) != tt.wantErr {
			t.Errorf("NewWebhook(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
		}
	}
}

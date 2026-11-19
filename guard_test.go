package googlecredentialguard

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

func validKey(t *testing.T) map[string]any {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"type": "service_account", "project_id": "test-project", "private_key_id": "test-key",
		"private_key":          string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":         "test@test-project.iam.gserviceaccount.com",
		"token_uri":            TokenURL,
		"auth_uri":             "https://accounts.google.com/o/oauth2/auth",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
	}
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseServiceAccountJSONAndAdapters(t *testing.T) {
	input := encode(t, validKey(t))
	parsed, err := ParseServiceAccountJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(parsed.CanonicalJSON(), &canonical); err != nil {
		t.Fatal(err)
	}
	if canonical["token_uri"] != TokenURL || canonical["type"] != "service_account" {
		t.Fatalf("unexpected canonical credential metadata: type=%v token_uri=%v", canonical["type"], canonical["token_uri"])
	}
	if _, ok := canonical["auth_uri"]; ok {
		t.Fatal("non-authentication field retained in canonical JSON")
	}
	copy := parsed.CanonicalJSON()
	copy[0] = '!'
	if parsed.CanonicalJSON()[0] != '{' {
		t.Fatal("canonical JSON was mutable through the returned copy")
	}
	if _, err := parsed.ClientOption(); err != nil {
		t.Fatal(err)
	}
	cfg, err := parsed.JWTConfig("https://www.googleapis.com/auth/cloud-platform")
	if err != nil || cfg.TokenURL != TokenURL {
		t.Fatalf("JWTConfig: cfg=%v err=%v", cfg, err)
	}
	if _, err := parsed.AuthCredentials("https://www.googleapis.com/auth/cloud-platform"); err != nil {
		t.Fatal(err)
	}
}

func TestParseServiceAccountJSONRejectsUnsafeConfigurations(t *testing.T) {
	base := validKey(t)
	cases := map[string]func(map[string]any){
		"external account file": func(m map[string]any) {
			m["type"] = "external_account"
			m["credential_source"] = map[string]any{"file": "/proc/self/environ"}
			m["token_url"] = "https://example.invalid/token"
		},
		"external account URL": func(m map[string]any) {
			m["type"] = "external_account"
			m["credential_source"] = map[string]any{"url": "http://169.254.169.254/latest/meta-data/"}
		},
		"external account executable": func(m map[string]any) {
			m["type"] = "external_account"
			m["credential_source"] = map[string]any{"executable": map[string]any{"command": "whoami"}}
		},
		"authorized user":     func(m map[string]any) { m["type"] = "authorized_user" },
		"hostile token URI":   func(m map[string]any) { m["token_uri"] = "https://example.invalid/token" },
		"nondefault universe": func(m map[string]any) { m["universe_domain"] = "example.invalid" },
		"missing key":         func(m map[string]any) { delete(m, "private_key") },
		"invalid key":         func(m map[string]any) { m["private_key"] = "not a key" },
		"nonstring field":     func(m map[string]any) { m["token_uri"] = nil },
		"unknown field":       func(m map[string]any) { m["source_credentials"] = map[string]any{} },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			value := make(map[string]any, len(base))
			for k, v := range base {
				value[k] = v
			}
			modify(value)
			_, err := ParseServiceAccountJSON(encode(t, value))
			if err == nil {
				t.Fatal("unsafe credential accepted")
			}
			if strings.Contains(err.Error(), "example.invalid") || strings.Contains(err.Error(), "/proc/") {
				t.Fatalf("credential data included in error: %v", err)
			}
		})
	}
}

func TestParseServiceAccountJSONRejectsParserAmbiguity(t *testing.T) {
	base := encode(t, validKey(t))
	cases := [][]byte{
		[]byte(`{"type":"service_account","type":"external_account"}`),
		[]byte(`{"type":"service_account","\u0074ype":"external_account"}`),
		[]byte(`{"type":"external_account","type":"service_account"}`),
		append(append([]byte{}, base...), []byte(` {}`)...),
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`{`),
		make([]byte, MaxJSONBytes+1),
	}
	for i, input := range cases {
		if _, err := ParseServiceAccountJSON(input); err == nil {
			t.Fatalf("ambiguous or oversized case %d accepted", i)
		}
	}
}

func TestFormattedValueRedactsKeyMaterial(t *testing.T) {
	parsed, err := ParseServiceAccountJSON(encode(t, validKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{fmt.Sprint(parsed), fmt.Sprintf("%+v", parsed), fmt.Sprintf("%#v", parsed)} {
		if strings.Contains(rendered, "PRIVATE KEY") || strings.Contains(rendered, "test-key") {
			t.Fatalf("credential leaked in formatted value: %s", rendered)
		}
	}
}

func TestZeroValueCannotCreateAdapter(t *testing.T) {
	var empty ServiceAccount
	if _, err := empty.ClientOption(); err == nil {
		t.Fatal("zero-value ClientOption accepted")
	}
	if _, err := empty.JWTConfig(); err == nil {
		t.Fatal("zero-value JWTConfig accepted")
	}
	if _, err := empty.AuthCredentials(); err == nil {
		t.Fatal("zero-value AuthCredentials accepted")
	}
}

func FuzzParseServiceAccountJSON(f *testing.F) {
	f.Add([]byte(`{"type":"external_account","credential_source":{"file":"/proc/self/environ"}}`))
	f.Add([]byte(`{"type":"service_account","type":"external_account"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := ParseServiceAccountJSON(input)
		if err != nil {
			return
		}
		canonical := parsed.CanonicalJSON()
		if len(canonical) > MaxJSONBytes {
			t.Fatal("canonical JSON exceeded input bound")
		}
		var key map[string]any
		if err := json.Unmarshal(canonical, &key); err != nil {
			t.Fatal(err)
		}
		if key["type"] != "service_account" || key["token_uri"] != TokenURL {
			t.Fatal("accepted value lost the credential contract")
		}
	})
}

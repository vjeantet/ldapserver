package ldapserver

import (
	"encoding/asn1"
	"testing"

	ldap "github.com/lor00x/goldap/message"
)

func TestParseCancelRequestValue(t *testing.T) {
	tests := []struct {
		name     string
		id       int
		wantErr  bool
	}{
		{"messageID 1", 1, false},
		{"messageID 42", 42, false},
		{"messageID large", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := asn1.Marshal(cancelRequestValue{CancelID: tt.id})
			if err != nil {
				t.Fatalf("failed to marshal test data: %v", err)
			}
			raw := ldap.OCTETSTRING(data)

			got, err := parseCancelRequestValue(&raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.id {
				t.Fatalf("expected cancelID %d, got %d", tt.id, got)
			}
		})
	}
}

func TestParseCancelRequestValue_Nil(t *testing.T) {
	_, err := parseCancelRequestValue(nil)
	if err == nil {
		t.Fatal("expected error for nil requestValue, got nil")
	}
}

func TestParseCancelRequestValue_InvalidData(t *testing.T) {
	raw := ldap.OCTETSTRING([]byte{0xff, 0xff})
	_, err := parseCancelRequestValue(&raw)
	if err == nil {
		t.Fatal("expected error for invalid ASN.1 data, got nil")
	}
}

func TestParseCancelRequestValue_TrailingData(t *testing.T) {
	data, _ := asn1.Marshal(cancelRequestValue{CancelID: 1})
	data = append(data, 0x00) // trailing byte
	raw := ldap.OCTETSTRING(data)

	_, err := parseCancelRequestValue(&raw)
	if err == nil {
		t.Fatal("expected error for trailing data, got nil")
	}
}

func TestParseCancelRequestValue_ZeroID(t *testing.T) {
	data, _ := asn1.Marshal(cancelRequestValue{CancelID: 0})
	raw := ldap.OCTETSTRING(data)

	_, err := parseCancelRequestValue(&raw)
	if err == nil {
		t.Fatal("expected error for cancelID 0, got nil")
	}
}

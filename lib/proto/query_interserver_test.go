package proto

import (
	"crypto/sha256"
	"testing"
)

func TestInterserverHashEmptySecret(t *testing.T) {
	q := Query{ClusterSalt: "salt", Body: "SELECT 1", ID: "qid", InitialUser: "alice"}
	if got := q.interserverHash(); got != "" {
		t.Fatalf("expected empty hash without cluster secret, got %q", got)
	}
}

func TestInterserverHashMatchesClickHouseLayout(t *testing.T) {
	q := Query{
		ClusterSecret: "topsecret",
		ClusterSalt:   "01234567890123456789012345678901",
		Body:          "SELECT 42",
		ID:            "test-query-id",
		InitialUser:   "alice",
	}

	h := sha256.New()
	h.Write([]byte(q.ClusterSalt))
	h.Write([]byte(q.ClusterSecret))
	h.Write([]byte(q.Body))
	h.Write([]byte(q.ID))
	h.Write([]byte(q.InitialUser))
	want := string(h.Sum(nil))

	got := q.interserverHash()
	if got != want {
		t.Fatalf("hash mismatch\n got: %x\nwant: %x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(got))
	}
}

func TestInterserverHashChangesWithInitialUser(t *testing.T) {
	base := Query{
		ClusterSecret: "secret",
		ClusterSalt:   "salt",
		Body:          "SELECT 1",
		ID:            "id",
	}
	a := base
	a.InitialUser = "alice"
	b := base
	b.InitialUser = "bob"
	if a.interserverHash() == b.interserverHash() {
		t.Fatal("hash must differ when initial_user differs")
	}
}

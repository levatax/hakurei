package hst

import (
	"strings"
	"testing"
)

func TestCgroupInstancePath(t *testing.T) {
	t.Parallel()

	cfg := &CgroupConfig{}
	var id ID
	if err := id.UnmarshalText([]byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}

	path, err := cfg.InstancePath("42", &id)
	if err != nil {
		t.Fatalf("InstancePath: %v", err)
	}

	wantPrefix := defaultCgroupSlice + "/hakurei-42/"
	if got := path.String(); !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("InstancePath: got %q, want prefix %q", got, wantPrefix)
	}
}

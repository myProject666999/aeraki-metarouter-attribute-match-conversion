// Copyright Aeraki Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scheme

import (
	"strings"
	"testing"

	metaprotocol "github.com/aeraki-mesh/api/metaprotocol/v1alpha1"
	"istio.io/istio/pkg/config"
)

func smExact(v string) *metaprotocol.StringMatch {
	return &metaprotocol.StringMatch{MatchType: &metaprotocol.StringMatch_Exact{Exact: v}}
}

func smRegex(v string) *metaprotocol.StringMatch {
	return &metaprotocol.StringMatch{MatchType: &metaprotocol.StringMatch_Regex{Regex: v}}
}

func longStr(n int) string {
	return strings.Repeat("a", n)
}

func TestValidateMetaAttributeName(t *testing.T) {
	tests := []struct {
		name    string
		attr    string
		wantErr bool
	}{
		{name: "normal name", attr: "method", wantErr: false},
		{name: "name with dot and dash", attr: "dubbo.interface-name", wantErr: false},
		{name: "empty name", attr: "", wantErr: true},
		{name: "name at the length limit", attr: longStr(MaxMetaAttributeNameLength), wantErr: false},
		{name: "name over the length limit", attr: longStr(MaxMetaAttributeNameLength + 1), wantErr: true},
		{name: "name with LF", attr: "bad\nname", wantErr: true},
		{name: "name with CR", attr: "bad\rname", wantErr: true},
		{name: "name with NUL", attr: "bad\x00name", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMetaAttributeName(tt.attr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateMetaAttributeName(%q) err = %v, wantErr = %v", tt.attr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateStringMatchRegexp(t *testing.T) {
	tests := []struct {
		name        string
		sm          *metaprotocol.StringMatch
		wantErr     bool
		wantWarning bool
	}{
		{name: "non regex match is not checked", sm: smExact(""), wantErr: false, wantWarning: false},
		{name: "valid regex", sm: smRegex("foo.*"), wantErr: false, wantWarning: false},
		{name: "empty regex is a hard error", sm: smRegex(""), wantErr: true},
		{name: "uncompilable regex is a hard error", sm: smRegex("("), wantErr: true},
		{name: "regex over the length limit is a hard error", sm: smRegex(longStr(MaxMetaRegexLength + 1)), wantErr: true},
		{name: "regex at the length limit is accepted", sm: smRegex(longStr(MaxMetaRegexLength)), wantErr: false},
		{name: "legacy star regex is only a warning", sm: smRegex("*"), wantErr: false, wantWarning: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := validateStringMatchRegexp(tt.sm, "attributes")
			if (v.Err != nil) != tt.wantErr {
				t.Fatalf("Err = %v, wantErr = %v", v.Err, tt.wantErr)
			}
			if (v.Warning != nil) != tt.wantWarning {
				t.Fatalf("Warning = %v, wantWarning = %v", v.Warning, tt.wantWarning)
			}
		})
	}
}

// TestValidateMetaRouteMatchDiagnostics checks the warning/error split that protects MetaRouters
// already stored in the cluster: length/charset violations and legacy regex spellings are
// warnings (updates are allowed), while empty names, null matches and unusable regexes remain hard
// errors.
func TestValidateMetaRouteMatchDiagnostics(t *testing.T) {
	tests := []struct {
		name            string
		attributes      map[string]*metaprotocol.StringMatch
		wantErr         bool
		wantWarning     bool
		errContains     string
		warningContains string
	}{
		{
			name: "valid attributes pass cleanly",
			attributes: map[string]*metaprotocol.StringMatch{
				"env":    smExact("prod"),
				"method": smRegex("say.*"),
			},
		},
		{
			name: "empty attribute name is a hard error",
			attributes: map[string]*metaprotocol.StringMatch{
				"": smExact("prod"),
			},
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name: "null attribute is a hard error",
			attributes: map[string]*metaprotocol.StringMatch{
				"env": nil,
			},
			wantErr:     true,
			errContains: "cannot be null",
		},
		{
			name: "overlong attribute name is only a warning so existing resources keep updating",
			attributes: map[string]*metaprotocol.StringMatch{
				longStr(MaxMetaAttributeNameLength + 1): smExact("v"),
			},
			wantWarning:     true,
			warningContains: "too long",
		},
		{
			name: "control characters in attribute name are only a warning",
			attributes: map[string]*metaprotocol.StringMatch{
				"bad\nname": smExact("v"),
			},
			wantWarning:     true,
			warningContains: "invalid control characters",
		},
		{
			name: "empty regex is a hard error even on an existing resource",
			attributes: map[string]*metaprotocol.StringMatch{
				"path": smRegex(""),
			},
			wantErr:     true,
			errContains: "should not be empty",
		},
		{
			name: "legacy star regex is only a warning",
			attributes: map[string]*metaprotocol.StringMatch{
				"path": smRegex("*"),
			},
			wantWarning:     true,
			warningContains: "present-match",
		},
		{
			name: "hard error and warning can coexist in one validation",
			attributes: map[string]*metaprotocol.StringMatch{
				"path":   smRegex(""),
				"bad\nx": smExact("v"),
			},
			wantErr:         true,
			wantWarning:     true,
			errContains:     "should not be empty",
			warningContains: "invalid control characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := validateMetaRouteMatch(&metaprotocol.MetaRouteMatch{Attributes: tt.attributes})
			if (v.Err != nil) != tt.wantErr {
				t.Fatalf("Err = %v, wantErr = %v", v.Err, tt.wantErr)
			}
			if (v.Warning != nil) != tt.wantWarning {
				t.Fatalf("Warning = %v, wantWarning = %v", v.Warning, tt.wantWarning)
			}
			if tt.errContains != "" && (v.Err == nil || !strings.Contains(v.Err.Error(), tt.errContains)) {
				t.Fatalf("Err = %q, want it to contain %q", v.Err, tt.errContains)
			}
			if tt.warningContains != "" && (v.Warning == nil || !strings.Contains(v.Warning.Error(), tt.warningContains)) {
				t.Fatalf("Warning = %q, want it to contain %q", v.Warning, tt.warningContains)
			}
		})
	}
}

// TestValidateMetaRouterAcceptsValidResource exercises the full webhook entry point with a
// complete MetaRouter to ensure attribute validation integrates without false diagnostics.
func TestValidateMetaRouterAcceptsValidResource(t *testing.T) {
	cfg := config.Config{
		Spec: &metaprotocol.MetaRouter{
			Hosts: []string{"org.example.service"},
			Routes: []*metaprotocol.MetaRoute{{
				Match: &metaprotocol.MetaRouteMatch{Attributes: map[string]*metaprotocol.StringMatch{
					"env": smExact("prod"),
				}},
				Route: []*metaprotocol.MetaRouteDestination{{
					Destination: &metaprotocol.Destination{Host: "org.example.service"},
				}},
			}},
		},
	}
	warning, err := ValidateMetaRouter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warning != nil {
		t.Fatalf("unexpected warning: %v", warning)
	}
}

// TestValidateMetaRouteMatchDiagnosticOrder verifies that map iteration does not make validation
// output nondeterministic: the same set of attributes must produce identical diagnostics every
// time.
func TestValidateMetaRouteMatchDiagnosticOrder(t *testing.T) {
	match := &metaprotocol.MetaRouteMatch{Attributes: map[string]*metaprotocol.StringMatch{
		"zebra":  smRegex(""),
		"apple":  smExact("v"),
		"mango":  smRegex("("),
		"bad\nx": smExact("v"),
	}}

	first := validateMetaRouteMatch(match)
	for i := 0; i < 20; i++ {
		current := validateMetaRouteMatch(match)
		if (first.Err == nil) != (current.Err == nil) ||
			(first.Err != nil && first.Err.Error() != current.Err.Error()) {
			t.Fatalf("iteration %d: error diagnostics differ:\nfirst: %v\nnow:   %v", i, first.Err, current.Err)
		}
		if (first.Warning == nil) != (current.Warning == nil) ||
			(first.Warning != nil && first.Warning.Error() != current.Warning.Error()) {
			t.Fatalf("iteration %d: warning diagnostics differ:\nfirst: %v\nnow:   %v", i, first.Warning, current.Warning)
		}
	}
}

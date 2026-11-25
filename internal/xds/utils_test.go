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

package xds

import (
	"strings"
	"testing"

	userapi "github.com/aeraki-mesh/api/metaprotocol/v1alpha1"
	httproute "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
)

func exact(v string) *userapi.StringMatch {
	return &userapi.StringMatch{MatchType: &userapi.StringMatch_Exact{Exact: v}}
}

func prefix(v string) *userapi.StringMatch {
	return &userapi.StringMatch{MatchType: &userapi.StringMatch_Prefix{Prefix: v}}
}

func regexMatch(v string) *userapi.StringMatch {
	return &userapi.StringMatch{MatchType: &userapi.StringMatch_Regex{Regex: v}}
}

func presentMatcher() *httproute.HeaderMatcher {
	return &httproute.HeaderMatcher{HeaderMatchSpecifier: &httproute.HeaderMatcher_PresentMatch{PresentMatch: true}}
}

// longString returns a string of n ASCII bytes.
func longString(n int) string {
	return strings.Repeat("a", n)
}

func TestMetaMatch2HttpHeaderMatch(t *testing.T) {
	tests := []struct {
		name           string
		match          *userapi.MetaRouteMatch
		wantMatchers   []*httproute.HeaderMatcher
		wantErr        bool
		wantWarning    bool
		errContains    string
		warningContain string
	}{
		{
			name:         "nil match produces nothing",
			match:        nil,
			wantMatchers: nil,
		},
		{
			name:         "empty attributes produces nothing",
			match:        &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{}},
			wantMatchers: nil,
		},
		{
			name: "exact prefix regex are converted",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"env":    exact("prod"),
				"method": prefix("say"),
				"path":   regexMatch("foo.*"),
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: "env", HeaderMatchSpecifier: &httproute.HeaderMatcher_ExactMatch{ExactMatch: "prod"}},
				{Name: "method", HeaderMatchSpecifier: &httproute.HeaderMatcher_PrefixMatch{PrefixMatch: "say"}},
				{Name: "path", HeaderMatchSpecifier: &httproute.HeaderMatcher_SafeRegexMatch{
					SafeRegexMatch: &matcher.RegexMatcher{
						EngineType: regexEngine,
						Regex:      "foo.*",
					},
				}},
			},
		},
		{
			name: "empty StringMatch is a documented present match",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"user": {},
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: "user", HeaderMatchSpecifier: &httproute.HeaderMatcher_PresentMatch{PresentMatch: true}},
			},
		},
		{
			name: "nil attribute is still a present match but raises a warning",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"user": nil,
			}},
			wantMatchers:   []*httproute.HeaderMatcher{{Name: "user", HeaderMatchSpecifier: presentMatcher().HeaderMatchSpecifier}},
			wantWarning:    true,
			warningContain: "null match value",
		},
		{
			name: "legacy regex star is a present match with a warning",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"user": regexMatch("*"),
			}},
			wantMatchers:   []*httproute.HeaderMatcher{{Name: "user", HeaderMatchSpecifier: presentMatcher().HeaderMatchSpecifier}},
			wantWarning:    true,
			warningContain: "not valid RE2",
		},
		{
			name: "empty attribute name is a hard error and emits no matcher",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"":    exact("prod"),
				"env": exact("prod"),
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: "env", HeaderMatchSpecifier: &httproute.HeaderMatcher_ExactMatch{ExactMatch: "prod"}},
			},
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name: "empty regex is a hard error",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"path": regexMatch(""),
			}},
			wantMatchers: nil,
			wantErr:      true,
			errContains:  "empty regex",
		},
		{
			name: "uncompilable regex is a hard error",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"path": regexMatch("("),
			}},
			wantMatchers: nil,
			wantErr:      true,
			errContains:  "invalid RE2 regex",
		},
		{
			name: "regex longer than the limit is a hard error",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"path": regexMatch(longString(MaxMetaRegexLength + 1)),
			}},
			wantMatchers: nil,
			wantErr:      true,
			errContains:  "regex is too long",
		},
		{
			name: "regex exactly at the length limit is accepted",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"path": regexMatch(longString(MaxMetaRegexLength)),
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: "path", HeaderMatchSpecifier: &httproute.HeaderMatcher_SafeRegexMatch{
					SafeRegexMatch: &matcher.RegexMatcher{EngineType: regexEngine, Regex: longString(MaxMetaRegexLength)},
				}},
			},
		},
		{
			name: "attribute name longer than the limit is a hard error",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				longString(MaxMetaAttributeNameLength + 1): exact("v"),
			}},
			wantMatchers: nil,
			wantErr:      true,
			errContains:  "too long",
		},
		{
			name: "attribute name at the length limit is accepted",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				longString(MaxMetaAttributeNameLength): exact("v"),
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: longString(MaxMetaAttributeNameLength),
					HeaderMatchSpecifier: &httproute.HeaderMatcher_ExactMatch{ExactMatch: "v"}},
			},
		},
		{
			name: "control characters in attribute name are a hard error",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"bad\nname": exact("v"),
			}},
			wantMatchers: nil,
			wantErr:      true,
			errContains:  "invalid control characters",
		},
		{
			name: "one bad attribute does not widen the remaining conditions",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"bad":  regexMatch("("),
				"env":  exact("prod"),
				"user": {},
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: "env", HeaderMatchSpecifier: &httproute.HeaderMatcher_ExactMatch{ExactMatch: "prod"}},
				{Name: "user", HeaderMatchSpecifier: &httproute.HeaderMatcher_PresentMatch{PresentMatch: true}},
			},
			wantErr:     true,
			errContains: "invalid RE2 regex",
		},
		{
			name: "exact empty string stays an exact match, not a present match",
			match: &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
				"user": exact(""),
			}},
			wantMatchers: []*httproute.HeaderMatcher{
				{Name: "user", HeaderMatchSpecifier: &httproute.HeaderMatcher_ExactMatch{ExactMatch: ""}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err, warning := MetaMatch2HttpHeaderMatch(tt.match)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if (warning != nil) != tt.wantWarning {
				t.Fatalf("warning = %v, wantWarning = %v", warning, tt.wantWarning)
			}
			if tt.errContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errContains)) {
				t.Fatalf("err = %q, want it to contain %q", err, tt.errContains)
			}
			if tt.warningContain != "" && (warning == nil || !strings.Contains(warning.Error(), tt.warningContain)) {
				t.Fatalf("warning = %q, want it to contain %q", warning, tt.warningContain)
			}
			if !headerMatcherListsEqual(got, tt.wantMatchers) {
				t.Fatalf("matchers = %v, want %v", got, tt.wantMatchers)
			}
		})
	}
}

func headerMatcherListsEqual(a, b []*httproute.HeaderMatcher) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestMetaMatch2HttpHeaderMatchIsOrderStable repeats the conversion of the same map many times and
// requires proto-equal output every time. Go randomizes map iteration, so an unsorted converter
// would fail this test intermittently.
func TestMetaMatch2HttpHeaderMatchIsOrderStable(t *testing.T) {
	match := &userapi.MetaRouteMatch{Attributes: map[string]*userapi.StringMatch{
		"zebra":  exact("1"),
		"apple":  prefix("p"),
		"mango":  regexMatch("r.*"),
		"banana": {},
		"lemon":  nil,
	}}

	first, err, warning := MetaMatch2HttpHeaderMatch(match)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warning == nil {
		t.Fatalf("expected a warning for the nil attribute")
	}

	// Explicitly assert the sorted order as well.
	wantNames := []string{"apple", "banana", "lemon", "mango", "zebra"}
	if len(first) != len(wantNames) {
		t.Fatalf("got %d matchers, want %d", len(first), len(wantNames))
	}
	for i, want := range wantNames {
		if first[i].Name != want {
			t.Fatalf("matcher %d name = %q, want %q; full order: %v", i, first[i].Name, want, matcherNames(first))
		}
	}

	for i := 0; i < 50; i++ {
		got, gotErr, gotWarning := MetaMatch2HttpHeaderMatch(match)
		if gotErr != nil || gotWarning == nil {
			t.Fatalf("iteration %d: err = %v, warning = %v", i, gotErr, gotWarning)
		}
		if !headerMatcherListsEqual(got, first) {
			t.Fatalf("iteration %d produced a different result: %v vs %v", i, matcherNames(got), matcherNames(first))
		}
	}
}

func matcherNames(matchers []*httproute.HeaderMatcher) []string {
	names := make([]string, 0, len(matchers))
	for _, m := range matchers {
		names = append(names, m.Name)
	}
	return names
}

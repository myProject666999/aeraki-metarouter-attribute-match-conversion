// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package xds

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"

	httpcore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	httproute "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/hashicorp/go-multierror"

	userapi "github.com/aeraki-mesh/api/metaprotocol/v1alpha1"
	metaroute "github.com/aeraki-mesh/meta-protocol-control-plane-api/aeraki/meta_protocol_proxy/config/route/v1alpha"
)

const (
	// MaxMetaAttributeNameLength is the maximum length in bytes of a MetaProtocol attribute name.
	//
	// Rationale: attributes are carried on a borrowed Envoy RDS HeaderMatcher, whose name field is
	// validated by protoc-gen-validate as at least one rune matching "^[^\x00\n\r]*$" with no
	// explicit upper bound. On the data path the name ends up in Envoy's request header block,
	// whose whole header list is capped by http.http_protocol_options.max_request_headers_kb
	// (default 60 KiB). A single name of 1 KiB already cannot coexist with a realistic number of
	// attributes, so 1024 bytes is a safe management-plane ceiling that stays an order of
	// magnitude below the transport limit. The same constant is used by the webhook validation.
	MaxMetaAttributeNameLength = 1024

	// MaxMetaRegexLength is the maximum length in bytes of a RE2 regex pattern accepted from a
	// MetaRouter.
	//
	// Rationale: Envoy compiles SafeRegex patterns with Google RE2 and rejects at config load any
	// regex whose compiled program size exceeds the runtime key re2.max_program_size.error_level,
	// which defaults to 100 (see envoy/type/matcher/v3/regex.proto). Go cannot evaluate the RE2
	// program size, and the program size is always larger than the pattern length, so Istio
	// approximates the check with a 1024-byte pattern length ceiling
	// (istio.io/istio/pkg/config/validation.validateStringMatchRegexp). Aeraki does not raise the
	// Envoy runtime default, so we adopt the same 1024-byte approximation; a pattern that passes
	// here can still be NACKed by Envoy if its compiled program size exceeds 100, which is logged
	// as an Envoy-side rejection rather than silently widened here.
	MaxMetaRegexLength = 1024

	// legacyCatchAllRegex is the historical, undocumented spelling for a "key must be present"
	// match. A bare "*" is not a valid RE2 expression, but older MetaMatch2HttpHeaderMatch
	// versions converted it to PresentMatch instead of handing it to RE2. Keep the conversion for
	// backward compatibility and report a warning so users migrate to the documented nil/empty
	// StringMatch spelling.
	legacyCatchAllRegex = "*"
)

// invalidAttributeNameChars mirrors the protoc-gen-validate rule on
// envoy.config.route.v3.HeaderMatcher.name: "^[^\x00\n\r]*$". The NUL, LF and CR control
// characters are rejected because the borrowed HeaderMatcher cannot carry them.
var invalidAttributeNameChars = regexp.MustCompile("[\x00\n\r]")

var regexEngine = &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}}

// We use Envoy RDS(HTTP RouteConfiguration) to transmit Meta Protocol Configuration from the RDS server to the Proxy
func metaProtocolRoute2HttpRoute(metaRoute *metaroute.RouteConfiguration) *httproute.RouteConfiguration {
	httpRoute := &httproute.RouteConfiguration{
		Name: metaRoute.Name,
		VirtualHosts: []*httproute.VirtualHost{
			{
				Name:    "dummy",
				Domains: []string{"*"},
			},
		},
	}

	for _, route := range metaRoute.Routes {
		routeMatch := httpRouteMatch(route)
		routeAction := httpRouteAction(route)
		requestHeaders := httpRequestHeaders(route)
		responseHeaders := httpResponseHeaders(route)
		httpRoute.VirtualHosts[0].Routes = append(httpRoute.VirtualHosts[0].Routes, &httproute.Route{
			Name:  route.Name,
			Match: routeMatch,
			Action: &httproute.Route_Route{
				Route: routeAction,
			},
			RequestHeadersToAdd:  requestHeaders,
			ResponseHeadersToAdd: responseHeaders,
		})
	}
	return httpRoute
}

func httpResponseHeaders(route *metaroute.Route) []*httpcore.HeaderValueOption {
	var responseHeaders []*httpcore.HeaderValueOption
	for _, mutation := range route.ResponseMutation {
		responseHeaders = append(responseHeaders, &httpcore.HeaderValueOption{
			Header: &httpcore.HeaderValue{
				Key:   mutation.Key,
				Value: mutation.Value,
			},
		})
	}
	return responseHeaders
}

func httpRequestHeaders(route *metaroute.Route) []*httpcore.HeaderValueOption {
	var requestHeaders []*httpcore.HeaderValueOption
	for _, mutation := range route.RequestMutation {
		requestHeaders = append(requestHeaders, &httpcore.HeaderValueOption{
			Header: &httpcore.HeaderValue{
				Key:   mutation.Key,
				Value: mutation.Value,
			},
		})
	}
	return requestHeaders
}

func httpRouteAction(route *metaroute.Route) *httproute.RouteAction {
	var routeAction = &httproute.RouteAction{}
	if route.Route.GetWeightedClusters() != nil {
		routeAction.ClusterSpecifier = &httproute.RouteAction_WeightedClusters{
			WeightedClusters: route.Route.GetWeightedClusters(),
		}
	} else {
		routeAction.ClusterSpecifier = &httproute.RouteAction_Cluster{
			Cluster: route.Route.GetCluster(),
		}
	}
	routeAction.RequestMirrorPolicies = make([]*httproute.
		RouteAction_RequestMirrorPolicy, len(route.Route.RequestMirrorPolicies))
	for i, mirrorPolicy := range route.Route.RequestMirrorPolicies {
		routeAction.RequestMirrorPolicies[i] = &httproute.RouteAction_RequestMirrorPolicy{
			Cluster:         mirrorPolicy.Cluster,
			RuntimeFraction: mirrorPolicy.RuntimeFraction,
		}
	}
	if len(route.Route.HashPolicy) > 0 {
		for _, hashPolicy := range route.Route.HashPolicy {
			routeAction.HashPolicy = append(routeAction.HashPolicy, &httproute.RouteAction_HashPolicy{
				PolicySpecifier: &httproute.RouteAction_HashPolicy_Header_{
					Header: &httproute.RouteAction_HashPolicy_Header{
						HeaderName: hashPolicy,
					},
				},
			})
		}
	}
	return routeAction
}

func httpRouteMatch(route *metaroute.Route) *httproute.RouteMatch {
	routeMatch := &httproute.RouteMatch{
		PathSpecifier: &httproute.RouteMatch_Prefix{
			Prefix: "/",
		},
	}
	for _, metadata := range route.Match.Metadata {
		routeMatch.Headers = append(routeMatch.Headers, &httproute.HeaderMatcher{
			Name:                 metadata.Name,
			HeaderMatchSpecifier: metadata.HeaderMatchSpecifier,
		})
	}
	return routeMatch
}

func generateSnapshot(metaRoutes []*metaroute.RouteConfiguration) (*cache.Snapshot, error) {
	var httpRoutes []types.Resource
	for _, route := range metaRoutes {
		httpRoutes = append(httpRoutes, metaProtocolRoute2HttpRoute(route))
	}
	return cache.NewSnapshot(
		strconv.FormatInt(time.Now().Unix(), 10),
		map[resource.Type][]types.Resource{
			resource.RouteType: httpRoutes,
		},
	)
}

// MetaMatch2HttpHeaderMatch converts MetaMatch to HttpHeaderMatch.
//
// MetaProtocol has no HTTP headers: match.attributes are metadata key/value pairs extracted from
// the wire payload by the protocol codec. The control plane borrows Envoy RDS and disguises each
// attribute as an Envoy HeaderMatcher, so the returned matchers follow Envoy HeaderMatcher
// semantics.
//
// The returned matchers are sorted by attribute name so that the same input always produces an
// equal RouteConfiguration even though matchCrd.Attributes is a map.
//
// Abnormal inputs are reported instead of being silently dropped. Errors are hard failures: the
// offending attribute is omitted from the result and the caller is expected to refuse publishing
// the whole configuration, because dropping a condition silently widens the match (e.g. a route
// with attributes user and env would match every request satisfying env alone). Warnings keep the
// historical conversion but make the behavior visible.
//
// Semantics of a missing key in the request metadata:
//   - PresentMatch (generated from a nil/empty StringMatch) requires the key to be present; a
//     missing key does not match.
//   - exact/prefix/regex matches on a missing key do not match either. The generated HeaderMatcher
//     leaves treat_missing_header_as_empty at its Envoy default false, so the rule is ignored for
//     a request that does not carry the key rather than comparing against an empty string.
//   - Whether "exact match of the empty string" is equivalent to "key missing" is therefore
//     intentionally not assumed: with the default false it is not. The data-plane meta-protocol
//     proxy owns the final evaluation, and this control plane does not flip the flag.
func MetaMatch2HttpHeaderMatch(matchCrd *userapi.MetaRouteMatch) ([]*httproute.HeaderMatcher, error, error) {
	if matchCrd == nil {
		return nil, nil, nil
	}

	var headerMatchers []*httproute.HeaderMatcher
	var errs *multierror.Error
	var warnings *multierror.Error

	// Sort the attribute names first so both diagnostics and the emitted matchers have a stable
	// order across conversions of the same map.
	names := make([]string, 0, len(matchCrd.Attributes))
	for name := range matchCrd.Attributes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		attribute := matchCrd.Attributes[name]
		headerMatcher, err, warning := metaAttribute2HttpHeaderMatch(name, attribute)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		if warning != nil {
			warnings = multierror.Append(warnings, warning)
		}
		if headerMatcher != nil {
			headerMatchers = append(headerMatchers, headerMatcher)
		}
	}
	return headerMatchers, errs.ErrorOrNil(), warnings.ErrorOrNil()
}

// metaAttribute2HttpHeaderMatch converts a single attribute. Disposition of the abnormal inputs:
//
//   - empty attribute name:            error, no matcher emitted (Envoy PGV requires a non-empty name)
//   - name too long / control chars:   error, no matcher emitted
//   - nil attribute value:             warning + PresentMatch, matching the historical behavior
//   - empty StringMatch (no oneof):    PresentMatch, this is the documented CRD spelling
//   - unknown oneof match type:        error, no matcher emitted (defensive; the oneof is sealed today)
//   - regex == "*":                    warning + PresentMatch, legacy catch-all spelling
//   - empty / uncompilable / too long regex: error, no matcher emitted (Envoy would NACK it)
func metaAttribute2HttpHeaderMatch(name string, attribute *userapi.StringMatch) (*httproute.HeaderMatcher, error,
	error) {
	if name == "" {
		return nil, fmt.Errorf("meta attribute name cannot be empty"), nil
	}
	if len(name) > MaxMetaAttributeNameLength {
		return nil, fmt.Errorf("meta attribute name %q is too long: %d bytes, max allowed is %d", name, len(name),
			MaxMetaAttributeNameLength), nil
	}
	if invalidAttributeNameChars.MatchString(name) {
		return nil, fmt.Errorf("meta attribute name %q contains invalid control characters (NUL, LF or CR)",
			name), nil
	}

	headerMatcher := &httproute.HeaderMatcher{Name: name}

	// A nil pointer and an empty StringMatch are the same thing on the wire: the CRD documents
	// that "if the value is empty and only the name of attribute is specified, presence of the
	// attribute is checked". The nil pointer is additionally warned on because the webhook rejects
	// it and reaching here means validation was bypassed.
	if attribute == nil {
		headerMatcher.HeaderMatchSpecifier = &httproute.HeaderMatcher_PresentMatch{PresentMatch: true}
		return headerMatcher, nil,
			fmt.Errorf("attribute %q has a null match value, converting to a present-match; fix the MetaRouter", name)
	}

	switch attribute.GetMatchType().(type) {
	case nil:
		headerMatcher.HeaderMatchSpecifier = &httproute.HeaderMatcher_PresentMatch{PresentMatch: true}
		return headerMatcher, nil, nil
	case *userapi.StringMatch_Exact:
		headerMatcher.HeaderMatchSpecifier = &httproute.HeaderMatcher_ExactMatch{
			ExactMatch: attribute.GetExact(),
		}
	case *userapi.StringMatch_Prefix:
		headerMatcher.HeaderMatchSpecifier = &httproute.HeaderMatcher_PrefixMatch{
			PrefixMatch: attribute.GetPrefix(),
		}
	case *userapi.StringMatch_Regex:
		regex := attribute.GetRegex()
		// Backward compatibility: a bare "*" used to be treated as a present-match even though it
		// is not valid RE2. Keep it, but make the reliance visible.
		if regex == legacyCatchAllRegex {
			headerMatcher.HeaderMatchSpecifier = &httproute.HeaderMatcher_PresentMatch{PresentMatch: true}
			return headerMatcher, nil,
				fmt.Errorf("attribute %q uses regex %q as a present-match, which is not valid RE2; "+
					"use an empty match value instead", name, legacyCatchAllRegex)
		}
		if regex == "" {
			return nil, fmt.Errorf("attribute %q has an empty regex match", name), nil
		}
		if len(regex) > MaxMetaRegexLength {
			return nil, fmt.Errorf("attribute %q regex is too long: %d bytes, max allowed is %d", name, len(regex),
				MaxMetaRegexLength), nil
		}
		if _, err := regexp.Compile(regex); err != nil {
			return nil, fmt.Errorf("attribute %q has an invalid RE2 regex: %w", name, err), nil
		}
		headerMatcher.HeaderMatchSpecifier = &httproute.HeaderMatcher_SafeRegexMatch{
			SafeRegexMatch: &matcher.RegexMatcher{
				EngineType: regexEngine,
				Regex:      regex,
			},
		}
	default:
		// The MatchType oneof is sealed today (exact/prefix/regex only); this branch guards
		// against future match types added without updating this converter. Dropping the attribute
		// here would silently widen the route match, so fail loudly instead.
		return nil, fmt.Errorf("attribute %q uses an unsupported string match type %T", name,
			attribute.GetMatchType()), nil
	}
	return headerMatcher, nil, nil
}

func translatePercentToFractionalPercent(p float64) *typev3.FractionalPercent {
	return &typev3.FractionalPercent{
		Numerator:   uint32(p * 10000),
		Denominator: typev3.FractionalPercent_MILLION,
	}
}

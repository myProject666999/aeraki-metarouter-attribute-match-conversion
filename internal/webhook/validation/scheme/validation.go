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
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/validation"
	"istio.io/istio/pkg/config/visibility"

	metaprotocol "github.com/aeraki-mesh/api/metaprotocol/v1alpha1"
)

// Validation holds errors and warnings. They can be joined with additional errors by called appendValidation
type Validation struct {
	Err     error
	Warning validation.Warning
}

// AnalysisAwareError wraps analysis error
type AnalysisAwareError struct {
	Type       string
	Msg        string
	Parameters []interface{}
}

var _ error = Validation{}

// WrapError turns an error into a Validation
func WrapError(e error) Validation {
	return Validation{Err: e}
}

// WrapWarning turns an error into a Validation as a warning
func WrapWarning(e error) Validation {
	return Validation{Warning: e}
}

// Warningf formats according to a format specifier and returns the string as a
// value that satisfies error. Like Errorf, but for warnings.
func Warningf(format string, a ...interface{}) Validation {
	return WrapWarning(fmt.Errorf(format, a...))
}

// Unwrap a validation
func (v Validation) Unwrap() (validation.Warning, error) {
	return v.Warning, v.Err
}

// Error return the error string
func (v Validation) Error() string {
	if v.Err == nil {
		return ""
	}
	return v.Err.Error()
}

// ValidatePort checks that the network port is in range
func ValidatePort(port int) error {
	if port >= 1 && port <= 65535 {
		return nil
	}
	return fmt.Errorf("port number %d must be in the range 1..65535", port)
}

// ValidateFQDN checks a fully-qualified domain name
func ValidateFQDN(fqdn string) error {
	if err := checkDNS1123Preconditions(fqdn); err != nil {
		return err
	}
	return validateDNS1123Labels(fqdn)
}

// encapsulates DNS 1123 checks common to both wildcarded hosts and FQDNs
func checkDNS1123Preconditions(name string) error {
	if len(name) > 255 {
		return fmt.Errorf("domain name %q too long (max 255)", name)
	}
	if name == "" {
		return fmt.Errorf("empty domain name not allowed")
	}
	return nil
}

func validateDNS1123Labels(domain string) error {
	parts := strings.Split(domain, ".")
	topLevelDomain := parts[len(parts)-1]
	if _, err := strconv.Atoi(topLevelDomain); err == nil {
		return fmt.Errorf("domain name %q invalid (top level domain %q cannot be all-numeric)", domain, topLevelDomain)
	}
	for i, label := range parts {
		// Allow the last part to be empty, for unambiguous names like `istio.io.`
		if i == len(parts)-1 && label == "" {
			return nil
		}
		if !labels.IsDNS1123Label(label) {
			return fmt.Errorf("domain name %q invalid (label %q invalid)", domain, label)
		}
	}
	return nil
}

// MaxMetaAttributeNameLength mirrors xds.MaxMetaAttributeNameLength. It is duplicated rather than
// imported because the validation package must not depend on the xds conversion package.
const MaxMetaAttributeNameLength = 1024

// MaxMetaRegexLength mirrors xds.MaxMetaRegexLength: Go cannot measure the RE2 program size Envoy
// enforces (re2.max_program_size.error_level, default 100), and Istio uses the same 1024-byte
// pattern-length approximation in its own StringMatch validation.
const MaxMetaRegexLength = 1024

// metaAttributeNameInvalidChars mirrors the protoc-gen-validate rule on the borrowed Envoy
// HeaderMatcher name: "^[^\x00\n\r]*$".
var metaAttributeNameInvalidChars = regexp.MustCompile("[\x00\n\r]")

// ValidateMetaAttributeName validates a MetaProtocol attribute name.
//
// The empty-name check stays a hard error: an empty name has never been a valid attribute and the
// conversion cannot emit a HeaderMatcher without a name. Length and character-set checks were
// added later (see validateMetaRouteMatch for the warning-vs-error policy on existing resources):
// they reject names that exceed MaxMetaAttributeNameLength bytes or contain NUL/LF/CR, matching
// the limit applied by the xds converter and Envoy's HeaderMatcher PGV rule.
func ValidateMetaAttributeName(name string) error {
	if name == "" {
		return fmt.Errorf("attribute name cannot be empty")
	}
	if len(name) > MaxMetaAttributeNameLength {
		return fmt.Errorf("attribute name %q is too long: %d bytes, max allowed is %d", name, len(name),
			MaxMetaAttributeNameLength)
	}
	if metaAttributeNameInvalidChars.MatchString(name) {
		return fmt.Errorf("attribute name %q contains invalid control characters (NUL, LF or CR)", name)
	}
	return nil
}

// ValidatePercent checks that percent is in range
func ValidatePercent(val uint32) error {
	if val > 100 {
		return fmt.Errorf("percentage %v is not in range 0..100", val)
	}
	return nil
}

func validateExportTo(namespace string, exportTo []string) (errs error) {
	if len(exportTo) > 0 {
		// Make sure there are no duplicates
		exportToMap := make(map[string]struct{})
		for _, e := range exportTo {
			key := e
			if visibility.Instance(e) == visibility.Private {
				// substitute this with the current namespace so that we
				// can check for duplicates like ., namespace
				key = namespace
			}
			if _, exists := exportToMap[key]; exists {
				if key != e {
					errs = appendErrors(errs, fmt.Errorf("duplicate entries in exportTo: . and current namespace %s", namespace))
				} else {
					errs = appendErrors(errs, fmt.Errorf("duplicate entries in exportTo for entry %s", e))
				}
			} else {
				if err := visibility.Instance(key).Validate(); err != nil {
					errs = appendErrors(errs, err)
				} else {
					exportToMap[key] = struct{}{}
				}
			}
		}

		// Make sure we have only one of . or *
		if _, public := exportToMap[string(visibility.Public)]; public {
			// make sure that there are no other entries in the exportTo
			// i.e. no point in saying ns1,ns2,*. Might as well say *
			if len(exportTo) > 1 {
				errs = appendErrors(errs, fmt.Errorf("cannot have both public (*) and non-public exportTo values for a resource"))
			}
		}

		// if this is a service entry, then we need to disallow * and ~ together. Or ~ and other namespaces
		if _, none := exportToMap[string(visibility.None)]; none {
			if len(exportTo) > 1 {
				errs = appendErrors(errs, fmt.Errorf("cannot export service entry to no one (~) and someone"))
			}
		}
	}

	return errs
}

// ValidateMetaRouter checks that a v1alpha1 route rule is well-formed.
var ValidateMetaRouter = func(cfg config.Config) (validation.Warning, error) {
	metaRouter, ok := cfg.Spec.(*metaprotocol.MetaRouter)
	if !ok {
		return nil, errors.New("cannot cast to meta router")
	}
	errs := Validation{}
	if len(metaRouter.Hosts) == 0 {
		errs = appendValidation(errs, fmt.Errorf("meta router must have one host"))
	}
	if len(metaRouter.Hosts) > 1 {
		errs = appendValidation(errs, fmt.Errorf("meta router can only have one host"))
	}
	if len(metaRouter.Hosts) == 1 {
		if err := ValidateFQDN(metaRouter.Hosts[0]); err != nil {
			errs = appendValidation(errs, err)
		}
	}

	if len(metaRouter.Routes) == 0 && metaRouter.GlobalRateLimit == nil && metaRouter.LocalRateLimit == nil {
		errs = appendValidation(errs, errors.New("meta router must at least have one of routes, globalRateLimit,"+
			" or LocalRateLimit"))
	}

	for _, route := range metaRouter.Routes {
		if route == nil {
			errs = appendValidation(errs, errors.New("meta route may not be null"))
			continue
		}
		errs = appendValidation(errs, validateMetaRoute(route))
	}

	errs = appendValidation(errs, validateExportTo(cfg.Namespace, metaRouter.ExportTo))

	warnUnused := func(ruleno, reason string) {
		errs = appendValidation(errs, WrapWarning(&AnalysisAwareError{
			Type:       "MetaRouterUnreachableRule",
			Msg:        fmt.Sprintf("MetaRouter rule %v not used (%s)", ruleno, reason),
			Parameters: []interface{}{ruleno, reason},
		}))
	}
	warnIneffective := func(ruleno, matchno, dupno string) {
		errs = appendValidation(errs, WrapWarning(&AnalysisAwareError{
			Type: "MetaRouterIneffectiveMatch",
			Msg: fmt.Sprintf("MetaRouter rule %v match %v is not used (duplicate/overlapping match in rule %v)",
				ruleno, matchno, dupno),
			Parameters: []interface{}{ruleno, matchno, dupno},
		}))
	}

	analyzeUnreachableMetaRules(metaRouter.Routes, warnUnused, warnIneffective)

	errs = appendValidation(errs, validateGlobalRateLimit(metaRouter.GlobalRateLimit))
	errs = appendValidation(errs, validateLocalRateLimit(metaRouter.LocalRateLimit))
	return errs.Unwrap()
}

func validateGlobalRateLimit(limit *metaprotocol.GlobalRateLimit) (errs Validation) {
	if limit != nil {
		errs = appendValidation(errs, validateNoneEmptyString(limit.Domain, "globalRateLimit domain"))
		errs = appendValidation(errs, validateNoneEmptyString(limit.RateLimitService, "globalRateLimit cluster"))
		errs = appendValidation(errs, validateMetaRouteMatch(limit.Match))
		errs = appendValidation(errs, validateRateLimitDescriptors(limit.Descriptors))
	}
	return
}

func validateLocalRateLimit(limit *metaprotocol.LocalRateLimit) (errs Validation) {
	if limit != nil {
		if limit.TokenBucket == nil && len(limit.Conditions) == 0 {
			errs = appendValidation(errs, errors.New("localRateLimit must have at least one of tokenBucket or conditions"))
		}
		errs = appendValidation(errs, validateTokenBucket(limit.TokenBucket))
		for _, condition := range limit.Conditions {
			errs = appendValidation(errs, validateLocalRateLimitCondition(condition))
		}
	}
	return
}

func validateLocalRateLimitCondition(condition *metaprotocol.LocalRateLimit_Condition) (errs Validation) {
	errs = appendValidation(errs, validateNoneNullObject(condition.Match, "localRateLimit condition match"))
	errs = appendValidation(errs, validateMetaRouteMatch(condition.Match))
	errs = appendValidation(errs, validateNoneNullObject(condition.TokenBucket, "localRateLimit condition tokenBucket"))
	errs = appendValidation(errs, validateTokenBucket(condition.TokenBucket))
	return
}

func validateTokenBucket(bucket *metaprotocol.LocalRateLimit_TokenBucket) (errs Validation) {
	if bucket != nil {
		errs = appendValidation(errs, validateNoneNullObject(bucket.FillInterval,
			"localRateLimit tokenBucket fillInterval"))
		errs = appendValidation(errs, validateNoneNullObject(bucket.TokensPerFill,
			"localRateLimit tokenBucket tokensPerfFill"))
		if bucket.TokensPerFill != nil && bucket.TokensPerFill.Value < 1 {
			errs = appendValidation(errs,
				errors.New("localRateLimit tokenBucket tokensPerfFill must be greater than 0"))
		}
		if bucket.MaxTokens < 1 {
			errs = appendValidation(errs, errors.New("localRateLimit tokenBucket maxTokens must be greater than 0"))
		}
	}
	return
}

func validateNoneEmptyString(str, name string) error {
	if str == "" {
		return errors.New(name + " cannot be empty")
	}
	return nil
}

func validateNoneNullObject(obj interface{}, name string) error {
	if reflect.ValueOf(obj).Kind() == reflect.Ptr && reflect.ValueOf(obj).IsNil() {
		return errors.New(name + " cannot be null")
	}
	return nil
}

func validateRateLimitDescriptors(descriptors []*metaprotocol.GlobalRateLimit_Descriptor) (errs Validation) {
	if len(descriptors) == 0 {
		errs = appendValidation(errs, fmt.Errorf("globalRateLimit must have descriptors"))
	}
	for _, descriptor := range descriptors {
		errs = appendValidation(errs, validateNoneEmptyString(descriptor.DescriptorKey,
			"globalRateLimit descriptor key"))
		errs = appendValidation(errs, validateNoneEmptyString(descriptor.Property,
			"globalRateLimit descriptor property"))
	}
	return
}

func validateMetaRoute(route *metaprotocol.MetaRoute) (errs Validation) {
	// check meta route match requests
	errs = appendValidation(errs, validateMetaRouteMatch(route.Match))

	// request manipulation
	for _, kv := range route.RequestMutation {
		if kv.Key == "" {
			errs = appendValidation(errs, fmt.Errorf("mutation key cannot be empty"))
		}
		if kv.Value == "" {
			errs = appendValidation(errs, fmt.Errorf("mutation value cannot be empty"))
		}
	}

	// response manipulation
	for _, kv := range route.ResponseMutation {
		if kv.Key == "" {
			errs = appendValidation(errs, fmt.Errorf("mutation key cannot be empty"))
		}
		if kv.Value == "" {
			errs = appendValidation(errs, fmt.Errorf("mutation value cannot be empty"))
		}
	}

	if route.MirrorPercentage != nil && route.Mirror == nil {
		errs = appendValidation(errs, fmt.Errorf("mirrorPercentage and mirror must be set together"))
	}

	if route.MirrorPercentage != nil {
		value := route.MirrorPercentage.GetValue()
		if value > 100 {
			errs = appendValidation(errs, fmt.Errorf("mirrorPercentage must not be greater than 100 (it has %f)",
				value))
		}
		if value <= 0 {
			errs = appendValidation(errs, fmt.Errorf("mirrorPercentage must not be less than or equal to 0 ("+
				"it has %f)",
				value))
		}
	}

	errs = appendValidation(errs, validateDestination(route.Mirror))
	errs = appendValidation(errs, validateMetaRouteDestinations(route.Route))

	return errs
}

func validateMetaRouteMatch(match *metaprotocol.MetaRouteMatch) (errs Validation) {
	if match == nil {
		return errs
	}
	// Sort names so repeated validations of the same resource report diagnostics in a stable
	// order and table-driven tests can assert a deterministic result.
	names := make([]string, 0, len(match.Attributes))
	for name := range match.Attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		attribute := match.Attributes[name]
		if attribute == nil {
			// Kept a hard error: a null match value was never representable as a meaningful
			// condition and the xds converter only tolerates it for backward compatibility.
			errs = appendValidation(errs, fmt.Errorf("attribute match %v cannot be null", name))
		}
		if name == "" {
			errs = appendValidation(errs, errors.New("attribute name cannot be empty"))
		} else {
			// Length/charset violations are reported as warnings rather than hard errors so that
			// MetaRouters already stored in the cluster are not blocked from updating (for
			// example a status or an unrelated rule). New creates get the same warning through
			// the admission response's Warnings field; operators should fix the name because the
			// xds converter refuses to publish an invalid attribute.
			if err := validateMetaAttributeNameContent(name); err != nil {
				errs = appendValidation(errs, WrapWarning(err))
			}
		}
		errs = appendValidation(errs, validateStringMatchRegexp(attribute, "attributes"))
	}
	return errs
}

// validateMetaAttributeNameContent performs the length and character-set checks added after
// ValidateMetaAttributeName was released with an empty-name-only check. Split out so callers can
// turn these newer violations into warnings for pre-existing resources while keeping empty names
// a hard rejection.
func validateMetaAttributeNameContent(name string) error {
	if len(name) > MaxMetaAttributeNameLength {
		return fmt.Errorf("attribute name %q is too long: %d bytes, max allowed is %d", name, len(name),
			MaxMetaAttributeNameLength)
	}
	if metaAttributeNameInvalidChars.MatchString(name) {
		return fmt.Errorf("attribute name %q contains invalid control characters (NUL, LF or CR)", name)
	}
	return nil
}

// nolint: unparam
func analyzeUnreachableMetaRules(routes []*metaprotocol.MetaRoute,
	reportUnreachable func(ruleno, reason string), _ func(ruleno, matchno, dupno string)) {
	emptyMatchEncountered := -1
	for rulen, route := range routes {
		if route == nil {
			continue
		}
		if route.Match == nil {
			if emptyMatchEncountered >= 0 {
				reportUnreachable(routeName(route, rulen), "only the last rule can have no match")
			}
			emptyMatchEncountered = rulen
			continue
		}
		// TODO check duplicated or overlapping match
	}
}

// ValidateApplicationProtocol checks that a v1alpha1 application protocol is well-formed.
var ValidateApplicationProtocol = func(cfg config.Config) (validation.Warning, error) {
	protocol, ok := cfg.Spec.(*metaprotocol.ApplicationProtocol)
	if !ok {
		return nil, errors.New("cannot cast to application protocol")
	}
	errs := Validation{}
	if protocol.Protocol == "" {
		errs = appendValidation(errs, fmt.Errorf("application protocol must have protocol"))
	}
	if protocol.Codec == "" {
		errs = appendValidation(errs, fmt.Errorf("application protocol must have codec"))
	}

	return errs.Unwrap()
}

func routeName(route interface{}, routen int) string {
	switch r := route.(type) {
	case *networking.HTTPRoute:
		if r.Name != "" {
			return fmt.Sprintf("%q", r.Name)
		}

		// TCP and TLS routes have no names
	}

	return fmt.Sprintf("#%d", routen)
}

// validateStringMatchRegexp returns a Validation so the legacy regex "*" can be reported as a
// warning while everything that would make the xds conversion fail stays a hard error.
func validateStringMatchRegexp(sm *metaprotocol.StringMatch, where string) Validation {
	if _, ok := sm.GetMatchType().(*metaprotocol.StringMatch_Regex); !ok {
		return Validation{}
	}
	re := sm.GetRegex()
	// Backward compatibility: historical builds converted regex "*" into a present-match even
	// though "*" is not valid RE2. Warn instead of rejecting so MetaRouters already relying on it
	// keep updating; the xds converter performs the same present-match conversion.
	if re == "*" {
		return WrapWarning(fmt.Errorf("%q: regex %q is not valid RE2 and is treated as a present-match; "+
			"use an empty match value instead", where, re))
	}
	if re == "" {
		return WrapError(fmt.Errorf("%q: regex string match should not be empty", where))
	}
	// Envoy enforces re2.max_program_size.error_level (default 100) on the compiled program; the
	// program size is always larger than the pattern length and Go cannot evaluate it, so the
	// pattern length is used as an approximation, mirroring Istio's StringMatch validation.
	if len(re) > MaxMetaRegexLength {
		return WrapError(fmt.Errorf("%q: regex is too long: %d bytes, max allowed is %d", where, len(re),
			MaxMetaRegexLength))
	}

	if _, err := regexp.Compile(re); err != nil {
		return WrapError(fmt.Errorf("%q: %w; Aeraki uses RE2 style regex-based match (https://github.com/google/re2/wiki/Syntax)",
			where, err))
	}
	return Validation{}
}

func validateMetaRouteDestinations(destinations []*metaprotocol.MetaRouteDestination) (errs error) {
	if len(destinations) == 0 {
		return errors.New("a route must has at least one destination")
	}
	var totalWeight uint32
	for _, destination := range destinations {
		if destination == nil {
			errs = multierror.Append(errs, errors.New("weight may not be nil"))
			continue
		}
		if destination.Destination == nil {
			errs = multierror.Append(errs, errors.New("destination is required"))
		}
		errs = appendErrors(errs, validateDestination(destination.Destination))
		errs = appendErrors(errs, ValidatePercent(destination.Weight))
		totalWeight += destination.Weight
	}
	if len(destinations) > 1 && totalWeight != 100 {
		errs = appendErrors(errs, fmt.Errorf("total destination weight %v != 100", totalWeight))
	}
	return
}

func validateDestination(destination *metaprotocol.Destination) (errs error) {
	if destination == nil {
		return
	}

	errs = appendErrors(errs, ValidateFQDN(destination.Host))

	if destination.Subset != "" {
		errs = appendErrors(errs, validateSubsetName(destination.Subset))
	}
	if destination.Port != nil {
		errs = appendErrors(errs, validatePortSelector(destination.Port))
	}

	return
}

func validateSubsetName(name string) error {
	if name == "" {
		return fmt.Errorf("subset name cannot be empty")
	}
	if !labels.IsDNS1123Label(name) {
		return fmt.Errorf("subset name is invalid: %s", name)
	}
	return nil
}

func validatePortSelector(selector *metaprotocol.PortSelector) (errs error) {
	if selector == nil {
		return nil
	}

	// port must be a number
	number := int(selector.GetNumber())
	errs = appendErrors(errs, ValidatePort(number))
	return
}

// ValidatePortName validates a port name to DNS-1123
func ValidatePortName(name string) error {
	if !labels.IsDNS1123Label(name) {
		return fmt.Errorf("invalid port name: %s", name)
	}
	return nil
}

// ValidateProtocol validates a portocol name is known
func ValidateProtocol(protocolStr string) error {
	// Empty string is used for protocol sniffing.
	if protocolStr != "" && protocol.Parse(protocolStr) == protocol.Unsupported {
		return fmt.Errorf("unsupported protocol: %s", protocolStr)
	}
	return nil
}

// wrapper around multierror.Append that enforces the invariant that if all input errors are nil, the output
// error is nil (allowing validation without branching).
func appendValidation(v Validation, vs ...error) Validation {
	appendError := func(err, err2 error) error {
		if err == nil {
			return err2
		} else if err2 == nil {
			return err
		}
		return multierror.Append(err, err2)
	}

	for _, nv := range vs {
		switch t := nv.(type) {
		case Validation:
			v.Err = appendError(v.Err, t.Err)
			v.Warning = appendError(v.Warning, t.Warning)
		default:
			v.Err = appendError(v.Err, t)
		}
	}
	return v
}

// wrapper around multierror.Append that enforces the invariant that if all input errors are nil, the output
// error is nil (allowing validation without branching).
func appendErrors(err error, errs ...error) error {
	appendError := func(err, err2 error) error {
		if err == nil {
			return err2
		} else if err2 == nil {
			return err
		}
		return multierror.Append(err, err2)
	}

	for _, err2 := range errs {
		switch t := err2.(type) {
		case Validation:
			err = appendError(err, t.Err)
		default:
			err = appendError(err, err2)
		}
	}
	return err
}

// Error return the error string
func (aae *AnalysisAwareError) Error() string {
	return aae.Msg
}

package saml

import (
	"errors"
	"fmt"
)

// Sentinel errors identifying why ParseResponse, ParseXMLResponse and
// ParseXMLArtifactResponse rejected a response. They are reachable with
// errors.Is on the returned *InvalidResponseError (which unwraps to its
// PrivateErr), so callers can classify failures without matching on message
// text. The human-readable messages are unchanged.
var (
	// ErrSignatureMissing means the Response or the Assertion that had to be
	// signed carries no Signature element.
	ErrSignatureMissing = errors.New("signature element not present")

	// ErrSignatureInvalid means a Signature element is present but could not
	// be validated: bad digest or signature value, a certificate that is not
	// one of the IDP's signing certificates, a malformed or ambiguous
	// Signature, or no usable signing certificate in the IDP metadata.
	ErrSignatureInvalid = errors.New("signature validation failed")

	// ErrExpired means the Response, the Assertion, its SubjectConfirmationData
	// or its Conditions are past their validity window.
	ErrExpired = errors.New("expired")

	// ErrNotYetValid means Conditions/@NotBefore lies in the future (beyond
	// MaxClockSkew).
	ErrNotYetValid = errors.New("not yet valid")

	// ErrAudienceMismatch means the Assertion's AudienceRestriction does not
	// contain this service provider (or the ValidateAudienceRestriction hook
	// rejected it).
	ErrAudienceMismatch = errors.New("audience restriction mismatch")

	// ErrInResponseToMismatch means the InResponseTo of the Response (or of an
	// Assertion's SubjectConfirmationData) is not one of the possible request
	// IDs (or the ValidateRequestID hook rejected it).
	ErrInResponseToMismatch = errors.New("InResponseTo mismatch")

	// ErrDestinationMismatch means the Response's Destination is neither the
	// request URL nor the ACS URL.
	ErrDestinationMismatch = errors.New("destination mismatch")

	// ErrRecipientMismatch means an Assertion's SubjectConfirmationData
	// Recipient is not the ACS URL.
	ErrRecipientMismatch = errors.New("recipient mismatch")

	// ErrIssuerMismatch means the Issuer of the Response or the Assertion is not
	// the IDP entity ID from the metadata.
	ErrIssuerMismatch = errors.New("issuer mismatch")
)

// classifiedError carries a diagnostic message together with the sentinel
// (kind) it falls under and, optionally, the underlying cause.
type classifiedError struct {
	msg   string
	kind  error
	cause error
}

func (e *classifiedError) Error() string { return e.msg }

func (e *classifiedError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}

	return []error{e.kind, e.cause}
}

// classify returns an error with the formatted message that matches kind with
// errors.Is. Use %v, not %w, in format; pass a wrapped cause via classifyCause.
func classify(kind error, format string, args ...interface{}) error {
	return &classifiedError{msg: fmt.Sprintf(format, args...), kind: kind}
}

// classifyCause is like classify and also exposes cause to errors.Is/As.
func classifyCause(kind, cause error, format string, args ...interface{}) error {
	return &classifiedError{msg: fmt.Sprintf(format, args...), kind: kind, cause: cause}
}

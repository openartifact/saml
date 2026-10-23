package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/golden"
)

// TestParseResponseTypedErrors checks that every rejection reason maps to its
// sentinel with errors.Is through *InvalidResponseError.
func TestParseResponseTypedErrors(t *testing.T) {
	const requestID = "id-9e61753d64e928af5a7a341a97f420c9"

	resetClock := func() {
		TimeNow = func() time.Time {
			rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
			return rv
		}
		Clock = dsig.NewFakeClockAt(TimeNow())
	}

	cases := []struct {
		name  string
		setup func(s *ServiceProvider) []string // returns the possible request IDs
		want  error
	}{
		{"in response to mismatch", func(*ServiceProvider) []string { return []string{"other"} }, ErrInResponseToMismatch},
		{"issuer mismatch", func(s *ServiceProvider) []string {
			s.IDPMetadata.EntityID = "http://snakeoil.com"
			return []string{requestID}
		}, ErrIssuerMismatch},
		{"expired", func(*ServiceProvider) []string {
			TimeNow = func() time.Time {
				rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Nov 30 20:57:09 UTC 2016")
				return rv
			}
			Clock = dsig.NewFakeClockAt(TimeNow())
			return []string{requestID}
		}, ErrExpired},
		{"unparseable certificate in metadata", func(s *ServiceProvider) []string {
			s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data = "aW52YWxpZA=="
			return []string{requestID}
		}, ErrSignatureInvalid},
		{"acs url change surfaces as recipient mismatch", func(s *ServiceProvider) []string {
			s.AcsURL = mustParseURL("https://elsewhere.example/saml2/acs")
			return []string{requestID}
		}, ErrRecipientMismatch},
		{"request id hook rejects", func(s *ServiceProvider) []string {
			s.ValidateRequestID = func(Response, []string) error { return errors.New("nope") }
			return []string{requestID}
		}, ErrInResponseToMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetClock()

			test := NewServiceProviderTest(t)
			s := ServiceProvider{
				Key:         test.Key,
				Certificate: test.Certificate,
				MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
				AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
				IDPMetadata: &EntityDescriptor{},
			}
			if err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata); err != nil {
				t.Fatal(err)
			}

			ids := tc.setup(&s)
			reqURL := mustParseURL("https://15661444.ngrok.io/saml2/acs")
			req := http.Request{PostForm: url.Values{}, URL: &reqURL}
			req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))

			_, err := s.ParseResponse(&req, ids)
			var ire *InvalidResponseError
			if !errors.As(err, &ire) {
				t.Fatalf("expected *InvalidResponseError, got %T (%v)", err, err)
			}

			if !errors.Is(err, tc.want) {
				t.Fatalf("errors.Is(%v, %v) = false; private error: %v", err, tc.want, ire.PrivateErr)
			}

			if ire.Error() != "Authentication failed" {
				t.Errorf("Error() must stay generic, got %q", ire.Error())
			}
		})
	}
}

func TestParseResponseBadStatusIsTyped(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	if err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata); err != nil {
		t.Fatal(err)
	}

	old := StatusSuccess
	StatusSuccess = "not:the:success:value"

	defer func() { StatusSuccess = old }()

	reqURL := s.AcsURL
	req := http.Request{PostForm: url.Values{}, URL: &reqURL}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))

	_, err := s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})

	var bad ErrBadStatus
	if !errors.As(err, &bad) {
		t.Fatalf("expected ErrBadStatus through errors.As, got %v", err)
	}
}

func TestValidateAssertionTypedErrors(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	if err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata); err != nil {
		t.Fatal(err)
	}

	assertion := func() *Assertion {
		a := &Assertion{}
		a.IssueInstant = TimeNow()
		a.Issuer.Value = s.IDPMetadata.EntityID
		a.Subject = &Subject{SubjectConfirmations: []SubjectConfirmation{{SubjectConfirmationData: &SubjectConfirmationData{
			InResponseTo: "req", Recipient: s.AcsURL.String(), NotOnOrAfter: TimeNow().Add(time.Minute),
		}}}}
		a.Conditions = &Conditions{
			NotBefore: TimeNow().Add(-time.Minute), NotOnOrAfter: TimeNow().Add(time.Minute),
			AudienceRestrictions: []AudienceRestriction{{Audience: Audience{Value: s.MetadataURL.String()}}},
		}

		return a
	}

	ids := []string{"req"}

	if err := s.validateAssertion(assertion(), ids, TimeNow()); err != nil {
		t.Fatalf("baseline assertion must validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(a *Assertion)
		now    time.Time
		want   error
	}{
		{"issue instant expired", func(*Assertion) {}, TimeNow().Add(time.Hour), ErrExpired},
		{"issuer", func(a *Assertion) { a.Issuer.Value = "bob" }, TimeNow(), ErrIssuerMismatch},
		{"subject confirmation in response to", func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "x"
		}, TimeNow(), ErrInResponseToMismatch},
		{"recipient", func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "wrong"
		}, TimeNow(), ErrRecipientMismatch},
		{"subject confirmation expired", func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = TimeNow().Add(-time.Hour)
		}, TimeNow(), ErrExpired},
		{"not yet valid", func(a *Assertion) { a.Conditions.NotBefore = TimeNow().Add(time.Hour) }, TimeNow(), ErrNotYetValid},
		{"conditions expired", func(a *Assertion) { a.Conditions.NotOnOrAfter = TimeNow().Add(-time.Hour) }, TimeNow(), ErrExpired},
		{"audience", func(a *Assertion) {
			a.Conditions.AudienceRestrictions[0].Audience.Value = "not/us"
		}, TimeNow(), ErrAudienceMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := assertion()
			tc.mutate(a)

			err := s.validateAssertion(a, ids, tc.now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want errors.Is %v", err, tc.want)
			}
		})
	}

	t.Run("audience hook error is wrapped", func(t *testing.T) {
		boom := errors.New("boom")
		s2 := s
		s2.ValidateAudienceRestriction = func(*Assertion) error { return boom }

		err := s2.validateAssertion(assertion(), ids, TimeNow())
		if !errors.Is(err, ErrAudienceMismatch) || !errors.Is(err, boom) {
			t.Fatalf("hook error must match both sentinel and cause, got %v", err)
		}
	})

	t.Run("nil subject, conditions and confirmation data do not panic", func(t *testing.T) {
		a := assertion()
		a.Subject = nil
		if err := s.validateAssertion(a, ids, TimeNow()); err == nil {
			t.Error("nil Subject must be rejected")
		}

		a = assertion()
		a.Conditions = nil
		if err := s.validateAssertion(a, ids, TimeNow()); err == nil {
			t.Error("nil Conditions must be rejected")
		}

		a = assertion()
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData = nil
		if err := s.validateAssertion(a, ids, TimeNow()); err == nil {
			t.Error("nil SubjectConfirmationData must be rejected")
		}
	})
}

func TestParseResponseDestinationMismatchIsTyped(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	if err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata); err != nil {
		t.Fatal(err)
	}

	req := http.Request{PostForm: url.Values{}, URL: &s.AcsURL}
	s.AcsURL = mustParseURL("https://wrong/saml2/acs")

	raw, _ := test.responseDom(t).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(raw))

	_, err := s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	if !errors.Is(err, ErrDestinationMismatch) {
		t.Fatalf("expected ErrDestinationMismatch, got %v", err)
	}
}

func TestParseResponseSignatureErrorsAreTyped(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 16:55:39 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	defer func() {
		TimeNow = func() time.Time {
			rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
			return rv
		}
		Clock = dsig.NewFakeClockAt(TimeNow())
	}()

	response := golden.Get(t, "TestSPCanHandlePlaintextResponse_response")
	idpMetadata := golden.Get(t, "TestSPCanHandlePlaintextResponse_IDPMetadata")

	newSP := func() ServiceProvider {
		s := ServiceProvider{
			Key:         test.Key,
			Certificate: test.Certificate,
			MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
			AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
			IDPMetadata: &EntityDescriptor{},
		}
		if err := xml.Unmarshal(idpMetadata, &s.IDPMetadata); err != nil {
			t.Fatal(err)
		}

		return s
	}

	parse := func(s *ServiceProvider, raw []byte) error {
		req := http.Request{PostForm: url.Values{}, URL: &s.AcsURL}
		req.PostForm.Set("SAMLResponse", string(raw))
		_, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})

		return err
	}

	t.Run("unsigned", func(t *testing.T) {
		decoded, err := base64.StdEncoding.DecodeString(string(response))
		if err != nil {
			t.Fatal(err)
		}

		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(decoded); err != nil {
			t.Fatal(err)
		}

		for _, sig := range doc.FindElements("//Signature") {
			sig.Parent().RemoveChild(sig)
		}

		stripped, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}

		s := newSP()
		err = parse(&s, []byte(base64.StdEncoding.EncodeToString(stripped)))

		if !errors.Is(err, ErrSignatureMissing) {
			t.Fatalf("expected ErrSignatureMissing, got %v", err)
		}
	})

	t.Run("signed by a certificate that is not in the metadata", func(t *testing.T) {
		s := newSP()
		// The metadata certificate is replaced by the SP's own, unrelated one.
		s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data =
			base64.StdEncoding.EncodeToString(test.Certificate.Raw)

		err := parse(&s, response)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected ErrSignatureInvalid, got %v", err)
		}

		if errors.Is(err, ErrSignatureMissing) {
			t.Fatal("an invalid signature must not be reported as missing")
		}
	})
}

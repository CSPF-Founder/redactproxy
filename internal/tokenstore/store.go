// Package tokenstore provides a persistent, process-local, bidirectional
// mapping between real sensitive values (domains, IPs, emails, phone
// numbers) and fake token values, backed by bbolt with a full in-memory
// mirror for zero-disk-I/O lookups on the hot path.
package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// EntityType identifies the category of a real value, which determines how
// its token is generated and formatted.
type EntityType string

const (
	// EntityDomain tokens identify an organization (a registrable
	// domain, effective TLD+1). Shared across every subdomain and every
	// email address at that organization, so "ns1.", "portal.", and
	// "admin@" all resolve to the same org-token; see the redact
	// package's domain-splitting logic for why.
	EntityDomain EntityType = "domain"
	// EntityIPNetwork tokens identify an IPv4 /24 network (the first
	// three octets), NOT a whole address. Shared across every host in
	// that network, so two real addresses in the same /24 also share the
	// same fake /24: their tokens differ only in the last octet, which
	// is preserved from the real address, exactly like an IPv4 analogue
	// of subdomain-label preservation; see the redact package's IPv4
	// detector for why.
	EntityIPNetwork EntityType = "ip_network"
	// EntityIPv6Network tokens identify an IPv6 /64 network (the first
	// four groups / 64 bits); the interface ID (last 64 bits) is
	// preserved from the real address the same way.
	EntityIPv6Network EntityType = "ipv6_network"
	// EntityEmailLocal tokens identify one mailbox's local part alone
	// (the piece before "@"), independent of EntityDomain. An email
	// address is redacted as (local-part token) + "@" + (shared
	// org-token) + "." + (real, preserved suffix).
	EntityEmailLocal EntityType = "email_local"
	// EntityPhone tokens identify a NANP-shaped (US/Canada) phone number.
	EntityPhone EntityType = "phone"
	// EntityIntlPhone tokens identify a non-NANP international phone
	// number's subscriber portion. The real country calling code is NOT
	// part of the stored real value's identity; it's preserved
	// literally in the output text (see redact.intlPhoneDetector),
	// exactly like a domain's public suffix, so Claude retains the
	// number's country/region context.
	EntityIntlPhone EntityType = "intl_phone"
	// EntityJWT tokens identify a whole JSON Web Token (all three
	// dot-separated segments) found in text: fully opaque, no internal
	// structure preserved, since a JWT's payload is exactly the kind of
	// thing that must never reach the model.
	EntityJWT EntityType = "jwt"
	// EntityBearerToken tokens identify an opaque bearer/API token
	// following an "Authorization: Bearer " (or similar) header; the
	// literal word "Bearer" is left untouched; only the token value
	// itself is redacted. JWT-shaped bearer tokens are claimed by
	// EntityJWT instead (see redact.bearerDetector), so this is only for
	// non-JWT opaque tokens.
	EntityBearerToken EntityType = "bearer_token"
	// EntityAWSKey tokens identify an AWS access key ID
	// (AKIA/ASIA-prefixed, 20 chars total).
	EntityAWSKey EntityType = "aws_key"
	// EntityAWSSecretKey tokens identify an AWS secret access key (40
	// base64-alphabet characters, keyword-anchored the same way password
	// hashes are (see redact.awsSecretKeyRe's doc comment), since the
	// value itself has no fixed prefix to detect on its own, unlike the
	// key ID it's always paired with. The actual authentication material
	// for an AWS credential pair, not just an identifier.
	EntityAWSSecretKey EntityType = "aws_secret_key"
	// EntityPEMKey tokens identify a whole PEM-armored private key block
	// (BEGIN...END), replaced wholesale with a fake PEM-shaped block;
	// there's no internal structure worth preserving, just enough shape
	// to remain visually recognizable as "a private key was here".
	EntityPEMKey EntityType = "pem_key"
	// EntityMAC tokens identify a colon-separated MAC address, replaced
	// with another locally-administered-range address (the "02" leading
	// octet, IEEE 802's bit for "not a real, globally-assigned OUI") so
	// it can never collide with or be mistaken for a real vendor OUI.
	EntityMAC EntityType = "mac"
	// EntityAadhaar tokens identify an Indian Aadhaar number (12 digits,
	// Verhoeff-checksum validated).
	EntityAadhaar EntityType = "aadhaar"
	// EntityPAN tokens identify an Indian PAN (Permanent Account Number,
	// 10-character alphanumeric with a constrained holder-type letter).
	EntityPAN EntityType = "pan"

	// The entity types below all identify a vendor-specific credential:
	// fully opaque, whole-secret tokens rather than structure-preserving
	// ones, since there's no substructure in any of these worth exposing
	// to Claude the way a domain suffix or IP network prefix is.
	EntityGitHubToken     EntityType = "github_token"
	EntityGitLabToken     EntityType = "gitlab_token"
	EntitySlackToken      EntityType = "slack_token"
	EntitySlackWebhook    EntityType = "slack_webhook"
	EntityStripeKey       EntityType = "stripe_key"
	EntityGoogleAPIKey    EntityType = "google_api_key"
	EntityNPMToken        EntityType = "npm_token"
	EntityConnString      EntityType = "conn_string"
	EntityTwilioSID       EntityType = "twilio_sid"
	EntitySendGridKey     EntityType = "sendgrid_key"
	EntityDigitalOcean    EntityType = "digitalocean_token"
	EntityCloudflare      EntityType = "cloudflare_token"
	EntityAzureStorageKey EntityType = "azure_storage_key"
	EntityArtifactory     EntityType = "artifactory_token"
	EntityDockerHub       EntityType = "dockerhub_token"
	EntityCircleCI        EntityType = "circleci_token"
	EntityTerraform       EntityType = "terraform_token"
	EntitySnyk            EntityType = "snyk_token"
	EntityBitbucket       EntityType = "bitbucket_password"
	EntityVault           EntityType = "vault_token"
	EntityOpenAI          EntityType = "openai_key"
	EntityAnthropicKey    EntityType = "anthropic_key"
	EntityRazorpay        EntityType = "razorpay_key"
	// EntityItsdangerousToken tokens identify a Flask itsdangerous-signed
	// token (payload.timestamp.signature, 3 dot-separated base64url
	// segments, same shape as a JWT but without the "eyJ" JSON-header
	// prefix, since itsdangerous's payload isn't JSON). Only claimed when
	// a nearby keyword (csrf_token=, session=, itsdangerous) provides
	// real evidence this is actually a signed token; see
	// redact.itsdangerousDetector for why a keyword-anchored gate was
	// chosen over broadening JWT-shape matching itself.
	EntityItsdangerousToken EntityType = "itsdangerous_token"
	// EntityPasswordHash tokens identify a bare cryptographic password
	// hash (MD5/NTLM/SHA-1/SHA-256, or an Impacket secretsdump-style
	// LM:NT pair): fully opaque, no structure preserved, same as a JWT
	// or PEM key. Deliberately narrow: a bare hex string this length is
	// exactly the shape of an ordinary git commit SHA (40 chars) or file
	// checksum, both of which appear constantly in unremarkable tool
	// output, so redact.hashDetector only claims one either via a
	// hash-type keyword nearby (ntlm, md5, sha1, sha256, "nt hash", ...)
	// or the secretsdump "LMHASH:NTHASH:::" triple-colon line shape,
	// never a bare hex string with no such context.
	EntityPasswordHash EntityType = "password_hash"
	// EntityCustomBlock tokens identify a value matched by a user-
	// supplied block-list entry (exact string or regex) rather than any
	// built-in detector, e.g. a customer name variant added via the
	// setup wizard, or a project codename an operator adds manually.
	// Fully opaque, same as any other secret-shaped entity: there's no
	// structure worth preserving since the value could be anything.
	EntityCustomBlock EntityType = "custom_block"
	// EntityADMachineAccount tokens identify a $-suffixed Active
	// Directory machine/computer account name (e.g. "WORKSTATION01$")
	// found in the same secretsdump.py/pwdump line shape as a password
	// hash pair; see redact.machineAccountSecretsdumpRe. Deliberately
	// scoped to ONLY $-suffixed names, never ordinary human usernames on
	// the same line: a trailing "$" is a hard, unambiguous AD naming
	// convention, while a bare username is prose-shaped free text (the
	// same deferred general-NER problem as any other name).
	EntityADMachineAccount EntityType = "ad_machine_account"
	// EntityGPPCPassword tokens identify a Group Policy Preferences
	// "cpassword" XML attribute value: a base64, AES-256-CBC
	// "encrypted" password that is, in practice, exactly as sensitive as
	// a plaintext password: Microsoft published the fixed AES key used
	// for every GPP cpassword value in MS14-025, so any real-world
	// GPP-password-cracking tool decrypts it directly with that same
	// published key. Fully opaque, same as any other secret-shaped
	// entity.
	EntityGPPCPassword EntityType = "gpp_cpassword"
)

var (
	bucketRealToToken = []byte("r2t")
	bucketTokenToReal = []byte("t2r")
	bucketMeta        = []byte("meta")
	bucketCounters    = []byte("counters")
	// bucketSpans persists the wire-span set spanTrie serves from memory
	// (see spans.go); without this, a proxy restart mid-engagement would
	// silently lose streaming-safety coverage for every credential minted
	// before the restart, since SafeFlushPoint would have no way to know
	// they exist until re-tokenized in a fresh request.
	bucketSpans = []byte("spans")
)

type entityMeta struct {
	EntityType EntityType `json:"entity_type"`
	FirstSeen  time.Time  `json:"first_seen"`
}

// Store is the bidirectional real<->token mapping. A Store owns its bbolt
// file exclusively (single-writer) and is safe for concurrent use from
// multiple goroutines within the owning process.
type Store struct {
	db *bolt.DB

	mu         sync.RWMutex
	real2token map[string]string
	token2real map[string]string

	// spanTrie backs RegisterSpan/SafeFlushPoint/AlreadyTokenizedSpans
	// (see spans.go) and carries its own lock, deliberately separate
	// from mu: span registration and the real/token maps are independent
	// concerns, and neither's methods call into the other's, so sharing
	// one lock would only add contention with no correctness benefit.
	// It is also the sole record of which spans are registered; there is
	// deliberately no membership set beside it, since a second structure
	// is a second thing to keep in sync (see RegisterSpan's doc comment).
	spanTrie *spanTrie
}

// Open opens (creating if necessary) the token store at path and loads its
// full contents into memory.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketRealToToken, bucketTokenToReal, bucketMeta, bucketCounters, bucketSpans} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("create bucket %s: %w", b, err)
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close() // returning the bucket-creation error
		return nil, err
	}

	s := &Store{
		db:         db,
		real2token: make(map[string]string),
		token2real: make(map[string]string),
		spanTrie:   newSpanTrie(),
	}

	if err := s.loadAll(); err != nil {
		_ = db.Close() // returning the load error
		return nil, err
	}

	return s, nil
}

// IsLockTimeout reports whether err is Open failing because another
// process already holds this same tokens.db open. bbolt allows only one
// writer at a time, so Open blocks for its configured Timeout (5s) then
// returns this specific error, distinct from every other way Open can
// fail (a corrupted/invalid file, a permission error, a bad path, ...).
// Callers use this to show "the proxy is already running for this
// engagement" only when that's actually the diagnosis; that hint is
// actively misleading for a genuinely corrupted tokens.db, which needs a
// completely different fix.
func IsLockTimeout(err error) bool {
	// bolterrors, not the bolt.ErrTimeout alias: bbolt deprecated the
	// top-level aliases in favour of its own errors package, and a
	// deprecated alias is exactly the kind of thing that gets removed in
	// a later major version, silently taking this check (and with it the
	// "another proxy is already running" diagnosis) with it.
	return errors.Is(err, bolterrors.ErrTimeout)
}

func (s *Store) loadAll() error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRealToToken)
		if err := b.ForEach(func(k, v []byte) error {
			real := string(k)
			token := string(v)
			s.real2token[real] = token
			s.token2real[token] = real
			return nil
		}); err != nil {
			return err
		}

		spans := tx.Bucket(bucketSpans)
		return spans.ForEach(func(k, _ []byte) error {
			s.spanTrie.insert(string(k))
			return nil
		})
	})
}

// Close closes the underlying database file.
func (s *Store) Close() error {
	return s.db.Close()
}

// LookupToken returns the existing token for a real value, if one has
// already been minted. It never creates one.
func (s *Store) LookupToken(real string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tok, ok := s.real2token[real]
	return tok, ok
}

// LookupReal returns the real value behind a token, if known. It never
// creates one; an unrecognized token is passed through unchanged by
// callers.
func (s *Store) LookupReal(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	real, ok := s.token2real[token]
	return real, ok
}

// GetOrCreateToken returns the token for real, minting and persisting a new
// one if this is the first time real has been seen. Safe for concurrent use.
func (s *Store) GetOrCreateToken(real string, et EntityType) (string, error) {
	if tok, ok := s.LookupToken(real); ok {
		return tok, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-check under the write lock: another goroutine may have created
	// this entry between our RUnlock above and this Lock.
	if tok, ok := s.real2token[real]; ok {
		return tok, nil
	}

	var token string
	err := s.db.Update(func(tx *bolt.Tx) error {
		var genErr error
		token, genErr = nextToken(tx, et, s.token2real)
		if genErr != nil {
			return genErr
		}

		meta := entityMeta{EntityType: et, FirstSeen: time.Now().UTC()}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return err
		}

		if err := tx.Bucket(bucketRealToToken).Put([]byte(real), []byte(token)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketTokenToReal).Put([]byte(token), []byte(real)); err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put([]byte(real), metaBytes)
	})
	if err != nil {
		return "", fmt.Errorf("create token for %s: %w", et, err)
	}

	s.real2token[real] = token
	s.token2real[token] = real
	return token, nil
}

// Entry describes one real<->token mapping and its metadata: the unit
// List returns and Delete removes, for admin/CLI-path inspection of an
// engagement's token store (see `redactproxy tokens show`/`remove`).
type Entry struct {
	Real       string
	Token      string
	EntityType EntityType
	FirstSeen  time.Time
}

// List returns every mapping currently in the store, oldest first. This
// is an admin/CLI-path operation, not part of the request hot path, and it
// reads directly from bbolt rather than the in-memory mirror, since
// FirstSeen (kept only in the meta bucket) is needed alongside the
// value and token.
func (s *Store) List() ([]Entry, error) {
	var entries []Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		r2t := tx.Bucket(bucketRealToToken)
		return meta.ForEach(func(k, v []byte) error {
			var m entityMeta
			if err := json.Unmarshal(v, &m); err != nil {
				return fmt.Errorf("decode meta for %q: %w", k, err)
			}
			entries = append(entries, Entry{
				Real:       string(k),
				Token:      string(r2t.Get(k)),
				EntityType: m.EntityType,
				FirstSeen:  m.FirstSeen,
			})
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("list entries: %w", err)
	}
	slices.SortStableFunc(entries, func(a, b Entry) int { return a.FirstSeen.Compare(b.FirstSeen) })
	return entries, nil
}

// Delete removes real's mapping entirely (from disk and the in-memory
// mirror) so a false-positive tokenization can be undone. Reports
// false if real had no mapping to remove. The next time the same real
// value is seen, GetOrCreateToken mints a FRESH token for it rather than
// reusing the deleted one, since a stale token left resolvable while
// everything that already saw the old one is out in the world would
// only cause confusion.
func (s *Store) Delete(real string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.real2token[real]
	if !ok {
		return false, nil
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketRealToToken).Delete([]byte(real)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketTokenToReal).Delete([]byte(token)); err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Delete([]byte(real))
	})
	if err != nil {
		return false, fmt.Errorf("delete %q: %w", real, err)
	}

	delete(s.real2token, real)
	delete(s.token2real, token)
	return true, nil
}

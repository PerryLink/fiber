package cache

import (
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/fieldname"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/fiber/v3/log"
)

// legacyKeyVersion is the key version before credential values were hashed in the key. Its
// entries are never read but still spell a credential out in an external Storage's keys until
// they expire; legacyPurge ends that for clients that return. Delete this file once none remain.
const legacyKeyVersion = "v4"

// maxLegacyProbes bounds the work purging adds; past it the rest is left to expire.
const maxLegacyProbes = 1024

// legacyPurge deletes what the previous key version stored for a request, found by keying it
// as that version did. A Storage cannot list its keys, so this reaches only the credentials
// that return; the rest expire on their own.
type legacyPurge struct {
	m       *manager
	current *Config // tells whether the request sends a credential the key holds
	cfg     Config  // keys as the previous version did, credential values spelled out
	probes  atomic.Int64
}

// newLegacyPurge returns nil when there is nothing to purge: an in-memory store does not
// outlive the process, a custom KeyGenerator's key never held the credential, and a key
// without a credential header or cookie spells none.
func newLegacyPurge(cfg *Config, m *manager) *legacyPurge {
	if cfg.Storage == nil || !cfg.usesDefaultKeyGenerator || (len(cfg.credentialKeyHeaders) == 0 && len(cfg.KeyCookies) == 0) {
		return nil
	}
	previous := *cfg
	previous.credentialKeyHeaders = nil
	previous.spellCookies = true
	return &legacyPurge{m: m, current: cfg, cfg: previous}
}

// purge deletes the entry, body, Vary manifest and variant the previous version stored for
// the request, if it sends a credential the key holds.
func (p *legacyPurge) purge(c fiber.Ctx, hasAuthorization bool) { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	if p == nil || p.probes.Load() >= maxLegacyProbes || !p.current.keyHoldsRequestCredential(c) {
		return
	}
	p.probes.Add(1)

	canonical := headerlookup.Canonical(c)
	bufPtr := acquireKeyBuffer()
	buf := (*bufPtr)[:0]
	buf = append(buf, legacyKeyVersion...)
	buf = append(buf, '|')
	buf = append(buf, c.Method()...)
	buf = append(buf, '|')
	buf = appendDefaultKey(buf, c, &p.cfg)
	if hasAuthorization {
		buf = append(buf, "|auth="...)
		buf = appendAuthHash(buf, fieldname.Lines(&c.Request().Header, fiber.HeaderAuthorization, canonical))
	}
	base := string(buf)
	releaseKeyBuffer(bufPtr, buf)

	keys := []string{base, base + "_body"}
	manifestKey := base + "|vary"
	ctx := c.Context()
	if names, found, err := loadVaryManifest(ctx, p.m, manifestKey); err == nil && found {
		variant := varyKey(base, names, &c.Request().Header, canonical)
		keys = append(keys, manifestKey, variant, variant+"_body")
	}
	for _, key := range keys {
		if err := p.m.del(ctx, key); err != nil {
			log.Warnf("cache: failed to purge an entry of the previous key version: %v", err)
		}
	}
}

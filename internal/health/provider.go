// Package health provides surveillance and fail-closed readiness enforcement for key providers
// and attributable audit pipelines (Requirement F17).
//
// Invariants:
//  1. No plaintext fallback exists during outage: when the key provider is unreachable,
//     sealed, or failing, requests fail closed immediately without returning cached plaintext.
//  2. Strict audited reveal policy: sensitive secret reveals must emit an attributable audit
//     event (secret.revealed.v1); if the audit subsystem fails, the reveal operation fails closed.
//  3. Secret bytes are owned exclusively by the provider; plaintext never enters health checks
//     or telemetry.
package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/provider"
)

// HealthState represents the operational status of an upstream provider.
type HealthState string

const (
	StatusHealthy  HealthState = "HEALTHY"
	StatusDegraded HealthState = "DEGRADED"
	StatusDown     HealthState = "DOWN"
	StatusSealed   HealthState = "SEALED"
)

// Typed health and outage error codes.
const (
	CodeAuditFailure        = "AUDIT_PIPELINE_FAILURE"
	CodeNoPlaintextFallback = "NO_PLAINTEXT_FALLBACK"
)

// Error is a typed health and outage error that never contains sensitive data.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}

func (e *Error) Unwrap() error {
	return e.Err
}

// ProviderStatus captures a point-in-time assessment of key provider and audit readiness.
type ProviderStatus struct {
	State       HealthState `json:"state"`
	ProviderID  string      `json:"provider_id"`
	Version     string      `json:"version,omitempty"`
	Sealed      bool        `json:"sealed"`
	AuditReady  bool        `json:"audit_ready"`
	CheckedAt   string      `json:"checked_at"`
	ErrorDetail string      `json:"error_detail,omitempty"`
}

// KeyProviderHealthChecker abstracts health inspection for key providers.
type KeyProviderHealthChecker interface {
	Health(ctx context.Context) (*provider.Health, error)
}

// AuditHealthChecker abstracts readiness checks for the audit pipeline.
type AuditHealthChecker interface {
	Record(ctx context.Context, envelope audit.EventEnvelope) error
}

// Monitor coordinates health surveillance and fail-closed policy enforcement.
type Monitor struct {
	mu           sync.RWMutex
	provider     KeyProviderHealthChecker
	auditChecker AuditHealthChecker
	lastStatus   ProviderStatus
}

// NewMonitor constructs a new health surveillance Monitor.
func NewMonitor(prov KeyProviderHealthChecker, auditChecker AuditHealthChecker) *Monitor {
	return &Monitor{
		provider:     prov,
		auditChecker: auditChecker,
		lastStatus: ProviderStatus{
			State:      StatusDown,
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
			AuditReady: auditChecker != nil,
		},
	}
}

// Check evaluates the current health of the key provider and audit pipeline.
func (m *Monitor) Check(ctx context.Context) (ProviderStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	status := ProviderStatus{
		State:      StatusHealthy,
		ProviderID: "openbao",
		CheckedAt:  now,
		AuditReady: m.auditChecker != nil,
	}

	if m.provider == nil {
		status.State = StatusDown
		status.ErrorDetail = "provider client is nil"
		m.lastStatus = status
		return status, &provider.Error{
			Code:    provider.CodeProviderUnavailable,
			Message: "key provider is not configured or unavailable",
		}
	}

	h, err := m.provider.Health(ctx)
	if err != nil {
		if provider.IsErrorCode(err, provider.CodeProviderSealed) {
			status.State = StatusSealed
			status.Sealed = true
			status.ErrorDetail = "provider is sealed"
			m.lastStatus = status
			return status, &provider.Error{
				Code:    provider.CodeProviderSealed,
				Message: "key provider is sealed; operations fail closed",
				Err:     err,
			}
		}

		status.State = StatusDown
		status.ErrorDetail = err.Error()
		m.lastStatus = status
		return status, &provider.Error{
			Code:    provider.CodeProviderUnavailable,
			Message: "key provider health check failed; operations fail closed",
			Err:     err,
		}
	}

	status.Version = h.Version
	status.Sealed = h.Sealed
	if h.Sealed {
		status.State = StatusSealed
		status.ErrorDetail = "provider is sealed"
		m.lastStatus = status
		return status, &provider.Error{
			Code:    provider.CodeProviderSealed,
			Message: "key provider is sealed; operations fail closed",
		}
	}

	if !status.AuditReady {
		status.State = StatusDegraded
		status.ErrorDetail = "audit pipeline is not available"
		m.lastStatus = status
		return status, &Error{
			Code:    CodeAuditFailure,
			Message: "audit pipeline is not ready; strict audit policy requires fail closed",
		}
	}

	m.lastStatus = status
	return status, nil
}

// LastStatus returns the most recently cached health status.
func (m *Monitor) LastStatus() ProviderStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastStatus
}

// EnforceOperational verifies provider readiness and asserts that operations fail closed immediately.
func (m *Monitor) EnforceOperational(ctx context.Context) error {
	_, err := m.Check(ctx)
	return err
}

// ExecuteStrictAuditedReveal executes a sensitive reveal action only if the attributable audit
// record is successfully generated and committed. If either the provider is in an outage or the
// audit pipeline fails, the reveal fails closed and no plaintext is returned.
func (m *Monitor) ExecuteStrictAuditedReveal(
	ctx context.Context,
	revealAction func() ([]byte, error),
	recordAudit func(outcome string) error,
) ([]byte, error) {
	// 1. Enforce that provider is healthy and not in an outage
	if err := m.EnforceOperational(ctx); err != nil {
		_ = recordAudit("provider_unavailable_fail_closed")
		return nil, &Error{
			Code:    CodeNoPlaintextFallback,
			Message: "provider outage: fail closed with zero cached plaintext fallback",
			Err:     err,
		}
	}

	// 2. Perform the transient decryption
	plaintext, err := revealAction()
	if err != nil {
		_ = recordAudit("reveal_failed")
		return nil, err
	}

	// 3. Strict Audit Policy: Commit the audit record. If auditing fails, zero plaintext and fail closed.
	if err := recordAudit("success"); err != nil {
		// Zero the sensitive buffer immediately
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, &Error{
			Code:    CodeAuditFailure,
			Message: "strict audited reveal policy violated: audit record emission failed; operation failed closed",
			Err:     err,
		}
	}

	return plaintext, nil
}

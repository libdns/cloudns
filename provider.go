package cloudns

import (
	"context"
	"fmt"
	"github.com/libdns/libdns"
	"strings"
	"time"
)

// ClouDNS API docs: https://www.cloudns.net/wiki/article/41/

// Default configuration values for DNS operations
const (
	// DefaultPropagationTimeout is the default timeout for DNS propagation verification
	DefaultPropagationTimeout = 5 * time.Minute

	// DefaultPropagationRetries is the default number of retries for DNS propagation verification
	DefaultPropagationRetries = 60

	// DefaultPropagationRetryInterval is the default interval between retries for DNS propagation verification
	DefaultPropagationRetryInterval = 5 * time.Second

	// DefaultOperationRetries is the default number of retries for DNS operations
	DefaultOperationRetries = 5

	// DefaultInitialBackoff is the default initial backoff duration for retries
	DefaultInitialBackoff = 1 * time.Second

	// DefaultMaxBackoff is the default maximum backoff duration for retries
	DefaultMaxBackoff = 30 * time.Second
)

// Provider facilitates DNS record manipulation with ClouDNS.
type Provider struct {
	AuthId                   string        `json:"auth_id"`
	SubAuthId                string        `json:"sub_auth_id,omitempty"`
	AuthPassword             string        `json:"auth_password"`
	PropagationTimeout       time.Duration `json:"propagation_timeout,omitempty"`
	PropagationRetries       int           `json:"propagation_retries,omitempty"`
	PropagationRetryInterval time.Duration `json:"propagation_retry_interval,omitempty"`
	OperationRetries         int           `json:"operation_retries,omitempty"`
	InitialBackoff           time.Duration `json:"initial_backoff,omitempty"`
	MaxBackoff               time.Duration `json:"max_backoff,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if strings.HasSuffix(zone, ".") {
		zone = strings.TrimSuffix(zone, ".")
	}

	// Use retry mechanism for the GetRecords operation
	var records []libdns.Record
	err := RetryWithBackoff(ctx, func() error {
		var err error
		records, err = UseClient(p.AuthId, p.SubAuthId, p.AuthPassword).GetRecords(ctx, zone)
		return err
	}, p.getOperationRetries(), p.getInitialBackoff(), p.getMaxBackoff())

	if err != nil {
		return nil, fmt.Errorf("failed to get records after retries: %w", err)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
// It also verifies that the records have properly propagated to DNS servers.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if strings.HasSuffix(zone, ".") {
		zone = strings.TrimSuffix(zone, ".")
	}

	var createdRecords []libdns.Record
	for _, record := range records {
		// Use retry mechanism for the AddRecord operation
		var r *libdns.Record
		err := RetryWithBackoff(ctx, func() error {
			var err error
			r, err = UseClient(p.AuthId, p.SubAuthId, p.AuthPassword).AddRecord(ctx, zone, record.Type, record.Name, record.Value, record.TTL)
			return err
		}, p.getOperationRetries(), p.getInitialBackoff(), p.getMaxBackoff())

		if err != nil {
			return nil, fmt.Errorf("failed to add record after retries: %w", err)
		}

		createdRecords = append(createdRecords, *r)

		// For TXT records (commonly used for ACME challenges), verify DNS propagation
		if record.Type == "TXT" {
			// Create a context with timeout for propagation verification
			propagationCtx, cancel := context.WithTimeout(ctx, p.getPropagationTimeout())
			defer cancel()

			// Construct the FQDN for the record
			fqdn := record.Name
			if fqdn != "" && fqdn != "@" {
				fqdn = fqdn + "." + zone
			} else {
				fqdn = zone
			}

			// Verify that the record has propagated
			err = VerifyDNSPropagation(
				propagationCtx,
				fqdn,
				record.Type,
				record.Value,
				p.getPropagationRetries(),
				p.getPropagationRetryInterval(),
			)

			if err != nil {
				return nil, fmt.Errorf("DNS propagation verification failed for %s: %w", fqdn, err)
			}
		}
	}

	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records and verifies that the records have properly propagated to DNS servers.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if strings.HasSuffix(zone, ".") {
		zone = strings.TrimSuffix(zone, ".")
	}

	var updatedRecords []libdns.Record
	for _, record := range records {
		var r *libdns.Record
		var err error

		if len(record.ID) == 0 {
			// Create new record with retry mechanism
			err = RetryWithBackoff(ctx, func() error {
				var opErr error
				r, opErr = UseClient(p.AuthId, p.SubAuthId, p.AuthPassword).AddRecord(ctx, zone, record.Type, record.Name, record.Value, record.TTL)
				return opErr
			}, p.getOperationRetries(), p.getInitialBackoff(), p.getMaxBackoff())

			if err != nil {
				return nil, fmt.Errorf("failed to add record after retries: %w", err)
			}
		} else {
			// Update existing record with retry mechanism
			err = RetryWithBackoff(ctx, func() error {
				var opErr error
				r, opErr = UseClient(p.AuthId, p.SubAuthId, p.AuthPassword).UpdateRecord(ctx, zone, record.ID, record.Name, record.Value, record.TTL)
				return opErr
			}, p.getOperationRetries(), p.getInitialBackoff(), p.getMaxBackoff())

			if err != nil {
				return nil, fmt.Errorf("failed to update record after retries: %w", err)
			}
		}

		updatedRecords = append(updatedRecords, *r)

		// For TXT records (commonly used for ACME challenges), verify DNS propagation
		if record.Type == "TXT" {
			// Create a context with timeout for propagation verification
			propagationCtx, cancel := context.WithTimeout(ctx, p.getPropagationTimeout())
			defer cancel()

			// Construct the FQDN for the record
			fqdn := record.Name
			if fqdn != "" && fqdn != "@" {
				fqdn = fqdn + "." + zone
			} else {
				fqdn = zone
			}

			// Verify that the record has propagated
			err = VerifyDNSPropagation(
				propagationCtx,
				fqdn,
				record.Type,
				record.Value,
				p.getPropagationRetries(),
				p.getPropagationRetryInterval(),
			)

			if err != nil {
				return nil, fmt.Errorf("DNS propagation verification failed for %s: %w", fqdn, err)
			}
		}
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if strings.HasSuffix(zone, ".") {
		zone = strings.TrimSuffix(zone, ".")
	}

	var deletedRecords []libdns.Record
	for _, record := range records {
		// Use retry mechanism for the DeleteRecord operation
		var r *libdns.Record
		err := RetryWithBackoff(ctx, func() error {
			var err error
			r, err = UseClient(p.AuthId, p.SubAuthId, p.AuthPassword).DeleteRecord(ctx, zone, record.ID)
			return err
		}, p.getOperationRetries(), p.getInitialBackoff(), p.getMaxBackoff())

		if err != nil {
			return nil, fmt.Errorf("failed to delete record after retries: %w", err)
		}

		if r != nil {
			deletedRecords = append(deletedRecords, *r)
		}
	}

	return deletedRecords, nil
}

// Helper methods to get configuration values with defaults

// getPropagationTimeout returns the configured propagation timeout or the default value
func (p *Provider) getPropagationTimeout() time.Duration {
	if p.PropagationTimeout <= 0 {
		return DefaultPropagationTimeout
	}
	return p.PropagationTimeout
}

// getPropagationRetries returns the configured propagation retries or the default value
func (p *Provider) getPropagationRetries() int {
	if p.PropagationRetries <= 0 {
		return DefaultPropagationRetries
	}
	return p.PropagationRetries
}

// getPropagationRetryInterval returns the configured propagation retry interval or the default value
func (p *Provider) getPropagationRetryInterval() time.Duration {
	if p.PropagationRetryInterval <= 0 {
		return DefaultPropagationRetryInterval
	}
	return p.PropagationRetryInterval
}

// getOperationRetries returns the configured operation retries or the default value
func (p *Provider) getOperationRetries() int {
	if p.OperationRetries <= 0 {
		return DefaultOperationRetries
	}
	return p.OperationRetries
}

// getInitialBackoff returns the configured initial backoff or the default value
func (p *Provider) getInitialBackoff() time.Duration {
	if p.InitialBackoff <= 0 {
		return DefaultInitialBackoff
	}
	return p.InitialBackoff
}

// getMaxBackoff returns the configured max backoff or the default value
func (p *Provider) getMaxBackoff() time.Duration {
	if p.MaxBackoff <= 0 {
		return DefaultMaxBackoff
	}
	return p.MaxBackoff
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

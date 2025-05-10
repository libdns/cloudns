package cloudns

import (
	"context"
	"iter"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var (
	TAuthId       = ""
	TSubAuthId    = ""
	TAuthPassword = ""
	TZone         = ""
)

func zip[T any, U any](first iter.Seq[T], second iter.Seq[U]) iter.Seq2[T, U] {
	return func(yield func(T, U) bool) {
		firstIter, firstStop := iter.Pull(first)
		defer firstStop()
		secondIter, secondStop := iter.Pull(second)
		defer secondStop()

		for {
			f, fok := firstIter()
			s, sok := secondIter()

			if !fok && !sok {
				return
			}

			if (!fok && sok) || (fok && !sok) {
				panic("uneven iterators")
			}

			if !yield(f, s) {
				return
			}
		}
	}
}

func TestGetRecords(t *testing.T) {
	provider := &Provider{
		AuthId:       TAuthId,
		SubAuthId:    TSubAuthId,
		AuthPassword: TAuthPassword,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	records, err := provider.GetRecords(ctx, TZone)
	if err != nil {
		t.Fatalf("Failed to get records: %s", err)
	}

	if len(records) == 0 {
		t.Fatalf("Expected at least one record")
	}

	for _, record := range records {
		if record.RR().Type == "" || record.RR().Data == "" {
			t.Errorf("Incomplete record data: %+v", record)
		}
		t.Logf("Record: %+v", record)
	}
}

func TestAppendRecords(t *testing.T) {
	provider := &Provider{
		AuthId:       TAuthId,
		SubAuthId:    TSubAuthId,
		AuthPassword: TAuthPassword,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// Prepare a record to append
	records := []libdns.Record{
		libdns.Address{
			Name: "test",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("127.0.0.1"),
		},
		libdns.Address{
			Name: "test",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("::1"),
		},
		libdns.CAA{
			Name:  "test",
			TTL:   300 * time.Second,
			Flags: 0,
			Tag:   "issue",
			Value: "bar",
		},
		libdns.CNAME{
			Name:   "test-cname",
			TTL:    300 * time.Second,
			Target: "example.com",
		},
		libdns.MX{
			Name:       "test-mx",
			TTL:        300 * time.Second,
			Preference: 1,
			Target:     "example.com",
		},
		libdns.NS{
			Name:   "test-ns",
			TTL:    300 * time.Second,
			Target: "example.com",
		},
		libdns.SRV{
			Service:   "http",
			Transport: "tcp",
			Name:      "test",
			TTL:       300 * time.Second,
			Priority:  1,
			Weight:    1,
			Port:      1,
			Target:    "example.com",
		},
		libdns.TXT{
			Name: "test",
			TTL:  300 * time.Second,
			Text: "test-value",
		},
	}

	// Append the record
	addedRecords, err := provider.AppendRecords(ctx, TZone, records)
	if err != nil {
		t.Fatalf("Failed to append records: %s", err)
	}

	if len(addedRecords) != len(records) {
		t.Fatalf("Expected %d record to be added, got %d", len(records), len(addedRecords))
	}

	// Validate the added record
	for addedRecord, record := range zip(slices.Values(addedRecords), slices.Values(records)) {
		if !reflect.DeepEqual(record.RR(), addedRecord.RR()) {
			t.Errorf("Record data mismatch: expected %+v, got %+v", record, addedRecord)
		}
	}

	// Clean up the added record
	_, err = provider.DeleteRecords(ctx, TZone, addedRecords)
	if err != nil {
		t.Errorf("Failed to clean up added record: %s", err)
	}
}

func TestSetRecords(t *testing.T) {
	provider := &Provider{
		AuthId:       TAuthId,
		SubAuthId:    TSubAuthId,
		AuthPassword: TAuthPassword,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// Prepare a record to set
	record := libdns.TXT{
		Name: "test-set",
		Text: "test-value",
		TTL:  300 * time.Second,
	}

	// Append the record to set
	addedRecords, err := provider.AppendRecords(ctx, TZone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("Failed to append records: %s", err)
	}

	// Set the record
	updatedValue := "updated-value"
	updatedRecord, ok := addedRecords[0].(libdns.TXT)
	if !ok {
		t.Fatalf("Return value is not a TXT record: %v", addedRecords[0])
	}

	updatedRecord.Text = updatedValue

	setRecords, err := provider.SetRecords(ctx, TZone, []libdns.Record{updatedRecord})
	if err != nil {
		t.Fatalf("Failed to set records: %s", err)
	}

	if len(setRecords) != 1 {
		t.Fatalf("Expected 1 record to be set, got %d", len(setRecords))
	}

	// Validate the updated record
	setRecord := setRecords[0]
	if !reflect.DeepEqual(setRecord.RR(), updatedRecord.RR()) {
		t.Errorf("Record data mismatch: expected %+v, got %+v", updatedRecord, setRecord)
	}

	// Clean up the added record
	_, err = provider.DeleteRecords(ctx, TZone, addedRecords)
	if err != nil {
		t.Errorf("Failed to clean up added record: %s", err)
	}
}

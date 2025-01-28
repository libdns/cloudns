package cloudns

import (
	"context"
	"github.com/libdns/libdns"
	"testing"
	"time"
)

var (
	TAuthId       = ""
	TSubAuthId    = ""
	TAuthPassword = ""
	TZone         = ""
)

func TestGetRecords(t *testing.T) {
	provider := &Provider{
		AuthId:       TAuthId,
		SubAuthId:    TSubAuthId,
		AuthPassword: TAuthPassword,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	records, err := provider.GetRecords(ctx, TZone)
	if err != nil {
		t.Fatalf("Failed to get records: %s", err)
	}

	if len(records) == 0 {
		t.Fatalf("Expected at least one record")
	}

	for _, record := range records {
		if record.ID == "" || record.Type == "" || record.Value == "" {
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Prepare a record to append
	record := libdns.Record{
		Type:  "TXT",
		Name:  "test",
		Value: "test-value",
		TTL:   300 * time.Second,
	}

	// Append the record
	addedRecords, err := provider.AppendRecords(ctx, TZone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("Failed to append records: %s", err)
	}

	if len(addedRecords) != 1 {
		t.Fatalf("Expected 1 record to be added, got %d", len(addedRecords))
	}

	// Validate the added record
	addedRecord := addedRecords[0]
	if addedRecord.Type != record.Type || addedRecord.Name != record.Name || addedRecord.Value != record.Value || addedRecord.TTL != record.TTL {
		t.Errorf("Record data mismatch: expected %+v, got %+v", record, addedRecord)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Prepare a record to set
	record := libdns.Record{
		Type:  "TXT",
		Name:  "test-set",
		Value: "test-value",
		TTL:   300 * time.Second,
	}

	// Append the record to set
	addedRecords, err := provider.AppendRecords(ctx, TZone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("Failed to append records: %s", err)
	}

	// Set the record
	updatedValue := "updated-value"
	updatedRecord := addedRecords[0]
	updatedRecord.Value = updatedValue

	setRecords, err := provider.SetRecords(ctx, TZone, []libdns.Record{updatedRecord})
	if err != nil {
		t.Fatalf("Failed to set records: %s", err)
	}

	if len(setRecords) != 1 {
		t.Fatalf("Expected 1 record to be set, got %d", len(setRecords))
	}

	// Validate the updated record
	setRecord := setRecords[0]
	if setRecord.Type != updatedRecord.Type || setRecord.Name != updatedRecord.Name || setRecord.Value != updatedRecord.Value || setRecord.TTL != updatedRecord.TTL {
		t.Errorf("Record data mismatch: expected %+v, got %+v", updatedRecord, setRecord)
	}

	// Clean up the added record
	_, err = provider.DeleteRecords(ctx, TZone, addedRecords)
	if err != nil {
		t.Errorf("Failed to clean up added record: %s", err)
	}
}

package cloudns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libdns/libdns"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Client struct {
	AuthId       string `json:"auth_id"`
	SubAuthId    string `json:"sub_auth_id"`
	AuthPassword string `json:"auth_password"`
}

var apiBaseUrl, _ = url.Parse("https://api.cloudns.net/dns/")

// UseClient initializes and returns a new Client instance with provided authentication details.
func UseClient(authId, subAuthId, authPassword string) *Client {
	return &Client{
		AuthId:       authId,
		SubAuthId:    subAuthId,
		AuthPassword: authPassword,
	}
}

// GetRecords retrieves all DNS records for the specified zone.
// It handles API communication, response parsing, and error handling.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - zone: The DNS zone (domain) to retrieve records from
//
// Returns:
//   - []libdns.Record: Slice of all DNS records in the zone
//   - error: Any error that occurred during the operation
func (c *Client) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	// Log the operation for debugging
	fmt.Printf("Getting all records from zone %s\n", zone)

	// Prepare the API endpoint and parameters
	recordsEndpoint := apiBaseUrl.JoinPath("records.json")
	params := map[string]string{
		"domain-name": zone,
	}

	// Perform the API request
	resp, err := c.performGetRequest(ctx, recordsEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned non-OK status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the API response
	var apiResult map[string]ApiDnsRecord
	if err := json.NewDecoder(resp.Body).Decode(&apiResult); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	// Convert API records to libdns.Record format
	records := make([]libdns.Record, 0, len(apiResult))
	for _, recordData := range apiResult {
		records = append(records, libdns.Record{
			ID:    recordData.Id,
			Type:  recordData.Type,
			Name:  recordData.Host,
			TTL:   parseDuration(recordData.Ttl + "s"),
			Value: recordData.Record,
		})
	}

	// Log the number of records found
	fmt.Printf("Found %d records in zone %s\n", len(records), zone)

	return records, nil
}

// GetRecord retrieves a specific DNS record by its ID from the specified zone.
// It first gets all records in the zone and then finds the one with the matching ID.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - zone: The DNS zone (domain) containing the record
//   - recordID: ID of the record to retrieve
//
// Returns:
//   - *libdns.Record: The matching record if found
//   - error: "record not found" error if no matching record exists, or any other error that occurred
func (c *Client) GetRecord(ctx context.Context, zone, recordID string) (*libdns.Record, error) {
	// Log the operation for debugging
	fmt.Printf("Getting record ID %s from zone %s\n", recordID, zone)

	// Get all records in the zone
	records, err := c.GetRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get records from zone %s: %w", zone, err)
	}

	// Find the record with the matching ID
	for _, record := range records {
		if record.ID == recordID {
			return &record, nil
		}
	}

	// No matching record found
	return nil, errors.New("record not found")
}

// AddRecord creates a new DNS record in the specified zone with the given properties and returns the created record or an error.
// It handles API communication, response parsing, and error handling.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - zone: The DNS zone (domain) to add the record to
//   - recordType: Type of DNS record (e.g., "TXT", "A", "CNAME")
//   - recordHost: Host part of the record (subdomain or @ for root)
//   - recordValue: Value of the record (e.g., IP address for A records, domain for CNAME)
//   - ttl: Time-to-live duration for the record
//
// Returns:
//   - *libdns.Record: The created record with its assigned ID
//   - error: Any error that occurred during the operation
func (c *Client) AddRecord(ctx context.Context, zone string, recordType string, recordHost string, recordValue string, ttl time.Duration) (*libdns.Record, error) {
	endpoint := apiBaseUrl.JoinPath("add-record.json")

	// Round TTL to an accepted value
	roundedTTL := ttlRounder(ttl)
	roundedTTLStr := strconv.Itoa(roundedTTL)

	// Prepare request parameters
	params := map[string]string{
		"domain-name": zone,
		"record-type": recordType,
		"host":        recordHost,
		"record":      recordValue,
		"ttl":         roundedTTLStr,
	}

	// Log the operation for debugging
	fmt.Printf("Adding %s record: %s.%s with value %s and TTL %s\n",
		recordType, recordHost, zone, recordValue, roundedTTLStr)

	// Perform the API request
	resp, err := c.performPostRequest(ctx, endpoint, params)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned non-OK status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the API response
	var resultModel ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&resultModel); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	// Check if the operation was successful
	if resultModel.Status != "Success" {
		return nil, fmt.Errorf("API operation failed: %s", resultModel.StatusDescription)
	}

	// Convert TTL string to duration
	parsedTTL := parseDuration(roundedTTLStr + "s")

	// Create and return the record
	return &libdns.Record{
		ID:    strconv.Itoa(resultModel.Data.Id),
		Type:  recordType,
		Name:  recordHost,
		TTL:   parsedTTL,
		Value: recordValue,
	}, nil
}

// UpdateRecord updates an existing DNS record in the specified zone with the provided values and returns the updated record.
// It handles API communication, response parsing, and error handling.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - zone: The DNS zone (domain) containing the record
//   - recordID: ID of the record to update
//   - host: New host part of the record (subdomain or @ for root)
//   - recordValue: New value for the record
//   - ttl: New time-to-live duration for the record
//
// Returns:
//   - *libdns.Record: The updated record
//   - error: Any error that occurred during the operation
func (c *Client) UpdateRecord(ctx context.Context, zone string, recordID string, host string, recordValue string, ttl time.Duration) (*libdns.Record, error) {
	updateEndpoint := apiBaseUrl.JoinPath("mod-record.json")

	// Round TTL to an accepted value
	ttlSec := ttlRounder(ttl)
	ttlSecStr := strconv.Itoa(ttlSec)

	// Prepare request parameters
	params := map[string]string{
		"domain-name": zone,
		"record-id":   recordID,
		"host":        host,
		"record":      recordValue,
		"ttl":         ttlSecStr,
	}

	// Log the operation for debugging
	fmt.Printf("Updating record ID %s in zone %s: host=%s, value=%s, TTL=%s\n",
		recordID, zone, host, recordValue, ttlSecStr)

	// Perform the API request
	resp, err := c.performPostRequest(ctx, updateEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned non-OK status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the API response
	var resultModel ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&resultModel); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	// Check if the operation was successful
	if resultModel.Status != "Success" {
		return nil, fmt.Errorf("API operation failed: %s", resultModel.StatusDescription)
	}

	// Get the existing record to retrieve its type
	existingRecord, err := c.GetRecord(ctx, zone, recordID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing record details: %w", err)
	}

	// Create and return the updated record
	return &libdns.Record{
		ID:    recordID,
		Type:  existingRecord.Type,
		Name:  host,
		TTL:   parseDuration(ttlSecStr + "s"),
		Value: recordValue,
	}, nil
}

// DeleteRecord deletes a DNS record identified by its ID in the specified zone.
// It first retrieves the record details to return them after deletion, then performs the delete operation.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - zone: The DNS zone (domain) containing the record
//   - recordId: ID of the record to delete
//
// Returns:
//   - *libdns.Record: The deleted record, or nil if the record was not found
//   - error: Any error that occurred during the operation
func (c *Client) DeleteRecord(ctx context.Context, zone string, recordId string) (*libdns.Record, error) {
	// First get the record details so we can return them after deletion
	rInfo, err := c.GetRecord(ctx, zone, recordId)
	if err != nil {
		if err.Error() == "record not found" {
			// Record doesn't exist, nothing to delete
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get record details before deletion: %w", err)
	}

	// Log the operation for debugging
	fmt.Printf("Deleting record ID %s from zone %s\n", recordId, zone)

	// Prepare the API endpoint and parameters
	endpoint := apiBaseUrl.JoinPath("delete-record.json")
	params := map[string]string{
		"domain-name": zone,
		"record-id":   recordId,
	}

	// Perform the API request
	resp, err := c.performPostRequest(ctx, endpoint, params)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned non-OK status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the API response
	var resultModel ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&resultModel); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	// Check if the operation was successful
	if resultModel.Status != "Success" {
		return nil, fmt.Errorf("API operation failed: %s", resultModel.StatusDescription)
	}

	// Return the deleted record information
	return rInfo, nil
}

// performPostRequest sends a POST request to the specified URL with query parameters and returns the HTTP response or an error.
// It adds authentication parameters and builds the request with the provided context.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - targetURL: The API endpoint URL
//   - params: Map of query parameters to include in the request
//
// Returns:
//   - *http.Response: The HTTP response from the API
//   - error: Any error that occurred during the request
func (c *Client) performPostRequest(ctx context.Context, targetURL *url.URL, params map[string]string) (*http.Response, error) {
	// Create a copy of the URL to avoid modifying the original
	requestURL := *targetURL

	// Get query parameters and add authentication
	queries := requestURL.Query()
	c.addAuthParams(queries)

	// Add all provided parameters to the query
	for k, v := range params {
		queries.Set(k, v)
	}

	// Encode the query parameters and set them on the URL
	requestURL.RawQuery = queries.Encode()

	// Create a new HTTP request with the provided context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set appropriate headers
	req.Header.Set("User-Agent", "cloudns-go-client/1.0")
	req.Header.Set("Accept", "application/json")

	// Execute the request
	return http.DefaultClient.Do(req)
}

// addAuthParams adds authentication parameters to the provided query values based on the client's credentials.
// It selects between auth-id and sub-auth-id based on which is provided.
//
// Parameters:
//   - queries: The url.Values to add authentication parameters to
func (c *Client) addAuthParams(queries url.Values) {
	// CloudNS API requires either auth-id or sub-auth-id, but not both
	if c.SubAuthId != "" {
		queries.Set("sub-auth-id", c.SubAuthId)
	} else {
		queries.Set("auth-id", c.AuthId)
	}

	// Always include the auth password
	queries.Set("auth-password", c.AuthPassword)
}

// performGetRequest sends a GET request to the specified URL with query parameters and returns the HTTP response or an error.
// It adds authentication parameters and builds the request with the provided context.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - targetURL: The API endpoint URL
//   - params: Map of query parameters to include in the request
//
// Returns:
//   - *http.Response: The HTTP response from the API
//   - error: Any error that occurred during the request
func (c *Client) performGetRequest(ctx context.Context, targetURL *url.URL, params map[string]string) (*http.Response, error) {
	// Create a copy of the URL to avoid modifying the original
	requestURL := *targetURL

	// Get query parameters and add authentication
	queries := requestURL.Query()
	c.addAuthParams(queries)

	// Add all provided parameters to the query
	for k, v := range params {
		queries.Set(k, v)
	}

	// Encode the query parameters and set them on the URL
	requestURL.RawQuery = queries.Encode()

	// Create a new HTTP request with the provided context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set appropriate headers
	req.Header.Set("User-Agent", "cloudns-go-client/1.0")
	req.Header.Set("Accept", "application/json")

	// Execute the request
	return http.DefaultClient.Do(req)
}

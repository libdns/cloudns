package cloudns

import (
	"errors"
	"testing"
)

var records = []ApiDnsRecord{
	{
		Id:     "1",
		Ttl:    "60",
		Type:   "A",
		Host:   "example.com",
		Record: "127.0.0.1",
	},
	{
		Id:     "2",
		Ttl:    "60",
		Type:   "AAAA",
		Host:   "example.com",
		Record: "::1",
	},
	{
		Id:       "3",
		Ttl:      "60",
		Type:     "CAA",
		Host:     "example.com",
		CAAFlag:  0,
		CAAType:  "issue",
		CAAValue: "bar",
	},
	{
		Id:     "4",
		Ttl:    "60",
		Type:   "CNAME",
		Host:   "example.com",
		Record: "other.example.com",
	},
	{
		Id:       "5",
		Ttl:      "60",
		Type:     "MX",
		Host:     "example.com",
		Priority: 1,
		Record:   "other.example.com",
	},
	{
		Id:     "6",
		Ttl:    "60",
		Type:   "NS",
		Host:   "example.com",
		Record: "other.example.com",
	},
	{
		Id:       "7",
		Ttl:      "60",
		Type:     "SRV",
		Host:     "_http._tcp.foo.example.com",
		Priority: 1,
		Weight:   5,
		Port:     80,
		Record:   "other.example.com",
	},
	{
		Id:     "8",
		Ttl:    "60",
		Type:   "SSHFP",
		Host:   "ssh.example.com",
		Record: "4 1 834B398AFD6CBFD93D06F26D2E23E0BAF6576A9D",
	},
}

func TestRoundTrip(t *testing.T) {
	for _, rec := range records {
		id := rec.Id
		libdnsrec, err := rec.toLibdnsRecord()
		if err != nil {
			t.Errorf("Error converting record %+v to libdns record: %v", rec, err)
		}

		newrec := fromLibdnsRecord(libdnsrec, id)
		if newrec != rec {
			t.Errorf("Expected newrec == rec: %+v == %+v", newrec, rec)
		}
	}
}

var invalidRecords = map[ApiDnsRecord]error{
	{
		Type: "SRV",
		Ttl:  "60",
		Host: "_http._tcp",
	}: errors.New("Name \"_http._tcp\" does not have enough components (expected >3, got 2)"),
	{
		Ttl: "foo",
	}: errors.New("Invalid TTL \"foo\""),
	{
		Type:   "AAAA",
		Ttl:    "60",
		Record: "foo",
	}: errors.New("Invalid IP \"foo\": ParseAddr(\"foo\"): unable to parse IP"),
}

func TestBadConversions(t *testing.T) {
	for rec, expectedErr := range invalidRecords {
		libdns, err := rec.toLibdnsRecord()
		if err == nil {
			t.Errorf("Expected err not to be nil, got record: %+v", libdns)
		}

		if err.Error() != expectedErr.Error() {
			t.Errorf("Expected err == expectedErr: %+v == %+v", err, expectedErr)
		}
	}
}

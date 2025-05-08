package cloudns

import (
	"reflect"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

type makeOperationListIn struct {
	desired  map[nameAndType][]libdns.RR
	existing map[nameAndType][]ApiDnsRecord
}

var makeOperationListTests = []struct {
	name string
	in   makeOperationListIn
	out  []operationEntry
}{
	{
		name: "no operations",
		in:   makeOperationListIn{},
		out:  []operationEntry{},
	},
	{
		name: "remove rrset entry",
		in: makeOperationListIn{
			desired: map[nameAndType][]libdns.RR{
				{name: "example.com", type_: "A"}: {
					{
						Name: "example.com",
						TTL:  time.Duration(60) * time.Second,
						Data: "192.0.2.3",
						Type: "A",
					},
				},
			},
			existing: map[nameAndType][]ApiDnsRecord{
				{name: "example.com", type_: "A"}: {
					{
						Id:     "1",
						Host:   "example.com",
						Type:   "A",
						Record: "192.0.2.1",
						Ttl:    "60",
					},
					{
						Id:     "2",
						Host:   "example.com",
						Type:   "A",
						Record: "192.0.2.2",
						Ttl:    "60",
					},
				},
			},
		},
		out: []operationEntry{
			{
				op: deleteRecord,
				record: ApiDnsRecord{
					Id:     "2",
					Host:   "example.com",
					Type:   "A",
					Record: "192.0.2.2",
					Ttl:    "60",
				},
			},
			{
				op: modifyRecord,
				record: ApiDnsRecord{
					Id:     "1",
					Host:   "example.com",
					Type:   "A",
					Record: "192.0.2.3",
					Ttl:    "60",
				},
			},
		},
	},
	{
		name: "only touch one rrset",
		in: makeOperationListIn{
			desired: map[nameAndType][]libdns.RR{
				{name: "a.example.com", type_: "AAAA"}: {
					libdns.RR{
						Name: "a.example.com",
						TTL:  time.Duration(60) * time.Second,
						Type: "AAAA",
						Data: "2001:db8::1",
					},
					libdns.RR{
						Name: "a.example.com",
						TTL:  time.Duration(60) * time.Second,
						Type: "AAAA",
						Data: "2001:db8::2",
					},
					libdns.RR{
						Name: "a.example.com",
						TTL:  time.Duration(60) * time.Second,
						Type: "AAAA",
						Data: "2001:db8::5",
					},
				},
			},
			existing: map[nameAndType][]ApiDnsRecord{
				{name: "a.example.com", type_: "AAAA"}: {
					ApiDnsRecord{
						Id:     "1",
						Host:   "a.example.com",
						Type:   "AAAA",
						Record: "2001:db8::1",
						Ttl:    "60",
					},
					ApiDnsRecord{
						Id:     "2",
						Host:   "a.example.com",
						Type:   "AAAA",
						Record: "2001:db8::2",
						Ttl:    "60",
					},
				},
				{name: "b.example.com", type_: "AAAA"}: {
					ApiDnsRecord{
						Id:     "3",
						Host:   "b.example.com",
						Type:   "AAAA",
						Record: "2001:db8::3",
						Ttl:    "60",
					},
					ApiDnsRecord{
						Id:     "4",
						Host:   "b.example.com",
						Type:   "AAAA",
						Record: "2001:db8::4",
						Ttl:    "60",
					},
				},
			},
		},
		out: []operationEntry{
			{
				op: addRecord,
				record: ApiDnsRecord{
					Id:     "",
					Host:   "a.example.com",
					Type:   "AAAA",
					Record: "2001:db8::5",
					Ttl:    "60",
				},
			},
		},
	},
	{
		name: "add rrset",
		in: makeOperationListIn{
			desired: map[nameAndType][]libdns.RR{
				{name: "foo.example.com", type_: "A"}: {
					{
						Name: "foo.example.com",
						TTL:  time.Duration(60) * time.Second,
						Data: "192.0.2.3",
						Type: "A",
					},
				},
			},
			existing: map[nameAndType][]ApiDnsRecord{
				{name: "example.com", type_: "A"}: {
					{
						Id:     "1",
						Host:   "example.com",
						Type:   "A",
						Record: "192.0.2.1",
						Ttl:    "60",
					},
					{
						Id:     "2",
						Host:   "example.com",
						Type:   "A",
						Record: "192.0.2.2",
						Ttl:    "60",
					},
				},
			},
		},
		out: []operationEntry{
			{
				op: addRecord,
				record: ApiDnsRecord{
					Host:   "foo.example.com",
					Type:   "A",
					Record: "192.0.2.3",
					Ttl:    "60",
				},
			},
		},
	},
}

func TestMakeOperationList(t *testing.T) {
	for _, tt := range makeOperationListTests {
		t.Run(tt.name, func(t *testing.T) {
			out := makeOperationList(tt.in.desired, tt.in.existing)
			if !reflect.DeepEqual(out, tt.out) {
				t.Errorf("actual: %+v\n\nexpected: %+v", out, tt.out)
			}
		})
	}
}

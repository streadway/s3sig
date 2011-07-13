package s3sig

import (
	"testing"
	"http"
	"strings"
)

type sig struct {
	name, method, url, key, secret, expected string
}

var v1sigs = []sig{
	sig{"http",
			"GET",
			"http://s3.amazonaws.com/bucket/path/resource",
			"a",
			"b",
			"blah",
	},
	sig{"https",
			"GET",
			"https://s3.amazonaws.com/bucket/path/resource",
			"a", "b",
			"blah",
	},
	sig{"host",
			"GET",
			"https://bucket.s3.amazonaws.com/path/resource",
			"a", "b",
			"blah",
	},
	sig{"torrent",
			"GET",
			"https://bucket.s3.amazonaws.com/path/resource?torrent",
			"a", "b",
			"blah",
	},
	sig{"custom query",
			"GET",
			"https://bucket.s3.amazonaws.com/path/resource?why=you&no&%20jelly%20",
			"a", "b",
			"blah",
	},
	sig{"encoded query",
			"GET",
			"https://bucket.s3.amazonaws.com/path/resource?versionId=%20%20",
			"a", "b",
			"blah",
	},
	sig{"put",
			"PUT",
			"https://bucket.s3.amazonaws.com/path/resource",
			"a", "b",
			"blah",
	},
}

func makeRequest(sig sig) *http.Request {
	req, _ := http.NewRequest(sig.method, sig.url, strings.NewReader(""))
	return req
}

func TestSignature(t *testing.T) {
	for _, sig := range v1sigs {
		actual := Signature(sig.key, sig.secret, makeRequest(sig))
		if actual != sig.expected {
			t.Errorf("Signing %v, got: %v, expected: %v", sig.name, actual, sig.expected)
		}
	}
}

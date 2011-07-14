package s3sig

import (
	"testing"
	"http"
	"strings"
	"bufio"
)

type sig struct {
	name, method, url, key, secret, expected string
}

type example struct {
	name    string
	request string
	auth    string
}

const (
	AWSAccessKeyId     = "0PN5J17HBGZHT7JJ3X82"
	AWSSecretAccessKey = "uV3F3YluFJax1cknvbcGwgjvx4QpvB+leU8dUj2o"
)

// Example requests from the S3 spec
var examples = []example{
	example{"Object GET",
		`GET /photos/puppy.jpg HTTP/1.1
Host: johnsmith.s3.amazonaws.com
Date: Tue, 27 Mar 2007 19:36:42 +0000

`, "AWS 0PN5J17HBGZHT7JJ3X82:xXjDGYUmKxnwqr5KXNPGldn5LbA="},

	example{"Object PUT",
		`PUT /photos/puppy.jpg HTTP/1.1
Content-Type: image/jpeg
Content-Length: 1
Host: johnsmith.s3.amazonaws.com
Date: Tue, 27 Mar 2007 21:15:45 +0000

0`, "AWS 0PN5J17HBGZHT7JJ3X82:hcicpDDvL9SsO6AkvxqmIWkmOuQ="},

	example{"List",
		`GET /?prefix=photos&max-keys=50&marker=puppy HTTP/1.1
User-Agent: Mozilla/5.0
Host: johnsmith.s3.amazonaws.com
Date: Tue, 27 Mar 2007 19:42:41 +0000

`, "AWS 0PN5J17HBGZHT7JJ3X82:jsRt/rhG+Vtp88HrYL706QhE4w4="},

	example{"Fetch",
		`GET /?acl HTTP/1.1
Host: johnsmith.s3.amazonaws.com
Date: Tue, 27 Mar 2007 19:44:46 +0000

`, "AWS 0PN5J17HBGZHT7JJ3X82:thdUi9VAkzhkniLj96JIrOPGi0g="},

	example{"Delete",
		`DELETE /johnsmith/photos/puppy.jpg HTTP/1.1
User-Agent: dotnet
Host: s3.amazonaws.com
Date: Tue, 27 Mar 2007 21:20:27 +0000
x-amz-date: Tue, 27 Mar 2007 21:20:26 +0000

`, "AWS 0PN5J17HBGZHT7JJ3X82:k3nL7gH3+PadhTEVn5Ip83xlYzk="},

	example{"Upload",
		`PUT /db-backup.dat.gz HTTP/1.1
User-Agent: curl/7.15.5
Host: static.johnsmith.net:8080
Date: Tue, 27 Mar 2007 21:06:08 +0000
x-amz-acl: public-read
content-type: application/x-download
Content-MD5: 4gJE4saaMU4BqNR0kLY+lw==
X-Amz-Meta-ReviewedBy: joe@johnsmith.net
X-Amz-Meta-ReviewedBy: jane@johnsmith.net
X-Amz-Meta-FileChecksum: 0x02661779
X-Amz-Meta-ChecksumAlgorithm: crc32
Content-Disposition: attachment; filename=database.dat
Content-Encoding: gzip
Content-Length: 1

0`, "AWS 0PN5J17HBGZHT7JJ3X82:C0FlOtU8Ylb9KDTpZqYkZPX91iI="},

	example{"List All My Buckets",
		`GET / HTTP/1.1
Host: s3.amazonaws.com
Date: Wed, 28 Mar 2007 01:29:59 +0000

`, "AWS 0PN5J17HBGZHT7JJ3X82:Db+gepJSUbZKwpx1FR0DLtEYoZA="},

	example{"Unicode Keys",
		`GET /dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re HTTP/1.1
Host: s3.amazonaws.com
Date: Wed, 28 Mar 2007 01:49:49 +0000

`, "AWS 0PN5J17HBGZHT7JJ3X82:dxhSBHoI6eVSPcXJqEghlUzZMnY="},
}

func makeRequest(sig sig) *http.Request {
	req, _ := http.NewRequest(sig.method, sig.url, strings.NewReader(""))
	return req
}

func TestAuthorize(t *testing.T) {
	for _, ex := range examples {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(ex.request)))
		if err != nil {
			t.Error(err)
		}

		Authorize(req, AWSAccessKeyId, AWSSecretAccessKey)

		if auth := req.Header.Get("Authorization"); auth != ex.auth {
			toSign := StringToSign(req.Method, req.URL, req.Header, "")
			t.Error("Fail Authorize:", ex.name, "got:", auth, "want:", ex.auth, "url:", req.URL.Host, "host:", req.Host, "string:", toSign)
		}

	}
}

func addAuth(raw, auth, expires string) string {
	sig := strings.Split(auth, ":", 2)[1]
	extra := "AWSAccessKeyId="+AWSAccessKeyId+"&Expires="+expires+"&Signature="+sig
	if strings.Contains(raw, "?") {
		return raw+"&"+extra
	}
	return raw+"?"+extra
}

func TestURL(t *testing.T) {
	for _, ex := range examples {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(ex.request)))
		if err != nil {
			t.Error(err)
		}

		if len(req.Header) > 1 {
			// Only works on requests without any headers
			// Host header has been removed
			continue
		}

		date := req.Header.Get("Date")

		url, err := http.ParseURL("http://"+req.Host+req.URL.RawPath)
		if err != nil {
			t.Error(err)
		}

		signed, err := URL(url, AWSAccessKeyId, AWSSecretAccessKey, req.Method, date)
		if err != nil {
			t.Error(err)
		}

		// Fudge a bit on this test.  The date should be in Unix timestamp
		// but we can only compare against known signatures for now so use
		// the existing date.

		if auth := addAuth(url.Raw, ex.auth, date); auth != signed.Raw {
			t.Error("Fail URL:", ex.name, "got:", signed.Raw, "want:", auth, "headers:", len(req.Header))
		}
	}
}

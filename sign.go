package s3sig

import (
	"os"
	"http"
	"time"
	"sort"
	"bytes"
	"strings"
	"encoding/base64"
	"crypto/hmac"
)

var amzQueryParams = map[string]bool{
	"acl":                          true,
	"location":                     true,
	"logging":                      true,
	"notification":                 true,
	"partNumber":                   true,
	"policy":                       true,
	"requestPayment":               true,
	"torrent":                      true,
	"uploadId":                     true,
	"uploads":                      true,
	"versionId":                    true,
	"versioning":                   true,
	"versions":                     true,
	"website":                      true,
	"response-content-type":        true,
	"response-content-language":    true,
	"response-expires":             true,
	"response-cache-control":       true,
	"response-content-disposition": true,
	"response-content-encoding":    true,
}

func canonicalizedResource(url *http.URL) string {
	var res string

	// Strip any port declaration (443/80/8080/...)
	host := first(strings.Split(url.Host, ":", 2))

	if strings.HasSuffix(host, "amazonaws.com") {
		// Hostname bucket style, ignore (s3-eu-west.|s3.)amazonaws.com
		parts := strings.Split(host, ".", -1)
		if len(parts) > 3 {
			res = res + "/" + strings.Join(parts[:len(parts)-3], ".")
		}
	} else if len(host) > 0 {
		// CNAME bucket style
		res = res + "/" + host
	} else {
		// Bucket as root element in path already
	}

	// RawPath will include the bucket if not in the host
	res = res + strings.Split(url.RawPath, "?", 2)[0]

	// Include a sorted list of query parameters that have
	// special meaning to aws.  These should stay decoded for
	// the canonical resource.
	var amz []string
	for key, values := range url.Query() {
		if amzQueryParams[key] {
			for _, value := range values {
				if value != "" {
					amz = append(amz, key+"="+value)
				} else {
					amz = append(amz, key)
				}
			}
		}
	}

	if len(amz) > 0 {
		sort.SortStrings(amz)
		res = res + "?" + strings.Join(amz, "&")
	}

	// All done.
	return res
}

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

/*
	Creates the StringToSign string for either query string
	or Authorization header based authentication.
*/
func StringToSign(method string, url *http.URL, requestHeaders http.Header, expires string) string {
	// Positional headers are optional but should be captured
	var contentMD5, contentType, date, amzDate string
	var headers []string

	// Build the named, and capture the positional headers
	for name, values := range requestHeaders {
		name = strings.ToLower(name)

		switch name {
		case "date":
			date = first(values)
		case "content-type":
			contentType = first(values)
		case "content-md5":
			contentMD5 = first(values)
		default:
			if strings.HasPrefix(name, "x-amz-") {
				// Capture the x-amz-date header
				// Note: undefined behavior if there are more than
				// one of these headers
				if name == "x-amz-date" {
					amzDate = first(values)
				}

				// Assuming any rfc822 unfolding has happened already
				headers = append(headers, name+":"+strings.Join(values, ",")+"\n")
			}
		}
	}

	sort.SortStrings(headers)

	// overrideDate is used for query string "expires" auth
	// and is a unix timestamp
	switch {
	case expires != "":
		date = expires
	case amzDate != "":
		date = ""
	default:
		// Don't break referential transparency here by injecting
		// the date when the Date is empty.  Rather we assume the
		// caller knows what she is doing. 
	}

	return method + "\n" +
		contentMD5 + "\n" +
		contentType + "\n" +
		date + "\n" +
		strings.Join(headers, "") +
		canonicalizedResource(url)
}

// Returns the signature to be used in the query string or Authorization header
func Signature(secret, toSign string) string {
	// Signature = Base64( HMAC-SHA1( UTF-8-Encoding-Of( YourSecretAccessKeyID, StringToSign ) ) );
	// Need to confirm what encoding go strings are when converted to []byte
	hmac := hmac.NewSHA1([]byte(secret))
	hmac.Write([]byte(toSign))

	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(hmac.Sum()))
	encoder.Close()

	return buf.String()
}

func Authorization(req *http.Request, key, secret string) string {
	return "AWS " + key + ":" + Signature(secret, StringToSign(req.Method, req.URL, req.Header, ""))
}

// Assumes no custom headers are sent so only needs access to a URL.
// If you plan on sending x-amz-* headers with a query string authorization
// you can use Signature(secret, StringToSign(url, headers, expires)) instead
// Returns an http.URL struct constructed from the Raw URL with the AWS
// query parameters appended at the end.
// Assumes any fragments are not included in url.Raw
func URL(url *http.URL, key, secret, method, expires string) (*http.URL, os.Error) {
	sig := Signature(secret, StringToSign(method, url, http.Header{}, expires))
	raw := url.Raw
	parts := strings.Split(raw, "?", 2)
	params := parts[1:]
	params = append(params, "AWSAccessKeyId="+key)
	params = append(params, "Expires="+expires)
	params = append(params, "Signature="+sig)
	signed := strings.Join(append(parts[:1], strings.Join(params, "&")), "?")

	return http.ParseURL(signed)
}

// Authorizes an http.Request pointer in place by in-place replacing the
// header of the provided request:
//
//	Authorization: AWS ACCOUNT SIGNATURE
//
// If the x-amz-date and Date headers are missing, this adds UTC current
// time in RFC1123 format inplace to the Date header:
//
//	Date: Mon, 02 Jan 2006 15:04:05 UTC
//
// If the Host does not appear in the req.URL, then it will be assigned
// from req.Host
func Authorize(req *http.Request, key, secret string) {
	var header string

	if req.URL.Host != req.Host {
		req.URL.Host = req.Host
	}

	if header = req.Header.Get("Date"); len(header) == 0 {
		if header = req.Header.Get("X-Amz-Date"); len(header) == 0 {
			req.Header.Set("Date", time.UTC().Format(time.RFC1123))
		}
	}

	req.Header.Set("Authorization", Authorization(req, key, secret))
}

package s3sig

import (
	"http"
	"sort"
	"strings"
	"fmt"
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

	// Split and prepend the host bucket off the top of 
	// s3-eu-west.amazonaws.com and the like
	parts := strings.Split(url.Host, ".", -1)
	if len(parts) > 3 {
		res = res + "/" + strings.Join(parts[:len(parts)-3], ".")
	}

	// RawPath will include the bucket if not in the host
	res = res + strings.Split(url.RawPath, "?", 2)[0]

	// Include a sorted list of query parameters that have
	// special meaning to aws.  These should stay decoded for
	// the canonical resource.
	var amz []string
	for key, values := range url.Query() {
		fmt.Println("q:", key, values)
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
	if len(s) > 0 { return s[0] }
	return ""
}

func stringToSign(r *http.Request) string {
	// Positional headers are optional but should be captured
	var contentMD5, contentType, httpDate, amzDate string
	var headers []string

	// Build the named, and capture the positional headers
	for name, values := range r.Header {
		name = strings.ToLower(name)

		switch name {
		case "date":
			httpDate = first(values)
		case "content-type":
			contentType = first(values)
		case "content-md5":
			contentType = first(values)
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

	if amzDate != "" {
		httpDate = ""
	} else {
		// We could break referential transparency here by injecting
		// the date when httpDate is empty.  Rather we assume the
		// caller knows what she is doing. 
	}

	return r.Method + "\n" +
				contentMD5 + "\n" +
				contentType + "\n" +
				httpDate + "\n" +
				strings.Join(headers, "") +
				canonicalizedResource(r.URL)
}

// Returns the signature to be used in the query string or Authorization header
func Signature(key, secret string, r *http.Request) string {
	return stringToSign(r)
}

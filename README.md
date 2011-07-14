# s3sig

There are many ways to interact with the [S3 REST API][api] and most client libraries encode assumptions about the kind of payload they're manipulating, don't quite handle errors in a way you'd like.

Talking HTTP and laying some calls together to form a domain specific client for your interaction with S3 is what this package tries to accomplish, and provides a means to sign any http.Request pointer, or return the signature for use in query string authorized S3 URLs.

# Don't use it

I'm still writing this.

[api]: http://docs.amazonwebservices.com/AmazonS3/latest/dev/index.html?RESTAuthentication.html

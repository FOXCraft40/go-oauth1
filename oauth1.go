package ezOauth1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OAuth1 //
type OAuth1 struct {
	ConsumerKey    string
	ConsumerSecret string
	AccessToken    string
	AccessSecret   string
}

// BuildOAuth1Header // Params being any key-value url query parameter pairs
func (auth OAuth1) BuildOAuth1Header(method, path string, withRealm bool, params map[string]string) string {
	vals := url.Values{}
	vals.Add("oauth_nonce", generateNonce())
	vals.Add("oauth_consumer_key", auth.ConsumerKey)
	vals.Add("oauth_signature_method", "HMAC-SHA1")
	vals.Add("oauth_timestamp", strconv.Itoa(int(time.Now().Unix())))
	vals.Add("oauth_version", "1.0")
	vals.Add("oauth_token", auth.AccessToken)

	for k, v := range params {
		vals.Add(k, v)
	}
	// net/url package QueryEscape escapes " " into "+", this replaces it with the percentage encoding of " "
	parameterString := strings.Replace(vals.Encode(), "+", "%20", -1)

	// Calculating Signature Base String and Signing Key
	signatureBase := strings.ToUpper(method) + "&" + url.QueryEscape(strings.Split(path, "?")[0]) + "&" + url.QueryEscape(parameterString)
	signingKey := url.QueryEscape(auth.ConsumerSecret) + "&" + url.QueryEscape(auth.AccessSecret)
	signature := calculateSignature(signatureBase, signingKey)

	// Set realm
	realm := ""
	if withRealm {
		realm = "realm=\"" + url.QueryEscape(strings.Split(path, "?")[0]) + "\", "
	}

	return "OAuth " + realm +
		"oauth_consumer_key=\"" + url.QueryEscape(vals.Get("oauth_consumer_key")) + "\"" +
		", oauth_token=\"" + url.QueryEscape(vals.Get("oauth_token")) + "\"" +
		", oauth_nonce=\"" + url.QueryEscape(vals.Get("oauth_nonce")) + "\"" +
		", oauth_signature_method=\"" + url.QueryEscape(vals.Get("oauth_signature_method")) + "\"" +
		", oauth_timestamp=\"" + url.QueryEscape(vals.Get("oauth_timestamp")) + "\"" +
		", oauth_version=\"" + url.QueryEscape(vals.Get("oauth_version")) + "\"" +
		", oauth_signature=\"" + url.QueryEscape(signature) + "\""
}

func calculateSignature(base, key string) string {
	hash := hmac.New(sha1.New, []byte(key))
	hash.Write([]byte(base))
	signature := hash.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature)
}

func generateNonce() string {
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 48)
	for i := range b {
		b[i] = allowed[rand.Intn(len(allowed))]
	}
	return string(b)
}

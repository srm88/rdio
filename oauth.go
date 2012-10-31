package rdio

import (
  "crypto/hmac"
  "crypto/sha1"
  "encoding/base64"
  "errors"
  "io/ioutil"
  "math/rand"
  "net/url"
  "net/http"
  "sort"
  "strconv"
  "strings"
  "time"
)

const (
  Version = "1.0"
  HashAlgorithm = "HMAC-SHA1"
)

type Consumer struct {
  Key, Secret string
}

func MakeConsumer(key, secret string) *Consumer {
  return &Consumer{key, secret}
}

type Token struct {
  Key, Secret string
}

func (t Token) Serialize() (rawToken string) {
  return strings.Join([]string{t.Key, t.Secret}, "|")
}

func DeserializeToken(rawToken string) (t Token, err error) {
  parts := strings.Split(rawToken, "|")
  if len(parts) != 2 {
    err = errors.New("Could not deserialize token from string " + rawToken)
    return
  }
  t = Token{parts[0], parts[1]}
  return
}

// GetAuth returns the Authorization header for a request to an oauth service.
// The first step in any oauth authorization is to request a token for the user,
// which will require an authorized request. For this stage, token is expected
// to be nil.
// Subsequent requests will use the token's key to generate the signature.
func (c *Consumer) GetAuth(endpoint string, parameters url.Values, token *Token, realm string) (string, error) {
  return c.GetAuthWithTimestampAndNonce(endpoint, parameters, token, realm, GenTimestamp(), GenNonce())
}

// GetAuthWithTimestampAndNonce is the sister function of GetAuth. Use this if
// you wish to control the oauth nonce and timestamp of your request.
func (c *Consumer) GetAuthWithTimestampAndNonce(endpoint string, parameters url.Values, token *Token, realm, timestamp, nonce string) (string, error) {
  paramsForSigning := getPairs(parameters)
  oauthPairs := pairList{
    pair{"oauth_version", Version},
    pair{"oauth_timestamp", timestamp},
    pair{"oauth_nonce", nonce},
    pair{"oauth_signature_method", HashAlgorithm},
    pair{"oauth_consumer_key", c.Key},
  }
  // Add the Oauth parameters to the existing ones.
  paramsForSigning = append(paramsForSigning, oauthPairs...)

  // Normalize the URL, stripping default port if present.
  u, err := url.Parse(endpoint)
  if err != nil {
    return "", err
  }
  if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) || 
  (u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
    trimLength := 0
    if strings.HasSuffix(u.Host, ":80") {
      trimLength = 3
    } else {
      trimLength = 4
    }
    u.Host = u.Host[:len(u.Host) - trimLength]
  }
  normalizedUrl := u.String()

  // Build the HMAC key.
  hmacKey := c.Secret + "&"
  if token != nil {
    hmacKey += token.Secret
    oauthPairs = append(oauthPairs, pair{"oauth_token", token.Key})
    paramsForSigning = append(paramsForSigning, pair{"oauth_token", token.Key})
  }

  // Sort the key-value pairs by key, then value.
  sort.Sort(paramsForSigning)

  normalizedParams := strings.Join(paramsForSigning.queryEscape(nil), "&")
  signatureBase := strings.Join([]string{
    escape("POST"),
    escape(normalizedUrl),
    escape(normalizedParams)}, "&")

  hash := hmac.New(sha1.New, []byte(hmacKey))
  hash.Write([]byte(signatureBase))
  signature := base64.StdEncoding.EncodeToString(hash.Sum(nil))

  // Build the authorization header. This consists of query escaping the oauth
  // parameters, including the computed signature and the realm.
  oauthPairs = append(oauthPairs, pair{"oauth_signature", signature})
  if realm != "" {
    oauthPairs = append(oauthPairs, pair{"realm", realm})
  }
  quoteWrap := func(in string) string { return "\"" + in + "\"" }
  res := strings.Join(oauthPairs.queryEscape(quoteWrap), ", ")
  return "OAuth " + res, nil
}

func (c *Consumer) SignedPostRequestWithTimestampAndNonce(url string, parameters url.Values, token *Token, timestamp string, nonce string) (response string, err error) {
  var (
    auth string
    request *http.Request
    resp *http.Response
    respBytes []byte
  )
  if request, err = http.NewRequest("POST", url, strings.NewReader(parameters.Encode())); err != nil {
    return
  }
  // Get our authorization header.
  if auth, err = c.GetAuthWithTimestampAndNonce(url, parameters, token, "", timestamp, nonce); err != nil {
    return
  }
  request.Header.Set("Authorization", auth)
  request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  if resp, err = http.DefaultClient.Do(request); err != nil {
    return
  }
  defer resp.Body.Close()
  if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
    return
  }
  response = string(respBytes)
  return
}


func (c *Consumer) SignedPostRequest(url string, parameters url.Values, token *Token) (response string, err error) {
  var (
    auth string
    request *http.Request
    resp *http.Response
    respBytes []byte
  )
  if request, err = http.NewRequest("POST", url, strings.NewReader(parameters.Encode())); err != nil {
    return
  }
  // Get our authorization header.
  if auth, err = c.GetAuth(url, parameters, token, ""); err != nil {
    return
  }
  request.Header.Set("Authorization", auth)
  request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  if resp, err = http.DefaultClient.Do(request); err != nil {
    return
  }
  defer resp.Body.Close()
  if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
    return
  }
  response = string(respBytes)
  return
}


// Utils
func ParseToken(values url.Values) (*Token, error) {
  key := values.Get("oauth_token")
  secret := values.Get("oauth_token_secret")
  if key == "" || secret == "" {
    return nil, errors.New("Key or secret not found!")
  }
  return &Token{key, secret}, nil
}

func GenTimestamp () string {
  return strconv.FormatInt(time.Now().Unix(), 10)
}

func GenNonce () string {
  rand.Seed(time.Now().Unix())
  const chars = "abcdefghijklmnopqrstuvwxyz1234567890"
  buf := make([]byte, 12)
  for i := 0; i < 12; i++ {
    buf[i] = chars[rand.Intn(len(chars))]
  }
  return string(buf)
}

func escape(s string) string {
  s = url.QueryEscape(s)
  return strings.Replace(s, "+", "%20", -1)
}

// Helpers for sorting url.Values
type pair struct {
  Key, Value string
}

type pairList []pair

// Implement sort.Interface.
func (p pairList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p pairList) Len() int { return len(p) }
func (p pairList) Less(i, j int) bool { return p[i].Key < p[j].Key || (p[i].Key == p[j].Key && p[i].Value < p[j].Value) }

func getPairs(v url.Values) pairList {
  p := make(pairList, 0, len(v) * 2)
  for k, vs := range v {
    if k == "oauth_signature" {
      continue
    }
    for _, v := range vs {
      p = append(p, pair{k, v})
    }
  }
  return p
}

func (pairs pairList) queryEscape(valueTransform func(string) string) []string {
  parts := make([]string, 0, len(pairs))
  for _, p := range pairs {
    part := escape(p.Key) + "="
    if valueTransform != nil {
      part += valueTransform(escape(p.Value))
    } else {
      part += escape(p.Value)
    }
    parts = append(parts, part)
  }
  return parts
}


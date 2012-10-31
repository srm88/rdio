package rdio

import (
  "errors"
  "encoding/json"
  "math"
  "net/url"
)

const (
  RequestTokenUrl = "http://api.rdio.com/oauth/request_token"
  AccessTokenUrl = "http://api.rdio.com/oauth/access_token"
  ALBUM_TYPE = "a"
  TRACK_TYPE = "t"
)

type Rdio struct {
  *Consumer
  AuthToken *Token
  Token *Token
  AuthUrl *url.URL
  Timestamp string
  Nonce string
}

func MakeRdio(consumerKey, consumerSecret string) (*Rdio, error) {
  consumer := &Consumer{consumerKey, consumerSecret}
  return &Rdio{consumer, nil, nil, nil, "", ""}, nil
}

func (r *Rdio) BeginAuth(callbackUrl string) (err error) {
  var resp string
  var values url.Values
  // Get a request token from the server.
  if resp, err = r.SignedPostRequest(RequestTokenUrl, url.Values{"oauth_callback": []string{callbackUrl}}, nil); err != nil {
    err = errors.New("Couldn't get a request token: " + err.Error())
    return
  }

  // Extract the token and secret from the response.
  if values, err = url.ParseQuery(resp); err != nil {
    err = errors.New("Couldn't parse response into a query string: " + err.Error())
    return
  }
  if r.AuthToken, err = ParseToken(values); err != nil {
    err = errors.New("Couldn't find token in values:\n'" + values.Encode() + "'\nError: " + err.Error())
    return
  }

  loginUrl := values.Get("login_url")
  if loginUrl == "" {
    err = errors.New("No oauth_login found in response")
    return
  }
  // Return a Url the caller can use to authorize this app.
  if r.AuthUrl, err = url.Parse(loginUrl + "?oauth_token=" + r.AuthToken.Key); err != nil {
    return
  }
  return
}

func (r *Rdio) CompleteAuth(verifier string) (err error) {
  var (
    resp string
    values url.Values
  )
  if r.Timestamp != "" && r.Nonce != "" {
    if resp, err = r.SignedPostRequestWithTimestampAndNonce(AccessTokenUrl, url.Values{"oauth_verifier": []string{verifier}}, r.AuthToken, r.Timestamp, r.Nonce); err != nil {
      return
    }
  } else {
    if resp, err = r.SignedPostRequest(AccessTokenUrl, url.Values{"oauth_verifier": []string{verifier}}, r.AuthToken); err != nil {
      return
    }
  }

  if values, err = url.ParseQuery(resp); err != nil {
    return
  }
  if r.Token, err = ParseToken(values); err != nil {
    return
  }
  return
}

func (r *Rdio) Call(method string, params url.Values) (resp string, err error) {
  params.Set("method", method)
  return r.SignedPostRequest("http://api.rdio.com/1/", params, r.Token)
}

func (r *Rdio) SetToken(key, secret string) {
  r.Token = &Token{key, secret}
}

func (r *Rdio) SetAuthToken(key, secret string) {
  r.AuthToken = &Token{key, secret}
}

func (r *Rdio) SetNonce(nonce string) {
  r.Nonce = nonce
}

func (r *Rdio) SetTimestamp(timestamp string) {
  r.Timestamp = timestamp
}

type SearchResult struct {
  Key string `json:"key"`
  Name string `json:"name"`
  Type string `json:"type"`
  Artist string `json:"artist"`
  Album string `json:"album"`
}

func (s *SearchResult) IsTrack() bool {
  return s.Type == TRACK_TYPE
}

func (s *SearchResult) IsAlbum() bool {
  return s.Type == ALBUM_TYPE
}

func ParseSearchResult(j string) (s *SearchResult, err error) {
  if err = json.Unmarshal([]byte(j), &s); err != nil {
    err = errors.New("Error parsing json string '" + j + "': " + err.Error())
    return
  }
  return
}

func shorten(s string, cutoff int) string {
  return s[:int(math.Min(float64(len(s)), float64(cutoff)))]
}

func ParseSearchResults(j string) ([]*SearchResult, error) {
  var err error
  var results struct { Result struct { Results []*SearchResult `json:"results"` } `json:"result"` }
  if err = json.Unmarshal([]byte(j), &results); err != nil {
    err = errors.New("Error parsing json string '" + shorten(j, 10) + "'...: " + err.Error())
    return nil, err
  }
  return results.Result.Results, err
}


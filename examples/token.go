package main

import (
  "flag"
  "fmt"
  "net/url"
  "github.com/srm88/rdio"
)

var (
  consumerKey string = *flag.String("key", "", "Consumer Key.")
  consumerSecret string = *flag.String("secret", "", "Consumer Secret.")
  err error
)

func main() {
  var err error
  flag.Parse()
  conn, _ := rdio.MakeRdio(consumerKey, consumerSecret)
  if err = conn.BeginAuth(""); err != nil {
    panic(err.Error())
  }
  fmt.Println(conn.AuthUrl.String())
  fmt.Println("Awaiting verifier...")
  var input string
  fmt.Scanln(&input)

  if err = conn.CompleteAuth(input); err != nil {
    panic(err.Error())
  }
  fmt.Println("Verified!")
  fmt.Println(conn.Token.Key)
  fmt.Println(conn.Token.Secret)

  var res string
  if res, err = conn.Call("get", url.Values{"keys": []string{"a254895,a104386"}}); err != nil {
    panic(err.Error())
  }
  fmt.Println(res)
}

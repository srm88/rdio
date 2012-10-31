package main

import (
  "flag"
  "fmt"
  "net/url"
  "rdio"
)

const (
  consumerKey = "xe9ns8uj4wzyxtahfre65nyd"
  consumerSecret = "sQXTFEPQWG"
)

var (
  accessKey = flag.String("key", "7d545kyfkuuhxnnq6h4kq9jh8wzqq5xxrbjy8qprgts8nh3xne2fnbvs5czuuz9v", "Access Key.")
  accessSecret = flag.String("secret", "WMfjahDVh8d8", "Access Secret.")
  err error
)

func main() {
  var err error
  flag.Parse()
  conn, _ := rdio.MakeRdio(consumerKey, consumerSecret)
  //if err = conn.BeginAuth("oob"); err != nil {
  //  panic(err.Error())
  //}
  //fmt.Println(conn.AuthUrl.String())
  //fmt.Println("Awaiting verifier...")
  //var input string
  //fmt.Scanln(&input)

  //if err = conn.CompleteAuth(input); err != nil {
  //  panic(err.Error())
  //}
  //fmt.Println("Verified!")
  conn.Token = &rdio.Token{*accessKey, *accessSecret}
  fmt.Println(conn.Token.Key)
  fmt.Println(conn.Token.Secret)

  var res string
  res, err = conn.Call("search", url.Values{
    "query": []string{"blah"},
    "types": []string{"Album, Track"},
  })
  if err != nil {
    panic(err.Error())
  }
  fmt.Println(res)

  //res, err = conn.Call("get", url.Values{"keys": []string{"a254895,a104386"}})
  //if err != nil {
  //  panic(err.Error())
  //}
  //fmt.Println(res)

  //res, err = conn.Call("get", url.Values{"keys": []string{"a254895,a104386"}})
  //if err != nil {
  //  panic(err.Error())
  //}
  //fmt.Println(res)

}

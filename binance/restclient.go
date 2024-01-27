// The MIT License (MIT)
//
// Copyright (c) 2018 Cranky Kernel
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package binance

import (
	"fmt"
	"net/http"
	"sort"
	"bytes"
	"io/ioutil"
	"encoding/json"
	"time"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const API_ROOT = "https://api.binance.com"

type restClientAuth struct {
	ApiKey    string
	ApiSecret string
}

type RestClient struct {
	auth *restClientAuth
}

func NewAnonymousClient() *RestClient {
	return &RestClient{
	}
}

func NewAuthenticatedClient(key string, secret string) *RestClient {
	return &RestClient{
		auth: &restClientAuth{
			ApiKey:    key,
			ApiSecret: secret,
		},
	}
}

// Perform an unauthenticated GET request.
func (c *RestClient) Get(endpoint string, params map[string]interface{}) (*http.Response, error) {

	url := fmt.Sprintf("%s%s", API_ROOT, endpoint)
	queryString := ""

	if params == nil {
		params = map[string]interface{}{}
	}

	if params != nil {
		queryString = c.BuildQueryString(params)
		if queryString != "" {
			url = fmt.Sprintf("%s?%s", url, queryString)
		}
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return http.DefaultClient.Do(request)
}

// Perform a fully authenticated GET request.
func (c *RestClient) GetWithAuth(endpoint string, params map[string]interface{}) (*http.Response, error) {

	url := fmt.Sprintf("%s%s", API_ROOT, endpoint)
	queryString := ""

	if params == nil {
		params = map[string]interface{}{}
	}

	if c.auth != nil {
		params["recvWindow"] = 5000
		params["timestamp"] = time.Now().UnixNano() / 1000000
	}

	if params != nil {
		queryString = c.BuildQueryString(params)
		if queryString != "" {
			url = fmt.Sprintf("%s?%s", url, queryString)
		}
	}

	if c.auth != nil {
		mac := hmac.New(sha256.New, []byte(c.auth.ApiSecret))
		mac.Write([]byte(queryString))
		signature := hex.EncodeToString(mac.Sum(nil))
		url = fmt.Sprintf("%s&signature=%s",
			url, signature)
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.auth != nil && c.auth.ApiKey != "" {
		request.Header.Add("X-MBX-APIKEY", c.auth.ApiKey)
	}

	return http.DefaultClient.Do(request)
}

func (c *RestClient) Post(endpoint string, params map[string]interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", API_ROOT, endpoint)
	queryString := ""

	if params == nil {
		params = map[string]interface{}{}
	}

	if c.auth != nil && c.auth.ApiSecret != "" {
		params["recvWindow"] = 5000
		params["timestamp"] = time.Now().UnixNano() / 1000000
	}

	if params != nil {
		queryString = c.BuildQueryString(params)
		if queryString != "" {
			url = fmt.Sprintf("%s?%s", url, queryString)
		}
	}

	if c.auth != nil && c.auth.ApiSecret != "" {
		mac := hmac.New(sha256.New, []byte(c.auth.ApiSecret))
		mac.Write([]byte(queryString))
		signature := hex.EncodeToString(mac.Sum(nil))
		url = fmt.Sprintf("%s&signature=%s",
			url, signature)
	}

	request, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	if c.auth != nil && c.auth.ApiKey != "" {
		request.Header.Add("X-MBX-APIKEY", c.auth.ApiKey)
	}

	return http.DefaultClient.Do(request)
}

// Send a POST request with only the API key and no other authentication.
func (c *RestClient) PostWithApiKey(endpoint string, params map[string]interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", API_ROOT, endpoint)
	queryString := ""

	if params == nil {
		params = map[string]interface{}{}
	}

	if params != nil {
		queryString = c.BuildQueryString(params)
		if queryString != "" {
			url = fmt.Sprintf("%s?%s", url, queryString)
		}
	}

	request, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	if c.auth != nil && c.auth.ApiKey != "" {
		request.Header.Add("X-MBX-APIKEY", c.auth.ApiKey)
	}

	return http.DefaultClient.Do(request)
}

func (c *RestClient) Delete(endpoint string, params map[string]interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", API_ROOT, endpoint)
	queryString := ""

	if params == nil {
		params = map[string]interface{}{}
	}

	if c.auth != nil && c.auth.ApiSecret != "" {
		params["recvWindow"] = 5000
		params["timestamp"] = time.Now().UnixNano() / 1000000
	}

	if params != nil {
		queryString = c.BuildQueryString(params)
		if queryString != "" {
			url = fmt.Sprintf("%s?%s", url, queryString)
		}
	}

	if c.auth != nil && c.auth.ApiSecret != "" {
		mac := hmac.New(sha256.New, []byte(c.auth.ApiSecret))
		mac.Write([]byte(queryString))
		signature := hex.EncodeToString(mac.Sum(nil))
		url = fmt.Sprintf("%s&signature=%s",
			url, signature)
	}

	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}

	if c.auth != nil && c.auth.ApiKey != "" {
		request.Header.Add("X-MBX-APIKEY", c.auth.ApiKey)
	}

	return http.DefaultClient.Do(request)
}

func (c *RestClient) DoPut(path string) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", API_ROOT, path)
	request, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("X-MBX-APIKEY", c.auth.ApiKey)

	return http.DefaultClient.Do(request)
}

func (c *RestClient) BuildQueryString(params map[string]interface{}) string {
	queryString := ""

	keys := func() []string {
		keys := []string{}
		for key, _ := range params {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	}()

	for _, key := range keys {
		if queryString != "" {
			queryString = fmt.Sprintf("%s&", queryString)
		}
		queryString = fmt.Sprintf("%s%s=%v", queryString, key, params[key])
	}

	return queryString
}

func (c *RestClient) decodeBody(r *http.Response, v interface{}) ([]byte, error) {
	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(v); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *RestClient) GetAllSymbols() ([]string, error) {
	lastTrades, err := c.GetAllPriceTicker()
	if err != nil {
		return nil, err
	}
	symbols := []string{}
	for _, trade := range lastTrades {
		symbols = append(symbols, trade.Symbol)
	}
	return symbols, nil
}

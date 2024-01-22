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
	"net/http"
	"strings"
	"io"
	"log"
)

// BinanceApiProxy is a standard web handler function that will proxy requests
// to the Binance API.
func BinanceApiProxy(w http.ResponseWriter, r *http.Request) {
	target := "https://api.binance.com"
	request, err := http.NewRequest(r.Method, target, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("error: failed to create request: %v\n", err)
		return
	}
	request.URL.Path = r.URL.Path
	request.URL.RawQuery = r.URL.RawQuery

	for key, val := range r.Header {
		switch strings.ToLower(key) {
		case "x-mbx-apikey":
			request.Header[key] = val
		default:
		}
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("error: failed to send request: %v\n", err)
		return
	}

	for key, val := range response.Header {
		w.Header()[key] = val
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

// NewBinanceApiProxyHandler return the Binance API proxy as a http.Handler.
//
// Useful if you need to strip the prefix, for example:
//     router.PathPrefix("/proxy/binance").Handler(
//         http.StripPrefix("/proxy/binance", NewBinanceApiProxyHandler()))
func NewBinanceApiProxyHandler() http.Handler {
	return http.HandlerFunc(BinanceApiProxy)
}

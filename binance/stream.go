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
	"github.com/gorilla/websocket"
	"strings"
	"fmt"
	"net/http"
)

const WS_STREAM_URL = "wss://stream.binance.com:9443"

type StreamClient struct {
	Conn *websocket.Conn
}

func OpenSingleStream(stream string) (*StreamClient, error) {
	client := NewStreamClient()
	err := client.ConnectSingle(stream)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func NewStreamClient() *StreamClient {
	client := &StreamClient{}
	return client
}

func (c *StreamClient) Connect(streams ... string) (err error) {
	path := fmt.Sprintf("stream?streams=%s", strings.Join(streams, "/"))
	c.Conn, err = openStream(path)
	return err
}

func (c *StreamClient) ConnectSingle(stream string) (err error) {
	path := fmt.Sprintf("ws/%s", stream)
	c.Conn, err = openStream(path)
	return err
}

func (c *StreamClient) Close() {
	c.Conn.Close()
}

func (c *StreamClient) Next() (messageType int, body []byte, err error) {
	return c.Conn.ReadMessage()
}

// Next reads the next message into a generic map.
func (c *StreamClient) NextJSON() (interface{}, error) {
	var message interface{}
	err := c.Conn.ReadJSON(&message)
	return message, err
}

func openStream(path string) (*websocket.Conn, error) {
	url := fmt.Sprintf("%s/%s", WS_STREAM_URL, path)
	ws, httpResponse, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%s", httpResponse.Status)
	}
	return ws, nil
}

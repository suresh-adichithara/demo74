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
	"strings"
	"github.com/gorilla/websocket"
	"encoding/json"
)

type AggTradeStreamEvent struct {
	Err   error
	Trade *StreamAggTrade
}

type AggTradeStream struct {
	ws             *websocket.Conn
	closeRequested bool
}

func OpenAggTradeStream(symbol string) (*AggTradeStream, error) {
	ws, err := openStream(fmt.Sprintf("ws/%s@aggTrade", strings.ToLower(symbol)))
	if err != nil {
		return nil, err
	}
	return &AggTradeStream{
		ws:             ws,
		closeRequested: false,
	}, nil
}

// Close closes the AggTradeStream. If there is a subscribed channel it will
// no longer be sent any data. So it is up to the subscriber to stop attempting
// to read from the channel.
func (c *AggTradeStream) Close() {
	c.closeRequested = true
	c.ws.Close()
}

func (c *AggTradeStream) Next() (trade *StreamAggTrade, err error) {
	_, buf, err := c.ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	var rawAggTrade StreamAggTrade
	if err := json.Unmarshal(buf, &rawAggTrade); err != nil {
		return nil, err
	}
	return &rawAggTrade, nil
}

func (c *AggTradeStream) Subscribe(channel chan AggTradeStreamEvent) {
	for {
		trade, err := c.Next()
		if err != nil {
			if !c.closeRequested {
				channel <- AggTradeStreamEvent{
					Err: err,
				}
			} else {
				// Close was requested. Attempt to send down a nil, nil message
				// as a signal that the stream has now been closed.
				select {
				case channel <- AggTradeStreamEvent{
					Err:   nil,
					Trade: nil,
				}:
				default:
				}
			}
			return
		} else {
			channel <- AggTradeStreamEvent{
				Trade: trade,
			}
		}
	}
}

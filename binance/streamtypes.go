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
	"strings"
	"encoding/json"
	"fmt"
	"time"
)

// Stream name: <symbol>@ticker.
type Stream24Ticker struct {
	EventType            string  `json:"e"`
	EventTime            int64   `json:"E"`
	Symbol               string  `json:"s"`
	PriceChange          float64 `json:"p,string"`
	PriceChangePercent   float64 `json:"P,string"`
	WeightedAveragePrice float64 `json:"w,string"`
	PreviousDayClose     float64 `json:"x,string"`
	CurrentDayClose      float64 `json:"c,string"`
	CloseTradeQuantity   float64 `json:"Q,string"`
	Bid                  float64 `json:"b,string"`
	BidQuantity          float64 `json:"B,string"`
	Ask                  float64 `json:"a,string"`
	AskQuantity          float64 `json:"A,string"`
	OpenPrice            float64 `json:"o,string"`
	HighPrice            float64 `json:"h,string"`
	LowPrice             float64 `json:"l,string"`
	TotalBaseVolume      float64 `json:"v,string"`
	TotalQuoteVolume     float64 `json:"q,string"`
	StatsOpenTime        int64   `json:"O"`
	StatsCloseTime       int64   `json:"C"`
	FirstTradeID         int64   `json:"F"`
	LastTradeID          int64   `json:"L"`
	TotalNumberTrades    int64   `json:"n"`
}

func (t *Stream24Ticker) Timestamp() time.Time {
	return time.Unix(0, t.EventTime*int64(time.Millisecond))
}

// Stream name: !ticker@arr.
type Stream24TickerAll []Stream24Ticker

// Stream name: <symbol>@aggTrade.
type StreamAggTrade struct {
	EventType       string  `json:"e"`
	EventTimeMillis int64   `json:"E"`
	Symbol          string  `json:"s"`
	TradeID         int64   `json:"a"`
	Price           float64 `json:"p,string"`
	Quantity        float64 `json:"q,string"`
	FirstTradeID    int64   `json:"f"`
	LastTradeID     int64   `json:"l"`
	TradeTimeMillis int64   `json:"T"`
	BuyerMaker      bool    `json:"m"`
	Ignored         bool    `json:"M"`
}

func (t *StreamAggTrade) QuoteQuantity() float64 {
	return t.Quantity * t.Price
}

func (t *StreamAggTrade) Timestamp() time.Time {
	return time.Unix(0, t.TradeTimeMillis*int64(time.Millisecond))
}

type CombinedStream24TickerAll struct {
	Stream  string            `json:"stream"`
	Tickers Stream24TickerAll `json:"data"`
}

type CombinedStreamAggTrade struct {
	Stream   string         `json:"stream"`
	AggTrade StreamAggTrade `json:"data"`
}

// Generic data type for a combined stream when it is not known how to decode
// the stream.
type CombinedStreamUnknown struct {
	Stream string      `json:"stream"`
	Data   interface{} `json:"data"`
}

type CombinedStreamMessage struct {
	Stream string

	// Data for !ticker@arr messages.
	Tickers []Stream24Ticker

	// Data for <symbol>@aggTrade messages.
	AggTrade *StreamAggTrade

	// For a stream that is unknown, decode the data into an interface{}.
	UnknownData interface{}

	Bytes []byte
}

func (r *CombinedStreamMessage) UnmarshalJSON(b []byte) error {
	r.Bytes = b
	prefix := string(b[0:40])
	if strings.HasPrefix(prefix, `{"stream":"!ticker@arr"`) {
		var message CombinedStream24TickerAll
		if err := json.Unmarshal(b, &message); err != nil {
			return err
		}
		r.Stream = message.Stream
		r.Tickers = message.Tickers
		return nil
	} else if strings.Index(prefix, "@aggTrade") > -1 {
		var message CombinedStreamAggTrade
		if err := json.Unmarshal(b, &message); err != nil {
			return err
		}
		r.Stream = message.Stream
		r.AggTrade = &message.AggTrade
		return nil
	} else if strings.HasPrefix(prefix, `{"stream":"`) {
		var message CombinedStreamUnknown
		if err := json.Unmarshal(b, &message); err != nil {
			return err
		}
		r.Stream = message.Stream
		r.UnknownData = message.Data
		return nil
	}
	return fmt.Errorf("not part of a multi-stream")
}

func DecodeRawStreamMessage(b []byte) (CombinedStreamMessage, error) {
	var message CombinedStreamMessage
	err := json.Unmarshal(b, &message)
	return message, err
}

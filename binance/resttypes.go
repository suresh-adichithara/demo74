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

type SymbolFilterResponse struct {
	FilterType  string  `json:"filterType"`
	MinPrice    float64 `json:"minPrice,string"`
	MaxPrice    float64 `json:"maxPrice,string"`
	TickSize    float64 `json:"tickSize,string"`
	MinQty      float64 `json:"minQty,string"`
	MaxQty      float64 `json:"maxQty,string"`
	StepSize    float64 `json:"stepSize,string"`
	MinNotional float64 `json:"minNotional,string"`
}

type SymbolInfoResponse struct {
	Symbol              string                 `json:"symbol"`
	Status              string                 `json:"status"`
	BaseAsset           string                 `json:"baseAsset"`
	BaseAssetPrecision  int64                  `json:"baseAssetPrecision`
	QuoteAsset          string                 `json:"quoteAsset"`
	QuoteAssetPrecision int64                  `json:"quoteAssetPrecision"`
	OrderTypes          []string               `json:"orderTypes"`
	IcebergAllowed      bool                   `json:"icebergAllowed"`
	Filters             []SymbolFilterResponse `json:"filters"`
}

type ExchangeInfoResponse struct {
	Timezone         string `json:"timezone"`
	ServerTimeMillis int64  `json:"serverTime"`
	RateLimits []struct {
		RateLimitType     string `json:"rateLimitType"`
		RateLimitInterval string `json"rateLimitInterval"`
		Limit             int64  `json"limit"`
	}
	Symbols []SymbolInfoResponse `json:"symbols"`

	RawResponse []byte `json:"-"`
}

type CancelOrderResponse struct {
	Symbol            string `json:"symbol"`
	OrigClientOrderID string `json:"origClientOrderId"`
	OrderID           int64  `json:"orderId"`
	ClientOrderID     string `json:"clientOrderId"`
}

type AccountInfoBalance struct {
	Asset  string  `json:"asset"`
	Free   float64 `json:"free,string"`
	Locked float64 `json:"locked,string"`
}

type AccountInfoResponse struct {
	MakerCommission  int64                `json:"makerCommission"`
	TakerCommission  int64                `json:"takerCommission"`
	BuyerCommission  int64                `json:"buyerCommission"`
	SellCommission   int64                `json:"sellCommission"`
	CanTrade         bool                 `json:"canTrade"`
	CanWithdraw      bool                 `json:"canWithdraw"`
	CanDeposit       bool                 `json:"canDeposit"`
	UpdateTimeMillis int64                `json:"updateTime"`
	Balances         []AccountInfoBalance `json:"balances"`
}

type QueryOrderResponse struct {
	Symbol        string      `json:"symbol"`
	OrderId       int64       `json:"orderId"`
	ClientOrderId string      `json:"clientOrderId"`
	Price         float64     `json:"price,string"`
	OrigQty       float64     `json:"origQty,string"`
	ExecutedQty   float64     `json:"executeQty,string"`
	Status        OrderStatus `json:"status"`
	TimeInForce   TimeInForce `json:"timeInForce"`
	Type          OrderType   `json:"type"`
	Side          OrderSide   `json:"side"`
	StopPrice     float64     `json:"stopPrice,string"`
	IcebergQty    float64     `json:"icebergQty,string"`
	TimeMillis    int64       `json:"time"`
	IsWorking     bool        `json:"isWorking"`
}

type PriceTickerResponse struct {
	Symbol string  `json:"symbol"`
	Price  float64 `json:"price,string"`
}

type OrderBookTickerResponse struct {
	Symbol   string  `json:"symbol"`
	BidPrice float64 `json:"bidPrice,string"`
	BidQty   float64 `json:"bidQty,string"`
	AskPrice float64 `json:"askPrice,string"`
	AskQty   float64 `json:"askQty,string"`
}

// GET /api/v3/myTrades
type TradeResponse struct {
	ID              int64   `json:"id"`
	OrderID         int64   `json:"orderId"`
	Price           float64 `json:"price,string"`
	Quantity        float64 `json:"qty,string"`
	Commission      float64 `json:"commission,string"`
	CommissionAsset string  `json:"commissionAsset"`
	TimeMillis      int64   `json:"time"`
	IsBuyer         bool    `json:"isBuyer"`
	IsMaker         bool    `json:"isMaker"`
	IsBestMatch     bool    `json:"isBestMatch"`
}

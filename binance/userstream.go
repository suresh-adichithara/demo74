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

type StreamAccountInfoBalance struct {
	Asset  string  `json:"a"`
	Free   float64 `json:"f,string"`
	Locked float64 `json:"l,string"`
}

type StreamOutboundAccountInfo struct {
	EventType             string                     `json:"e"`
	EventTimeMillis       int64                      `json:"E"`
	MakerCommissionRate   int64                      `json:"m"`
	TakerCommissionRate   int64                      `json:"t"`
	BuyerCommissionRate   int64                      `json:"b"`
	SellerCommissionRate  int64                      `json:"s"`
	CanTrade              bool                       `json:"T"`
	CanWithdraw           bool                       `json:"W"`
	CanDeposit            bool                       `json:"D"`
	LastAccountUpdateTime int64                      `json:"u"`
	Balances              []StreamAccountInfoBalance `json:"B"`
}

type StreamExecutionReport struct {
	EventType                string      `json:"e"`
	EventTimeMillis          int64       `json:"E"`
	Symbol                   string      `json:"s"`
	ClientOrderID            string      `json:"c"`
	Side                     OrderSide   `json:"S"`
	OrderType                string      `json:"o"`
	TimeInForce              string      `json:"f"`
	Quantity                 float64     `json:"q,string"`
	Price                    float64     `json:"p,string"`
	StopPrice                float64     `json:"P,string"`
	IcebergQuantity          float64     `json:"F,string"`
	OriginalClientOrderID    string      `json:"C"`
	CurrentExecutionType     OrderStatus `json:"x"`
	CurrentOrderStatus       OrderStatus `json:"X"`
	OrderRejectReason        string      `json:"r"`
	OrderID                  int64       `json:"i"`
	LastExecutedQuantity     float64     `json:"l,string"`
	CumulativeFilledQuantity float64     `json:"z,string"`
	LastExecutedPrice        float64     `json:"L,string"`
	CommissionAmount         float64     `json:"n,string"`
	CommissionAsset          string      `json:"N"`
	TransactionTimeMillis    int64       `json:"T"`
	TradeID                  int64       `json:"t"`
	IsWorking                bool        `json:"w"`
	IsMaker                  bool        `json:"m"`

	// Ignore values that we have to include here due to the case insensitivity
	// of the Go JSON unmarshaller.
	Ignore0 int64       `json:"O,-"`
	Ignore1 interface{} `json:"I,-"`
}

func OpenUserStream(restClient *RestClient) (*StreamClient, error) {
	listenKey, err := restClient.GetUserDataStream()
	if err != nil {
		return nil, err
	}

	streamClient := NewStreamClient()
	if err := streamClient.ConnectSingle(listenKey); err != nil {
		return nil, err
	}

	return streamClient, nil
}

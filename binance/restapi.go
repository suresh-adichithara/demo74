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
	"io/ioutil"
	"net/http"
	"fmt"
	"encoding/json"
	"bytes"
)

type RestApiError struct {
	StatusCode int
	Body       []byte
}

func NewRestApiErrorFromResponse(r *http.Response) *RestApiError {
	body, _ := ioutil.ReadAll(r.Body)
	return &RestApiError{
		StatusCode: r.StatusCode,
		Body:       body,
	}
}

func (e *RestApiError) Error() string {
	return string(e.Body)
}

type UserDataStreamResponse struct {
	ListenKey string `json:"listenKey"`
}

// GetUserDataStream makes the get request for a user data stream listen key.
func (c *RestClient) GetUserDataStream() (string, error) {
	httpResponse, err := c.PostWithApiKey("/api/v1/userDataStream", nil)
	if err != nil {
		return "", err
	}

	if httpResponse.StatusCode >= 400 {
		return "", NewRestApiErrorFromResponse(httpResponse)
	}

	var response UserDataStreamResponse
	if _, err = c.decodeBody(httpResponse, &response); err != nil {
		return "", err
	}

	return response.ListenKey, nil
}

func (c *RestClient) PutUserStreamKeepAlive(listenKey string) error {
	queryString := c.BuildQueryString(map[string]interface{}{
		"listenKey": listenKey,
	})
	path := fmt.Sprintf("/api/v1/userDataStream?%s", queryString)
	httpResponse, err := c.DoPut(path)
	if err != nil {
		return err
	}
	if httpResponse.StatusCode != http.StatusOK {
		return NewRestApiErrorFromResponse(httpResponse)
	}
	return nil
}

type OrderSide string

const (
	OrderSideBuy  OrderSide = "BUY"
	OrderSideSell OrderSide = "SELL"
)

type OrderType string

const (
	OrderTypeLimit  OrderType = "LIMIT"
	OrderTypeMarket OrderType = "MARKET"
)

type TimeInForce string

const (
	TimeInForceGTC TimeInForce = "GTC"
	TimeInForceIOC TimeInForce = "IOC"
	TimeInForceFOK TimeInForce = "FOK"
)

// Order status / execution type.
type OrderStatus string

const (
	OrderStatusNew             OrderStatus = "NEW"
	OrderStatusCanceled        OrderStatus = "CANCELED"
	OrderStatusFilled          OrderStatus = "FILLED"
	OrderStatusPartiallyFilled OrderStatus = "PARTIALLY_FILLED"
)

type OrderParameters struct {
	Symbol           string
	Side             OrderSide
	Type             OrderType
	TimeInForce      TimeInForce
	Quantity         float64
	Price            float64
	NewClientOrderId string
}

// TODO: Implement RESULT and FULL response types. Currently only ACK implemented.
type PostOrderResponse struct {
	Symbol                string `json:"symbol"`
	OrderId               int64  `json:"orderId"`
	ClientOrderId         string `json:"clientOrderId"`
	TransactionTimeMillis int64  `json:"transactTime"`
}

func (c *RestClient) PostOrder(order OrderParameters) (*http.Response, error) {
	params := map[string]interface{}{}
	params["symbol"] = order.Symbol
	params["side"] = order.Side
	params["type"] = order.Type
	params["quantity"] = order.Quantity

	switch order.Type {
	case OrderTypeMarket:
	default:
		params["price"] = fmt.Sprintf("%.8f", order.Price)
	}
	params["newClientOrderId"] = order.NewClientOrderId
	if order.TimeInForce != "" {
		params["timeInForce"] = order.TimeInForce
	}

	response, err := c.Post("/api/v3/order", params)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return response, NewRestApiErrorFromResponse(response)
	}
	return response, nil
}

func (c *RestClient) CancelOrder(symbol string, orderId int64) (*CancelOrderResponse, error) {
	params := map[string]interface{}{}
	params["symbol"] = symbol
	params["orderId"] = orderId

	httpResponse, err := c.Delete("/api/v3/order", params)
	if err != nil {
		return nil, err
	}

	if httpResponse.StatusCode != http.StatusOK {
		return nil, NewRestApiErrorFromResponse(httpResponse)
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	var cancelOrderResponse CancelOrderResponse
	if err := json.Unmarshal(body, &cancelOrderResponse); err != nil {
		return nil, err
	}
	return &cancelOrderResponse, nil
}

func GetExchangeInfo() (*ExchangeInfoResponse, error) {
	client := NewAnonymousClient()
	response, err := client.GetWithAuth("/api/v1/exchangeInfo", nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, NewRestApiErrorFromResponse(response)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var exchangeInfoResponse ExchangeInfoResponse
	if err := json.Unmarshal(body, &exchangeInfoResponse); err != nil {
		return nil, err
	}
	exchangeInfoResponse.RawResponse = body

	return &exchangeInfoResponse, nil
}

func (c *RestClient) GetAccount() (*AccountInfoResponse, error) {
	httpResponse, err := c.GetWithAuth("/api/v3/account", nil)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode >= 400 {
		return nil, NewRestApiErrorFromResponse(httpResponse)
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	var response AccountInfoResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *RestClient) GetOrderByOrderId(symbol string, orderId int64) (QueryOrderResponse, error) {
	var response QueryOrderResponse
	params := map[string]interface{}{
		"symbol":  symbol,
		"orderId": orderId,
	}
	httpResponse, err := c.GetWithAuth("/api/v3/order", params)
	if err != nil {
		return response, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return response, NewRestApiErrorFromResponse(httpResponse)
	}
	decoder := json.NewDecoder(httpResponse.Body)
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	return response, nil
}

func (c *RestClient) GetOrderByClientId(symbol string, clientId string) (QueryOrderResponse, error) {
	var response QueryOrderResponse
	params := map[string]interface{}{
		"symbol":  symbol,
		"origClientOrderId": clientId,
	}
	httpResponse, err := c.GetWithAuth("/api/v3/order", params)
	if err != nil {
		return response, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return response, NewRestApiErrorFromResponse(httpResponse)
	}
	decoder := json.NewDecoder(httpResponse.Body)
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	return response, nil
}

// Return the latest prices for all symbols.
func (c *RestClient) GetAllPriceTicker() ([]PriceTickerResponse, error) {
	endpoint := "/api/v3/ticker/price"
	var response []PriceTickerResponse
	err := c.genericGetAndDecode(endpoint, nil, &response)
	return response, err
}

func (c *RestClient) GetPriceTicker(symbol string) (PriceTickerResponse, error) {
	endpoint := "/api/v3/ticker/price"
	var response PriceTickerResponse
	params := map[string]interface{}{
		"symbol": symbol,
	}
	err := c.genericGetAndDecode(endpoint, params, &response)
	return response, err
}

func (c *RestClient) GetOrderBookTicker(symbol string) (OrderBookTickerResponse, error) {
	endpoint := "/api/v3/ticker/bookTicker"
	params := map[string]interface{}{
		"symbol": symbol,
	}
	var response OrderBookTickerResponse
	err := c.genericGetAndDecode(endpoint, params, &response)
	return response, err
}

func (c *RestClient) GetMytrades(symbol string, limit int64, fromId int64) ([]TradeResponse, error) {
	endpoint := "/api/v3/myTrades"
	params := map[string]interface{}{
		"symbol": symbol,
	}
	if limit > 0 {
		params["limit"] = limit
	}
	if fromId > -1 {
		params["fromId"] = fromId
	}
	var response []TradeResponse
	err := c.genericGetWithAuthAndDecode(endpoint, params, &response)
	return response, err
}

func (c *RestClient) genericGetWithAuthAndDecode(endpoint string, params map[string]interface{}, response interface{}) error {
	httpResponse, err := c.GetWithAuth(endpoint, params)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != 200 {
		return NewRestApiErrorFromResponse(httpResponse)
	}
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	return decoder.Decode(response)
}

func (c *RestClient) genericGetAndDecode(endpoint string, params map[string]interface{}, response interface{}) error {
	httpResponse, err := c.GetWithAuth(endpoint, params)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != 200 {
		return NewRestApiErrorFromResponse(httpResponse)
	}
	decoder := json.NewDecoder(httpResponse.Body)
	return decoder.Decode(response)
}

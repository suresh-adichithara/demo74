package binance

import (
	"testing"
	"encoding/json"
)

func TestDecodeRawOrderUpdate(t *testing.T) {
	buf := `{"e":"executionReport","E":1525367516316,"s":"ETHBTC","c":"ixN5efEm67zwRm3Ts8NL3R","S":"SELL","o":"MARKET","f":"GTC","q":"0.02900000","p":"0.00000000","P":"0.00000000","F":"0.00000000","g":-1,"C":"null","x":"NEW","X":"NEW","r":"NONE","i":140990852,"l":"0.00000000","z":"0.00000000","L":"0.00000000","n":"0","N":null,"T":1525367516312,"t":-1,"I":339998904,"w":true,"m":false,"Trackers":false,"O":-1,"Z":"-0.00000001"}`
	var rawOrderUpdate StreamExecutionReport
	err := json.Unmarshal([]byte(buf), &rawOrderUpdate)
	if err != nil {
		t.Fatal(err)
	}
}

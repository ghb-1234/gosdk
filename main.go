package main

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

const (
	peerendpoint = "peer0.org1.example.com:7051"
	channelid    = "mychannel"
	orgID        = "Org1"
	orgAdmin     = "Admin"
	chaincodeid  = "mycc"
)

var (
	efsdk *fabsdk.FabricSDK
)

func main() {
	LoadConfig()
	channelquery()
}

func channelquery() {
	c := efsdk.Context(fabsdk.WithUser(orgAdmin), fabsdk.WithOrg(orgID))
	resMgmtClient, err := resmgmt.New(c)
	if err != nil {
		fmt.Println(">>>>2222", err)
		return
	}
	resp, err := resMgmtClient.QueryChannels(resmgmt.WithTargetEndpoints(peerendpoint))
	if err != nil {
		fmt.Println(">>>333", err)
		return
	}
	fmt.Printf(">>>%#v\n", resp)
}

func query() {
	clientcontext := efsdk.ChannelContext(channelid, fabsdk.WithUser(orgAdmin))
	channelclient, err := channel.New(clientcontext)
	if err != nil {
		fmt.Println(">>>>query init:", err)
		return
	}

	req := channel.Request{
		ChaincodeID: chaincodeid,
		Fcn:         "query",
		Args:        [][]byte{[]byte("query"), []byte("a")},
	}

	resp, err := channelclient.Query(req, channel.WithTargetEndpoints(peerendpoint))
	if err != nil {
		fmt.Println(">>>>query:", err)
		return
	}
	fmt.Println(resp)
}

func invoke() {
	//   clientcontext := sdk.sdk.ChannelContext(e.ChannelID, fabsdk.WithUser(e.OrgName))
	// 	channelclient, err := channel.New(clientcontext)
	// 	if err != nil {
	// 		return fmt.Errorf("[YYChannelClient] channel.New error %v\n", err)
	// 	}

	//   req := channel.Request{
	// 		ChaincodeID: chaincodeid,
	// 		Fcn:         fcn,
	// 		Args:        args,
	// 	}
	// 	resp, err := e.channelClient.Execute(req, channel.WithTargetEndpoints(endpointpeer))
	// 	if err != nil {
	// 		return nil, err
	// 	}
}

func LoadConfig() {
	//配置文件参数
	fabsdkfile := "./config_e2e.yaml"

	if strings.TrimSpace(fabsdkfile) == "" {
		panic("do not find the sdk file")
	}
	var err error
	configProvider := config.FromFile(fabsdkfile)
	efsdk, err = fabsdk.New(configProvider)
	if err != nil {
		fmt.Printf("initialize fabsdk error: %v\n", err)
		panic(err)
	}

	// configBackend, err := efsdk.Config()
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// endpointConfig, err := plocyfab.ConfigFromBackend(configBackend)
	// if err != nil {
	// 	fmt.Println(">>>", err)
	// }
	// fmt.Printf("%#v\n", endpointConfig)

	logging.SetLevel("sdk", logging.DEBUG)
	// networkConfig, err := endpointConfig.NetworkConfig()
	// if err != nil {
	// 	fmt.Println(">>>", err)

	// }
	// fmt.Printf("%#v\n", networkConfig)

}

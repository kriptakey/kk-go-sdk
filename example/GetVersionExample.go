package main

import (
	"fmt"

	kk "github.com/kriptakey/kk-go-sdk/kriptakey"
)

func main() {

	sdkVersion := kk.GetSDKVersion()
	fmt.Println(sdkVersion)
}

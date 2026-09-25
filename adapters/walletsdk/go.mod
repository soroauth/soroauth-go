module github.com/soroauth/soroauth-go/adapters/walletsdk

go 1.25.0

require (
	github.com/okx/go-wallet-sdk v0.0.0-20260523030746-12fec6b06163
	github.com/soroauth/soroauth-go v0.0.0
	github.com/stellar/go-stellar-sdk v0.7.3
)

require (
	github.com/klauspost/compress v1.17.6 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stellar/go-xdr v0.0.0-20260806060815-dc590f17552a // indirect
)

replace github.com/soroauth/soroauth-go => ../..

package main

import (
	"github.com/lodevil/ladder"
	_ "github.com/lodevil/ladder/encryptors"
	"log"
)

func main() {
	cfg, _ := ladder.NewConfig([]byte("{}"))
	if maker, err := ladder.GetEncryptorMaker("dummy", cfg); err != nil {
		log.Fatal(err)
	} else {
		enc, _ := maker.New()
		msg := []byte("lodevil")
		log.Println(enc.Encrypt(msg))
	}
}

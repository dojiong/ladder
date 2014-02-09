package ladder

import "errors"

type EncryptorMakerFunc func(Config) (EncryptorMaker, error)

type EncryptorMaker interface {
	New() (Encryptor, error)
}

type Encryptor interface {
	Close() error
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

var encryptors map[string]EncryptorMakerFunc

func init() {
	encryptors = make(map[string]EncryptorMakerFunc)
}

func RegisterEncryptorMaker(name string, f EncryptorMakerFunc) {
	encryptors[name] = f
}

func GetEncryptorMaker(name string, cfg Config) (EncryptorMaker, error) {
	if f, ok := encryptors[name]; ok {
		return f(cfg)
	}
	return nil, errors.New("no such EncryptorMaker")
}

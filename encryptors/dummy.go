package encryptors

import (
	"github.com/lodevil/ladder"
)

type DummyEncryptorMaker struct {
}

type DummyEncryptor struct {
}

func (d *DummyEncryptorMaker) New() (ladder.Encryptor, error) {
	return &DummyEncryptor{}, nil
}

func (d *DummyEncryptor) Close() error {
	return nil
}

func (d *DummyEncryptor) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (d *DummyEncryptor) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

func init_maker(cfg ladder.Config) (ladder.EncryptorMaker, error) {
	return &DummyEncryptorMaker{}, nil
}

func init() {
	ladder.RegisterEncryptorMaker("dummy", init_maker)
}

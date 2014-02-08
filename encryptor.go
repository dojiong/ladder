package ladder

type Encryptor interface {
	New(config Config) (Encryptor, error)
	Close() error
	Encrypt(in []byte, out []byte) error
	Decrypt(in []byte, out []byte) error
}

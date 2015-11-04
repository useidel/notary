package cryptoservice

import (
	"crypto/rand"
	"fmt"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
)

const (
	rsaKeySize = 2048 // Used for snapshots and targets keys
)

// CryptoService implements Sign and Create, holding a specific GUN and keystore to
// operate on
type CryptoService struct {
	gun       string
	keyStores []trustmanager.KeyStore
}

// NewCryptoService returns an instance of CryptoService
func NewCryptoService(gun string, keyStores ...trustmanager.KeyStore) *CryptoService {
	return &CryptoService{gun: gun, keyStores: keyStores}
}

// Create is used to generate keys for targets, snapshots and timestamps
func (ccs *CryptoService) Create(role, algorithm string) (data.PublicKey, error) {
	var privKey data.PrivateKey
	var err error

	switch algorithm {
	case data.RSAKey:
		privKey, err = trustmanager.GenerateRSAKey(rand.Reader, rsaKeySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %v", err)
		}
	case data.ECDSAKey:
		privKey, err = trustmanager.GenerateECDSAKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EC key: %v", err)
		}
	case data.ED25519Key:
		privKey, err = trustmanager.GenerateED25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ED25519 key: %v", err)
		}
	default:
		return nil, fmt.Errorf("private key type not supported for key generation: %s", algorithm)
	}
	logrus.Debugf("generated new %s key for role: %s and keyID: %s", algorithm, role, privKey.ID())

	// Store the private key into our keystore with the name being: /GUN/ID.key with an alias of role
	var keyPath string
	if role == data.CanonicalRootRole {
		keyPath = privKey.ID()
	} else {
		keyPath = filepath.Join(ccs.gun, privKey.ID())
	}

	for _, ks := range ccs.keyStores {
		err = ks.AddKey(keyPath, role, privKey)
		if err == nil {
			return data.PublicKeyFromPrivate(privKey), nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to add key to filestore: %v", err)
	}
	return nil, fmt.Errorf("keystores would not accept new private keys for unknown reasons")

}

// GetPrivateKey returns a private key by ID. It tries to get the key first
// without a GUN (in which case it's a root key).  If that fails, try to get
// the key with the GUN (non-root key).
// If that fails, then we don't have the key.
func (ccs *CryptoService) GetPrivateKey(keyID string) (k data.PrivateKey, id string, err error) {
	keyPaths := []string{keyID, filepath.Join(ccs.gun, keyID)}
	for _, ks := range ccs.keyStores {
		for _, keyPath := range keyPaths {
			k, id, err = ks.GetKey(keyPath)
			if err != nil {
				continue
			}
			return
		}
	}
	return // returns whatever the final values were
}

// GetKey returns a key by ID
func (ccs *CryptoService) GetKey(keyID string) data.PublicKey {
	privKey, _, err := ccs.GetPrivateKey(keyID)
	if err != nil {
		return nil
	}
	return data.PublicKeyFromPrivate(privKey)
}

// RemoveKey deletes a key by ID
func (ccs *CryptoService) RemoveKey(keyID string) (err error) {
	keyPaths := []string{keyID, filepath.Join(ccs.gun, keyID)}
	for _, ks := range ccs.keyStores {
		for _, keyPath := range keyPaths {
			_, _, err = ks.GetKey(keyPath)
			if err != nil {
				continue
			}
			err = ks.RemoveKey(keyPath)
			return
		}
	}
	return // returns whatever the final values were
}

// Sign returns the signatures for the payload with a set of keyIDs. It ignores
// errors to sign and expects the called to validate if the number of returned
// signatures is adequate.
func (ccs *CryptoService) Sign(keyIDs []string, payload []byte) ([]data.Signature, error) {
	signatures := make([]data.Signature, 0, len(keyIDs))
	for _, keyid := range keyIDs {
		keyName := keyid

		privKey, _, err := ccs.GetPrivateKey(keyName)
		if err != nil {
			logrus.Debugf("error attempting to retrieve private key: %s, %v", keyid, err)
			continue
		}

		sigAlgo := privKey.SignatureAlgorithm()
		sig, err := privKey.Sign(rand.Reader, payload, nil)
		if err != nil {
			logrus.Debugf("ignoring error attempting to %s sign with keyID: %s, %v",
				privKey.Algorithm(), keyid, err)
			continue
		}

		logrus.Debugf("appending %s signature with Key ID: %s", privKey.Algorithm(), keyid)

		// Append signatures to result array
		signatures = append(signatures, data.Signature{
			KeyID:     keyid,
			Method:    sigAlgo,
			Signature: sig[:],
		})
	}

	return signatures, nil
}

// ListKeys returns a list of key IDs valid for the given role
func (ccs *CryptoService) ListKeys(role string) []string {
	var res []string
	for _, ks := range ccs.keyStores {
		for k, r := range ks.ListKeys() {
			if r == role {
				res = append(res, k)
			}
		}
	}
	return res
}

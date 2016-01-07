package main

import (
	"fmt"
	"io/ioutil"
	"os"

	notaryclient "github.com/docker/notary/client"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cmdDelegationTemplate = usageTemplate{
	Use:   "delegation",
	Short: "Operates on delegations.",
	Long:  `Operations on TUF delegations.`,
}

var cmdDelegationListTemplate = usageTemplate{
	Use:   "list [ GUN ]",
	Short: "Lists delegations for the Global Unique Name.",
	Long:  "Lists all delegations known to notary for a specific Global Unique Name.",
}

var cmdDelegationRemoveTemplate = usageTemplate{
	Use:   "remove [ GUN ] [ KeyID ] [ Role ]",
	Short: "Remove a Role delegation for the KeyID.",
	Long:  "Remove a Role delegation for the KeyID in a specific Global Unique Name.",
}

var cmdDelegationAddTemplate = usageTemplate{
	Use:   "add [ GUN ] [ Path to PEM file ] [ Role ] <delegation path 1> ...",
	Short: "Add a Role delegation for the KeyID.",
	Long:  "Add a Role delegation for the KeyID in a specific Global Unique Name.",
}

type delegationCommander struct {
	// these need to be set
	configGetter func() *viper.Viper
	retriever    passphrase.Retriever
}

func (d *delegationCommander) GetCommand() *cobra.Command {
	cmd := cmdDelegationTemplate.ToCommand(nil)
	cmd.AddCommand(cmdDelegationListTemplate.ToCommand(d.delegationsList))
	cmd.AddCommand(cmdDelegationRemoveTemplate.ToCommand(d.delegationRemove))
	cmd.AddCommand(cmdDelegationAddTemplate.ToCommand(d.delegationAdd))

	return cmd
}

// delegationsList lists all the delegations for a particular GUN
func (d *delegationCommander) delegationsList(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf(
			"Please provide a Global Unique Name as an argument to list")
	}

	_ = d.configGetter()

	cmd.Println("")
	cmd.Println("DELEGATIONS GO HERE")
	cmd.Println("")
	return nil
}

// delegationRemove removes a public key from a specific role in a GUN
func (d *delegationCommander) delegationRemove(cmd *cobra.Command, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("must specify the Global Unique Name, the Key ID and the role of the delegation to remove")
	}

	_ = d.configGetter()
	cmd.Println("")
	cmd.Println("Remove delegation here")
	cmd.Println("")

	return nil
}

// delegationAdd adds a public key to a specific role in a GUN
func (d *delegationCommander) delegationAdd(cmd *cobra.Command, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("must specify the Global Unique Name, the Key ID, the role of the delegation to add and a list of paths")
	}

	config := d.configGetter()
	ks, err := d.getKeyStores(config, true)
	if err != nil {
		return err
	}
	gun := args[0]
	pubKeyPath := args[1]
	role := args[2]
	paths := args[3:]

	// Check to see if the public key file exists
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("pub key file does not exist: %s", pubKeyPath)
	}

	// Read public key from PEM file
	pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("unable to read public key from file: %s", pubKeyPath)
	}

	// Parse PEM bytes into a public key
	pubKey, err := trustmanager.Parse

	// Check to see if it is an invalid ID
	if len(keyID) != idSize {
		return fmt.Errorf("invalid key ID provided: %s", keyID)
	}

	// Create a CryptoService from all the keystores so we can retrieve the public key
	cs := cryptoservice.NewCryptoService(gun, ks...)

	// Get the PublicKey from the ID
	pubKey := cs.GetKey(keyID)
	if pubKey == nil {
		return fmt.Errorf("key ID not found: %s", keyID)
	}

	// no online operations are performed by add so the transport argument
	// should be nil
	nRepo, err := notaryclient.NewNotaryRepository(mainViper.GetString("trust_dir"), gun, getRemoteTrustServer(mainViper), nil, retriever)
	if err != nil {
		fatalf(err.Error())
	}

	// Add the delegation to the repository
	err = nRepo.AddDelegation(role, 1, []data.PublicKey{pubKey}, paths)
	if err != nil {
		return fmt.Errorf("failed to add delegation: %v", err)
	}

	cmd.Println("")
	cmd.Printf(
		"Addition of delegation of key \"%s\" to role %s with paths %s, to repository \"%s\" staged for next publish.\n",
		keyID, role, paths, gun)
	cmd.Println("")
	return nil
}

func (d *delegationCommander) getKeyStores(
	config *viper.Viper, withHardware bool) ([]trustmanager.KeyStore, error) {

	directory := config.GetString("trust_dir")
	fileKeyStore, err := trustmanager.NewKeyFileStore(directory, d.retriever)
	if err != nil {
		return nil, fmt.Errorf(
			"Failed to create private key store in directory: %s", directory)
	}

	ks := []trustmanager.KeyStore{fileKeyStore}

	if withHardware {
		yubiStore, err := getYubiKeyStore(fileKeyStore, d.retriever)
		if err == nil && yubiStore != nil {
			// Note that the order is important, since we want to prioritize
			// the yubikey store
			ks = []trustmanager.KeyStore{yubiStore, fileKeyStore}
		}
	}

	return ks, nil
}

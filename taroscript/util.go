package taroscript

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/commitment"
)

// PayToAddrScript constructs a P2TR script that embeds a Taro commitment
// by tweaking the receiver key by a Tapscript tree that contains the Taro
// commitment root. The Taro commitment must be reconstructed by the receiver,
// and they also need to Tapscript sibling hash used here if present.
func PayToAddrScript(internalKey btcec.PublicKey, sibling *chainhash.Hash,
	commitment commitment.TaroCommitment) ([]byte, error) {

	tapscriptRoot := commitment.TapscriptRoot(sibling)
	outputKey := txscript.ComputeTaprootOutputKey(
		&internalKey, tapscriptRoot[:],
	)

	return PayToTaprootScript(outputKey)
}

// PayToTaprootScript creates a pk script for a pay-to-taproot output key.
func PayToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}

// IdentifyTapScriptSibling finds the sibling to the Taro root commitment in
// the list of tapscript leaves. It returns the root hash of the Tapscript
// merkle tree and the sibling leaf.
func IdentifyTapScriptSibling(leaves []txscript.TapLeaf) (chainhash.Hash,
	*txscript.TapLeaf, error) {

	// Find the sibling to the Taro root commitment.
	switch {
	case len(leaves) == 1:
		return leaves[0].TapHash(), nil, nil

	case len(leaves) == 2:
		tree := txscript.AssembleTaprootScriptTree(leaves...)
		rootHash := tree.RootNode.TapHash()

		siblingIndex := 0
		if commitment.IsTaroCommitmentScript(leaves[0].Script) {
			siblingIndex = 1
		}

		return rootHash, &leaves[siblingIndex], nil

	default:
		// TODO(guggero): Support more than two leaves by implementing
		// branch pre-image tapscript siblings.
		return chainhash.Hash{}, nil, fmt.Errorf("unexpected number "+
			"of tapscript leaves: %d", len(leaves))
	}
}

package taprpc

import (
	"context"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// KeyLookup is used to determine whether a key is under the control of the
// local wallet.
type KeyLookup interface {
	// IsLocalKey returns true if the key is under the control of the
	// wallet and can be derived by it.
	IsLocalKey(ctx context.Context, desc keychain.KeyDescriptor) bool
}

// MarshalAsset converts an asset to its rpc representation.
func MarshalAsset(ctx context.Context, a *asset.Asset,
	isSpent, withWitness bool,
	keyRing KeyLookup) (*Asset, error) {

	scriptKeyIsLocal := false
	if a.ScriptKey.TweakedScriptKey != nil && keyRing != nil {
		scriptKeyIsLocal = keyRing.IsLocalKey(
			ctx, a.ScriptKey.RawKey,
		)
	}

	rpcAsset := &Asset{
		Version: int32(a.Version),
		AssetGenesis: &GenesisInfo{
			GenesisPoint: a.Genesis.FirstPrevOut.String(),
			Name:         a.Genesis.Tag,
			MetaHash:     a.Genesis.MetaHash[:],
			AssetId:      a.ID[:],
			OutputIndex:  a.Genesis.OutputIndex,
		},
		AssetType:        AssetType(a.Type),
		Amount:           a.Amount,
		LockTime:         int32(a.LockTime),
		RelativeLockTime: int32(a.RelativeLockTime),
		ScriptVersion:    int32(a.ScriptVersion),
		ScriptKey:        a.ScriptKey.PubKey.SerializeCompressed(),
		ScriptKeyIsLocal: scriptKeyIsLocal,
		IsSpent:          isSpent,
		IsBurn:           a.IsBurn(),
	}

	if a.GroupKey != nil {
		var (
			rawKey       []byte
			groupWitness []byte
			err          error
		)

		if a.GroupKey.RawKey.PubKey != nil {
			rawKey = a.GroupKey.RawKey.PubKey.SerializeCompressed()
		}
		if len(a.GroupKey.Witness) != 0 {
			groupWitness, err = asset.SerializeGroupWitness(
				a.GroupKey.Witness,
			)
			if err != nil {
				return nil, err
			}
		}
		rpcAsset.AssetGroup = &AssetGroup{
			RawGroupKey:     rawKey,
			TweakedGroupKey: a.GroupKey.GroupPubKey.SerializeCompressed(),
			AssetWitness:    groupWitness,
		}
	}

	if withWitness {
		for idx := range a.PrevWitnesses {
			witness := a.PrevWitnesses[idx]

			prevID := witness.PrevID
			rpcPrevID := &PrevInputAsset{
				AnchorPoint: prevID.OutPoint.String(),
				AssetId:     prevID.ID[:],
				ScriptKey:   prevID.ScriptKey[:],
			}

			var rpcSplitCommitment *SplitCommitment
			if witness.SplitCommitment != nil {
				rootAsset, err := MarshalAsset(
					ctx, &witness.SplitCommitment.RootAsset,
					false, true, nil,
				)
				if err != nil {
					return nil, err
				}

				rpcSplitCommitment = &SplitCommitment{
					RootAsset: rootAsset,
				}
			}

			rpcAsset.PrevWitnesses = append(
				rpcAsset.PrevWitnesses, &PrevWitness{
					PrevId:          rpcPrevID,
					TxWitness:       witness.TxWitness,
					SplitCommitment: rpcSplitCommitment,
				},
			)
		}
	}

	return rpcAsset, nil
}

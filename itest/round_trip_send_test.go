package itest

import (
	"context"
	"time"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testRoundTripSend tests that we can properly send the full value of a
// normal asset.
func testRoundTripSend(t *harnessTest) {
	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.Stop(true))
	}()

	// We'll send half of the minted units to Bob, and then have Bob return
	// half of the units he received.
	fullAmt := rpcAssets[0].Amount
	bobAmt := fullAmt / 2
	aliceAmt := bobAmt / 2

	// First, we'll send half of the units to Bob.
	bobAddr, err := secondTarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     bobAmt,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)
	sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId,
		[]uint64{bobAmt, bobAmt}, 0, 1,
	)
	_ = sendProof(t, t.tarod, secondTarod, bobAddr.ScriptKey, genInfo)

	// Now, Alice will request half of the assets she sent to Bob.
	aliceAddr, err := t.tarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     aliceAmt,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, t.tarod, rpcAssets[0], aliceAddr)
	sendResp = sendAssetsToAddr(t, secondTarod, aliceAddr)
	sendRespJSON, err = formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	confirmAndAssertOutboundTransfer(
		t, secondTarod, sendResp, genInfo.AssetId,
		[]uint64{aliceAmt, aliceAmt}, 0, 1,
	)
	_ = sendProof(t, secondTarod, t.tarod, aliceAddr.ScriptKey, genInfo)

	// Give both nodes some time to process the final transfer.
	time.Sleep(time.Second * 1)

	// Check the final state of both nodes. Each node should list
	// one transfer, and Alice should have 3/4 of the total units.
	err = wait.NoError(func() error {
		assertTransfers(t.t, t.tarod, []uint64{bobAmt})
		assertBalanceByID(t.t, t.tarod, genInfo.AssetId, bobAmt+aliceAmt)

		assertTransfers(t.t, secondTarod, []uint64{aliceAmt})
		assertBalanceByID(t.t, secondTarod, genInfo.AssetId, aliceAmt)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)
}

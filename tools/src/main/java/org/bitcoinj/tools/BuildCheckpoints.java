/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.tools;

import org.bitcoinj.core.listeners.NewBestBlockListener;
import org.bitcoinj.core.*;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import com.google.common.io.Resources;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Future;

import static com.google.common.base.Preconditions.checkState;
import static java.util.concurrent.TimeUnit.SECONDS;


import com.google.common.base.Objects;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.net.discovery.*;
import org.bitcoinj.params.*;
import org.bitcoinj.script.*;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import org.bitcoinj.utils.MonetaryFormat;

import javax.annotation.*;
import java.io.*;
import java.math.*;
import java.util.*;

import static org.bitcoinj.core.Coin.*;
import org.bitcoinj.utils.VersionTally;

/**
 * Downloads and verifies a full chain from your local peer, emitting checkpoints at each difficulty transition period
 * to a file which is then signed with your key.
 */
public class BuildCheckpoints {
    private static NetworkParameters params;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.initWithSilentBitcoinJ();

        OptionParser parser = new OptionParser();
        parser.accepts("help");
        OptionSpec<NetworkEnum> netFlag = parser.accepts("net").withRequiredArg().ofType(NetworkEnum.class).defaultsTo(NetworkEnum.MAIN);
        parser.accepts("peer").withRequiredArg();
        OptionSpec<Integer> daysFlag = parser.accepts("days").withRequiredArg().ofType(Integer.class).defaultsTo(30);
        OptionSet options = parser.parse(args);

        if (options.has("help")) {
            System.out.println(Resources.toString(BuildCheckpoints.class.getResource("build-checkpoints-help.txt"), StandardCharsets.UTF_8));
            return;
        }

        final String suffix;
        switch (netFlag.value(options)) {
            case MAIN:
            case PROD:
                params = MainNetParams.get();
                suffix = "";
                break;
            case TEST:
                params = TestNet3Params.get();
                suffix = "-testnet";
                break;
            case REGTEST:
                params = RegTestParams.get();
                suffix = "-regtest";
                break;
            default:
                throw new RuntimeException("Unreachable.");
        }

        final File plainFile = new File("checkpoints" + suffix);
        final File textFile = new File("checkpoints" + suffix + ".txt");

        // Configure bitcoinj to fetch only headers, not save them to disk, connect to a local fully synced/validated
        // node and to save block headers that are on interval boundaries, as long as they are <1 month old.
        final BlockStore store = new MemoryBlockStore(params);

        Block genesisBlock;
        String genesisHash;
        Block genesisHeader;
        Block genesisCPBlock;
        String genesisCPHash;
        Block genesisCPHeader;

        genesisBlock = params.getGenesisBlock();
        genesisBlock.setDifficultyTarget(0x1f00ffffL);
        genesisBlock.setTime(1466861400L);
        genesisBlock.setNonce(63342);
        genesisHash = genesisBlock.getHashAsString();
        System.out.println("genesisHash="+genesisHash);
        System.out.println("genesisBlock="+genesisBlock.toString());
        genesisHeader = genesisBlock.cloneAsHeader();
        System.out.println("genesisHeader="+genesisHeader.toString());
        System.out.println("genesisHeader.getWork()="+genesisHeader.getWork());

        genesisCPBlock = params.getGenesisCheckpointBlock();
//        genesisBlock.setDifficultyTarget(0x1e012f76L);
//        genesisBlock.setTime(1541470033L);
//        genesisBlock.setNonce(3573025536L);
//        genesisBlock.setPrevBlockHash(Sha256Hash.wrap("000000f392442aee306d11be927f6c34be829ebcafaaa4fe645df7889f9f4cf0"));
        genesisCPHash = genesisCPBlock.getHashAsString();
//        System.out.println("genesisCheckpointHash="+genesisHash);
//        System.out.println("genesisBlock="+genesisBlock.toString());
        genesisCPHeader = genesisCPBlock.cloneAsHeader();
//        System.out.println("genesisHeader="+genesisHeader.toString());
//        System.out.println("genesisHeader.getWork()="+genesisHeader.getWork());

        StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
        StoredBlock storedCPGenesis = new StoredBlock(genesisCPHeader, genesisCPHeader.getWork(), 300000);
////        put(storedGenesis);
//

        //height 400000
        Transaction t = new Transaction(params);
        try {
            // A script containing the difficulty bits and the following message:
            //
            //   "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
//            byte[] bytes = Utils.HEX.decode
//                    ("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73");
//            "The New York Times June 25, 2016 BREXIT SETS OFF A CASCADE OF AFTERSHOCKS"
            byte[] bytes = Utils.HEX.decode
                    ("03801a060393bd180888000001000000050d2f436f696e69756d536572762f");
//            "04ffff001d010449546865204e657720596f726b2054696d6573204a756e652032352c2032303136204252455849542053455453204f464620412043415343414445204f4620414654455253484f434b53"
//            byte[] bytes = "The New York Times June 25, 2016 BREXIT SETS OFF A CASCADE OF AFTERSHOCKS".getBytes();
            //            System.out.println(bytes);
//            System.out.println(new String(bytes));
//            System.out.println(Utils.HEX.encode("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".getBytes()));
//            System.out.println(Utils.HEX.encode("The New York Times June 25, 2016 BREXIT SETS OFF A CASCADE OF AFTERSHOCKS".getBytes()));
            t.addInput(new TransactionInput(params, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Utils.HEX.decode
                    ("76a9140388720093ee4ba796c7e2e7e54b294eedfee05588ac"));
//            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
//            t.addOutput(new TransactionOutput(n, t, FIFTY_COINS, scriptPubKeyBytes.toByteArray()));
            t.addOutput(new TransactionOutput(params, t, COIN.multiply(64000), scriptPubKeyBytes.toByteArray()));
            ByteArrayOutputStream scriptPubKeyBytes2 = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes2, Utils.HEX.decode
                    ("76a914f58acda0cd52886951cbb5d6810faea02dba93d988ac"));
//            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
//            t.addOutput(new TransactionOutput(n, t, FIFTY_COINS, scriptPubKeyBytes.toByteArray()));
            t.addOutput(new TransactionOutput(params, t, COIN.multiply(64000), scriptPubKeyBytes2.toByteArray()));

        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        List<Transaction> transactions=new ArrayList<Transaction>();
        transactions.add(t);
        Block genesisCP40KBlock = new Block(
                params,
                0x20000000L,
                Sha256Hash.wrap("000000000cb9fe3bbd3de4a4a8099e232b0c9fd5e87001d5b545e8baa5d7ecd0"),
                Sha256Hash.wrap("960ec60ba3d7b0ab1033b8246bdc7d246f54ef6d8304faf5f71404742883e60c"),
                1621395117L,
                0x1c574991L,
                2352442800L,
                transactions
        );
//        genesisBlock.addTransaction(t);
//        return genesisBlock;
        String genesisCP40KHash = genesisCP40KBlock.getHashAsString();
        System.out.println("genesisCheckpointHash="+genesisCP40KHash);
        System.out.println("genesisBlock="+genesisCP40KBlock.toString());
        Block genesisCP40KHeader = genesisCP40KBlock.cloneAsHeader();
        StoredBlock storedCP40KGenesis = new StoredBlock(genesisCP40KHeader, genesisCP40KHeader.getWork(), 400000);

//        store.setChainHead(storedCP40KGenesis);

        final BlockChain chain = new BlockChain(params, store);
        final PeerGroup peerGroup = new PeerGroup(params, chain);

        final InetAddress ipAddress;

        // DNS discovery can be used for some networks
        boolean networkHasDnsSeeds = params.getDnsSeeds() != null;
        if (options.has("peer")) {
            // use peer provided in argument
            String peerFlag = (String) options.valueOf("peer");
            try {
                ipAddress = InetAddress.getByName(peerFlag);
                startPeerGroup(peerGroup, ipAddress);
            } catch (UnknownHostException e) {
                System.err.println("Could not understand peer domain name/IP address: " + peerFlag + ": " + e.getMessage());
                System.exit(1);
                return;
            }
        } else if (networkHasDnsSeeds) {
            // for PROD and TEST use a peer group discovered with dns
            peerGroup.setUserAgent("PeerMonitor", "1.0");
            peerGroup.setMaxConnections(20);
            peerGroup.addPeerDiscovery(new DnsDiscovery(params));
            peerGroup.start();

            // Connect to at least 4 peers because some may not support download
            Future<List<Peer>> future = peerGroup.waitForPeers(4);
            System.out.println("Connecting to " + params.getId() + ", timeout 20 seconds...");
            // throw timeout exception if we can't get peers
            future.get(20, SECONDS);
        } else {
            // try localhost
            ipAddress = InetAddress.getLocalHost();
            startPeerGroup(peerGroup, ipAddress);
        }

        // Sorted map of block height to StoredBlock object.
        final TreeMap<Integer, StoredBlock> checkpoints = new TreeMap<Integer, StoredBlock>();

        long now = new Date().getTime() / 1000;
        peerGroup.setFastCatchupTimeSecs(now);

        final long timeAgo = now - (86400 * options.valueOf(daysFlag));
        System.out.println("Checkpointing up to " + Utils.dateTimeFormat(timeAgo * 1000));
        System.out.println(String.format("params.getInterval()=%d" ,params.getInterval()));

        chain.addNewBestBlockListener(Threading.SAME_THREAD, new NewBestBlockListener() {
            @Override
            public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
                int height = block.getHeight();
//                System.out.println(String.format("notifyNewBestBlock block %s at height %d, time %s; height%%params.getInterval()=%d%%%d=%d; checkpoints.size()=%d",
//                        block.getHeader().getHash(), block.getHeight(), Utils.dateTimeFormat(block.getHeader().getTime()),height,params.getInterval()
//                        ,height % params.getInterval(),checkpoints.size()
//                ));
//                if (height % 6720 == 0 && block.getHeader().getTimeSeconds() <= timeAgo) {
//                    checkpoints.put(height, block);
//                    System.out.println(String.format("notifyNewBestBlock block %s at height %d, time %s; height%%params.getInterval()=%d%%%d=%d; checkpoints.size()=%d",
//                            block.getHeader().getHash(), block.getHeight(), Utils.dateTimeFormat(block.getHeader().getTime()),height,params.getInterval()
//                            ,height % params.getInterval(),checkpoints.size()
//                    ));
////                    System.out.println(block);
//                    if(checkpoints.size()>=3){
////                        System.out.println("peerGroup.stop();");
////                        peerGroup.stop();
////                        checkpoints.put(300000, storedCPGenesis);
////                        checkpoints.put(400000, storedCP40KGenesis);
////                        System.out.println(storedCPGenesis);
//                        try {
//                            // Write checkpoint data out.
//                            writeBinaryCheckpoints(checkpoints, plainFile);
//                            writeTextualCheckpoints(checkpoints, textFile);
//                        }catch(Exception e){
//
//                        }
//                    }
//                }
                if (height % params.getInterval() == 0 && block.getHeader().getTimeSeconds() <= timeAgo) {
                    System.out.println(String.format("Checkpointing block %s at height %d, time %s",
                            block.getHeader().getHash(), block.getHeight(), Utils.dateTimeFormat(block.getHeader().getTime())));
                    checkpoints.put(height, block);
                }
            }
        });
        System.out.println("peerGroup.getFastCatchupTimeSecs()="+Utils.dateTimeFormat(peerGroup.getFastCatchupTimeSecs()*1000));
//        peerGroup.setFastCatchupTimeSecs(1621395117L);
//        System.out.println("peerGroup.getFastCatchupTimeSecs()="+Utils.dateTimeFormat(peerGroup.getFastCatchupTimeSecs()*1000));
        System.out.println(String.format("before download: checkpoints.size()=%d" ,checkpoints.size()));
        peerGroup.downloadBlockChain();
        System.out.println(String.format("after download: checkpoints.size()=%d" ,checkpoints.size()));

        checkState(checkpoints.size() > 0);



        // Write checkpoint data out.
        writeBinaryCheckpoints(checkpoints, plainFile);
        writeTextualCheckpoints(checkpoints, textFile);

        peerGroup.stop();
        store.close();

        // Sanity check the created files.
        sanityCheck(plainFile, checkpoints.size());
        sanityCheck(textFile, checkpoints.size());
    }

    private static void writeBinaryCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws Exception {
        final FileOutputStream fileOutputStream = new FileOutputStream(file, false);
        MessageDigest digest = Sha256Hash.newDigest();
        final DigestOutputStream digestOutputStream = new DigestOutputStream(fileOutputStream, digest);
        digestOutputStream.on(false);
        final DataOutputStream dataOutputStream = new DataOutputStream(digestOutputStream);
        dataOutputStream.writeBytes("CHECKPOINTS 1");
        dataOutputStream.writeInt(0);  // Number of signatures to read. Do this later.
        digestOutputStream.on(true);
        dataOutputStream.writeInt(checkpoints.size());
        ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        for (StoredBlock block : checkpoints.values()) {
            block.serializeCompact(buffer);
            dataOutputStream.write(buffer.array());
            buffer.position(0);
        }
        dataOutputStream.close();
        Sha256Hash checkpointsHash = Sha256Hash.wrap(digest.digest());
        System.out.println("Hash of checkpoints data is " + checkpointsHash);
        digestOutputStream.close();
        fileOutputStream.close();
        System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    }

    private static void writeTextualCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.US_ASCII));
        writer.println("TXT CHECKPOINTS 1");
        writer.println("0"); // Number of signatures to read. Do this later.
        writer.println(checkpoints.size());
        ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        for (StoredBlock block : checkpoints.values()) {
            block.serializeCompact(buffer);
            writer.println(CheckpointManager.BASE64.encode(buffer.array()));
            buffer.position(0);
        }
        writer.close();
        System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    }

    private static void sanityCheck(File file, int expectedSize) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        CheckpointManager manager;
        try {
            manager = new CheckpointManager(params, fis);
        } finally {
            fis.close();
        }

        checkState(manager.numCheckpoints() == expectedSize);

        if (params.getId().equals(NetworkParameters.ID_MAINNET)) {
            StoredBlock test = manager.getCheckpointBefore(1390500000); // Thu Jan 23 19:00:00 CET 2014
            checkState(test.getHeight() == 280224);
            checkState(test.getHeader().getHashAsString()
                    .equals("00000000000000000b5d59a15f831e1c45cb688a4db6b0a60054d49a9997fa34"));
        } else if (params.getId().equals(NetworkParameters.ID_TESTNET)) {
            StoredBlock test = manager.getCheckpointBefore(1390500000); // Thu Jan 23 19:00:00 CET 2014
            checkState(test.getHeight() == 167328);
            checkState(test.getHeader().getHashAsString()
                    .equals("0000000000035ae7d5025c2538067fe7adb1cf5d5d9c31b024137d9090ed13a9"));
        }
    }

    private static void startPeerGroup(PeerGroup peerGroup, InetAddress ipAddress) {
        final PeerAddress peerAddress = new PeerAddress(params, ipAddress);
        System.out.println("Connecting to " + peerAddress + "...");
        peerGroup.addAddress(peerAddress);
        peerGroup.start();
    }
}

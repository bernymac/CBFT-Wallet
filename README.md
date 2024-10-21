<div align="center">

# CBFT-Wallet - a Confidential Byzantine Fault-Tolerant Wallet

</div>

## ⇁ Context
Hardware Security Modules (HSMs) and cryptographic wallets play a crucial role in enterprise environments by **safeguarding sensitive cryptographic keys** and **performing essential cryptographic operations**. However, these devices are _expensive and difficult to manage_, making them inaccessible to startups and small organisations. This work presents the development of a virtual and distributed HSM / Wallet that can be practically deployed in real-world environments while providing robust security guarantees comparable to those of physical solutions.

Our approach **leverages efficient protocols from the field of threshold cryptography**, specifically `distributed key generation`, `threshold signatures`, and `threshold symmetric encryption`, which are the key operations performed by hardware wallets and HSMs. By distributing trust among multiple parties and ensuring that no single entity has full control over cryptographic keys, our solution enhances security and resilience against breaches for a fraction of the cost of real HSMs. These protocols are implemented in a **Byzantine Fault-Tolerant State Machine Replication system**, making it tolerate to asynchrony, faults, and intrusions. None of these techniques were implemented by previous works that addressed the same problem.

Additionally, our system can **securely managing cryptocurrencies**, such as Bitcoin and Ethereum. This demonstrates the flexibility and applicability of our solution, namely in the growing field of digital finance, where it provides a secure alternative to managing digital assets.

## ⇁ Installation
* Install JDK 17;
* Make sure you have `unzip`, `cmake`, and `gcc` installed as well;
* Run the `build_relic.sh` script to install the RELIC library in the `/pairing` subdirectory, which our BLS signature implementation depends on, followed by the `build.sh` script to build the .so library;
* Next, in the project's root directory, run the command `./gradlew simpleLocalDeploy` to compile the project into a .jar file;

Now, everything is installed and ready to be tested!

## ⇁ Running the Project
To demonstrate how to run the project, we will use the setting of 4 servers, with 1 possible fault.

Inside the `/scripts` folder, use the `run.sh` to run the project as follows:
* `./run.sh wallet.server.ServerKt <server_id (0-3)>`
* `./run.sh wallet.client.ClientKt <operation> <client_id> ...`
* `./run.sh wallet.client.ThroughputLatencyEvaluationKt <operation> <client_id>`

Specifically, to test our project, you can use the `Client` class or the `ThroughputLatencyEvaluation` class, which was used to perform the experimental evaluation presented in the [/docs](./docs). We have developed a ClientAPI, which can be used via CLI through the following commands:
```text
wallet.client.ClientKt                   	keyGen           <client id> <index key id> <schnorr | bls | symmetric>
                                            sign             <client id> <index key id> <schnorr | bls> <data>
                                            enc              <client id> <index key id> <data>
                                            dec              <client id> <index key id> <ciphertext>
                                            getPk            <client id> <index key id> <schnorr | bls>
                                            valSign          <client id> <signature> <initial data>
                                            availableKeys    <client id>
                                            help
                                   
wallet.client.ThroughputLatencyEvaluationKt keyGen    <initial client id> <number of clients> <number of reps> <index key id> <schnorr | bls | symmetric>
                                            sign      <initial client id> <number of clients> <number of reps> <index key id> <schnorr | bls> <data>
                                            encDec    <initial client id> <number of clients> <number of reps> <index key id> <data>
                                            all       <initial client id> <number of clients> <number of reps>
```

### Example
The following commands demonstrate the usage of the operations of key generation, signature, and encryption/decryption.

First, initialize the required number of servers, in this case we are using 4:
```text
./run.sh wallet.server.ServerKt 0
./run.sh wallet.server.ServerKt 1
./run.sh wallet.server.ServerKt 2
./run.sh wallet.server.ServerKt 3
```

Then, execute the available operations using the client API:
```text
./run.sh wallet.client.ClientKt keyGen 1 myfirstblskeypair123 bls
./run.sh wallet.client.ClientKt keyGen 1 mysymmetrickeyid symmetric
./run.sh wallet.client.ClientKt sign 1 myfirstblskeypair123 bls SignThisUsefulMessagePlease
./run.sh wallet.client.ClientKt enc 1 mysymmetrickeyid VerySecretKey
./run.sh wallet.client.ClientKt dec 1 mysymmetrickeyid -5312fffa88a1fffffffefeffffffdfb248282d98fe761a0ed85f239dceb2ee5b7acb4b9c5ad61c292cfcd188d62f5affffffce00f866f24dd9eb10f2d48467e081c2c27d7753b4c4aa8b66c976f2eac99cb0dbba19f26fa32403df87da26fea8466cc6eb
```

##### NOTE: By default, the project is configured to work with 4 replicas, tolerating 1 fault; however, you can change these settings by changing the `host.config` file, adding more addresses, and the `system.config` file, changing the lines 66, 69, and 153 to your preferred values.

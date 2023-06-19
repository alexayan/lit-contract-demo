import * as LitJsSdk from "@lit-protocol/lit-node-client-nodejs";
import * as u8a from "uint8arrays";
import ethers from "ethers";
import { SiweMessage } from "lit-siwe";
import {
  newSessionCapabilityObject,
  LitAccessControlConditionResource,
  LitAbility,
} from "@lit-protocol/auth-helpers";

const CHAIN_ID = 80001;
const CHAIN = "mumbai";

const signAuthMessage = async (resources) => {
  // Replace this with you private key
  const privKey =
    "3dfb4f70b15b6fccc786347aaea445f439a7f10fd10c55dd50cafc3d5a0abac1";
  const privKeyBuffer = u8a.fromString(privKey, "base16");
  const wallet = new ethers.Wallet(privKeyBuffer);

  const domain = "localhost";
  const origin = "https://localhost/login";
  const statement =
    "This is a test statement.  You can put anything you want here.";

  const expiration = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

  console.log("walet address", wallet.address);

  const message = {
    domain,
    address: wallet.address,
    uri: origin,
    version: "1",
    chainId: CHAIN_ID,
    expirationTime: expiration,
  };

  if (resources) {
    message.resources = resources;
  }

  const siweMessage = new SiweMessage(message);

  const messageToSign = siweMessage.prepareMessage();

  const signature = await wallet.signMessage(messageToSign);

  console.log("signature", signature);

  const recoveredAddress = ethers.utils.verifyMessage(messageToSign, signature);
  console.log("recoveredAddress", recoveredAddress);

  const authSig = {
    sig: signature,
    derivedVia: "web3.eth.personal.sign",
    signedMessage: messageToSign,
    address: recoveredAddress,
  };

  return authSig;
};

async function main() {
  const litNodeClient = new LitJsSdk.LitNodeClientNodeJs();
  await litNodeClient.connect();
  const messageToEncrypt = "Lit is 🔥";

  let authSig = await signAuthMessage();

  const evmContractConditions = [
    {
      contractAddress: "0x42e3dD0Cc7957dDc04aF14A44aD29d30a25F7d64",
      functionName: "authorizedIssuers",
      functionParams: [":litParam:addr"],
      functionAbi: {
        inputs: [
          {
            internalType: "address",
            name: "addr",
            type: "address",
          },
        ],
        name: "authorizedIssuers",
        outputs: [
          {
            internalType: "bool",
            name: "",
            type: "bool",
          },
        ],
        stateMutability: "view",
        type: "function",
      },
      chain: CHAIN,
      returnValueTest: {
        key: "",
        comparator: "=",
        value: "true",
      },
    },
  ];

  const { encryptedString, symmetricKey } = await LitJsSdk.encryptString(
    messageToEncrypt
  );

  // 2. Saving the Encrypted Content to the Lit Nodes
  // <Unit8Array> encryptedSymmetricKey
  const encryptedSymmetricKey = await litNodeClient.saveEncryptionKey({
    evmContractConditions,
    symmetricKey,
    authSig,
    chain: CHAIN,
    permanent: 0,
  });

  const toDecrypt = LitJsSdk.uint8arrayToString(
    encryptedSymmetricKey,
    "base16"
  );

  const contractParamData = "0x0f97C506B7c3E38e487BDd5C9F381514E1f21eb9";
  const sessionCapabilityObject = newSessionCapabilityObject();
  const resource = `litParam:addr:${LitJsSdk.uint8arrayToString(
    LitJsSdk.uint8arrayFromString(contractParamData, "utf8"),
    "base64urlpad"
  )}`;
  const litResource = new LitAccessControlConditionResource(
    `litParam:addr:${resource}`
  );
  sessionCapabilityObject.addCapabilityForResource(
    litResource,
    LitAbility.AccessControlConditionDecryption
  );

  authSig = await signAuthMessage([
    sessionCapabilityObject.encodeAsSiweResource(),
  ]);

  const _symmetricKey = await litNodeClient.getEncryptionKey({
    evmContractConditions,
    toDecrypt,
    chain: CHAIN,
    authSig,
  });

  let decryptedString;

  try {
    decryptedString = await LitJsSdk.decryptString(
      encryptedString,
      _symmetricKey
    );
  } catch (e) {
    console.log(e);
  }

  console.warn("decryptedString:", decryptedString);
}

main();

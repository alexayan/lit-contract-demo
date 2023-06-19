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

function rmOx(str) {
  return str.replace(/^0x/, "");
}

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
      contractAddress: "0xC10Ae43129192D15A0a30Dcab487Ed0428AAc5FE",
      functionName: "canDecrypt",
      functionParams: [
        ":litParam:scene",
        ":litParam:user",
        ":litParam:requestor",
        ":litParam:uuids",
        ":litParam:signature",
      ],
      functionAbi: {
        inputs: [
          {
            internalType: "string",
            name: "scene",
            type: "string",
          },
          {
            internalType: "address",
            name: "user",
            type: "address",
          },
          {
            internalType: "address",
            name: "requestor",
            type: "address",
          },
          {
            internalType: "uint256[]",
            name: "uuids",
            type: "uint256[]",
          },
          {
            internalType: "bytes",
            name: "signature",
            type: "bytes",
          },
        ],
        name: "canDecrypt",
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
      chain: "mumbai",
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

  const user = "0x31C5bd64D62cca56aA3A5e8486c7d9103EfFb5Fc";
  const uuids = [
    "9902652726180147746430150263113238388949401383732865956487362701780228133241",
    "102286496491116273792549272839046822105423891360175458581979267554964815629946",
  ];
  const requestor = "0x4c79B28335723E158b8F02b7E3191Aa570B2ED91";
  const signature =
    "0xa8c09432d1d31c77177675c4c781805ca2a1b818ffc0356fa789028190fab73700d676ce77fcebeb70a5268bdb6d04808a69c1dcbeedd9f97e3d925bd2c8e88d1b";

  const uuidStr = uuids
    .map((str) => {
      return rmOx(str);
    })
    .join(",");

  authSig = await signAuthMessage([
    `litParam:scene:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx("project"), "utf8"),
      "base64urlpad"
    )}`,
    `litParam:user:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx(user), "utf8"),
      "base64urlpad"
    )}`,
    `litParam:requestor:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx(requestor), "utf8"),
      "base64urlpad"
    )}`,
    `litParam:uuids:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(`[${uuidStr}]`, "utf8"),
      "base64urlpad"
    )}`,
    `litParam:signature:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx(signature), "utf8"),
      "base64urlpad"
    )}`,
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

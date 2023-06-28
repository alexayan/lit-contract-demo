import * as LitJsSdk from "@lit-protocol/lit-node-client-nodejs";
import * as u8a from "uint8arrays";
import ethers from "ethers";
import { SiweMessage } from "lit-siwe";
import {
  newSessionCapabilityObject,
  LitAccessControlConditionResource,
  LitAbility,
} from "@lit-protocol/auth-helpers";

const CHAIN_ID = 324;
const CHAIN = "zksync";

function rmOx(str) {
  console.log("str", str);
  return str.replace(/^0x/, "");
}

const signAuthMessage = async (resources) => {
  // Replace this with you private key
  const privKey =
    "ae53275d9b77fe2615f7cb49779d80748f065a62eaa0a3376d462f1650077829";
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

async function test() {
  const litNodeClient = new LitJsSdk.LitNodeClientNodeJs({
    litNetwork: "jalapeno",
  });
  await litNodeClient.connect();
  const messageToEncrypt = "Lit is 🔥";
  let authSig = await signAuthMessage();

  const accessControlConditions = [
    {
      contractAddress: "0x112E5059a4742ad8b2baF9C453fDA8695c200454",
      standardContractType: "ERC721",
      chain: CHAIN,
      method: "balanceOf",
      parameters: ["0x2c11613DC6668fc000b31d8fDf9588a60053B6cc"],
      returnValueTest: {
        comparator: ">",
        value: "0",
      },
    },
  ];

  const { encryptedString, symmetricKey } = await LitJsSdk.encryptString(
    messageToEncrypt
  );

  // <Unit8Array> encryptedSymmetricKey
  const encryptedSymmetricKey = await litNodeClient.saveEncryptionKey({
    accessControlConditions,
    symmetricKey,
    authSig,
    chain: CHAIN,
    permanent: 0,
  });

  const toDecrypt = LitJsSdk.uint8arrayToString(
    encryptedSymmetricKey,
    "base16"
  );

  const _symmetricKey = await litNodeClient.getEncryptionKey({
    accessControlConditions,
    toDecrypt,
    chain: CHAIN,
    authSig,
  });

  console.log("_symmetricKey", _symmetricKey);
}

async function main() {
  const litNodeClient = new LitJsSdk.LitNodeClientNodeJs({
    litNetwork: "serrano",
  });
  await litNodeClient.connect();
  const messageToEncrypt = "Lit is 🔥";

  let authSig = await signAuthMessage();

  const evmContractConditions = [
    {
      contractAddress: "0x72d7DcC557902A48EE0289eEf8c5E3Fd8A167e10",
      functionName: "checkDecrypt",
      functionParams: [
        ":litParam:sceneIndex",
        ":litParam:user",
        ":userAddress",
        ":litParam:uuids",
        ":litParam:signature",
        ":litParam:args1",
        ":litParam:args2",
      ],
      functionAbi: {
        inputs: [
          {
            internalType: "uint256",
            name: "sceneIndex",
            type: "uint256",
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
          {
            internalType: "bytes[]",
            name: "args1",
            type: "bytes[]",
          },
          {
            internalType: "bytes[]",
            name: "args2",
            type: "bytes[]",
          },
        ],
        name: "checkDecrypt",
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

  // const { encryptedString, symmetricKey } = await LitJsSdk.encryptString(
  //   messageToEncrypt
  // );

  // 2. Saving the Encrypted Content to the Lit Nodes
  // // <Unit8Array> encryptedSymmetricKey
  // const encryptedSymmetricKey = await litNodeClient.saveEncryptionKey({
  //   evmContractConditions,
  //   symmetricKey,
  //   authSig,
  //   chain: CHAIN,
  //   permanent: 0,
  // });

  // const toDecrypt = LitJsSdk.uint8arrayToString(
  //   encryptedSymmetricKey,
  //   "base16"
  // );

  // const toDecrypt =
  //   "954884e1dc75e31bcdc73d42b0dfd1e35ec68fcfd74373d343b1979a3c181caeb142d01b6db4bad18608b3c67fb0881941ee0ada4b8a80e433a951727859e0985b44a7be84040442795964cd78178d9bc1ab600cf3daed7c01ace37b5a864aabcf0d0174f0bc770197b1771e89709c534ae66b320c2fecd570f71542cb2be60a000000000000002031e1feefce84fcf0c774d8d7f390a9ae30a82802d80fd85e842b5dcc57ae50d87af5b96a4654f88c387c4e9b73e0ee86";

  // console.log("toDecrypt", toDecrypt);

  const user = "0x2c11613DC6668fc000b31d8fDf9588a60053B6cc";
  const uuids = [
    "75682235775716889169053958985018289655377006682129274549968445093521439609384",
    "93233475074686709017445900781235473934510624688497742929719674483975924837873",
  ];
  // const requestor = "0x4c79B28335723E158b8F02b7E3191Aa570B2ED91";
  // const signature =
  //   "0x923b0161c68ead0e28efeff7e51da7ff31dedabd11ef827960bd5847b31c7987564444d61b4d907b6553d8f1cc45062360d64ea88ee58101fa8d0bcfa20c0a981c";

  const uuidStr = uuids
    .sort()
    .map((str) => {
      return rmOx(str);
    })
    .join(",");

  console.log("uuidStr", uuidStr);

  // const signature =
  //   "0x62c974e0ec01717d42e7b70bee9edf35db69acc01060524963ad6ec0f4bdc56b03e42bbe51022c7a78f47e7f311a0fb754f87e23e311a5f641dc63b9d0975df91b";
  const signature =
    "0xc019f6989de6652a450f227e5cc36c44d0617bba2c98cfda7055cc3e1699d35278c7c5c5eb12cac0be23519595817dff7c246982ec16a7f51165292e47dbaf0b1c";
  authSig = await signAuthMessage([
    `litParam:sceneIndex:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString("1", "utf8"),
      "base64urlpad"
    )}`,
    `litParam:user:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx(user), "utf8"),
      "base64urlpad"
    )}`,
    // `litParam:requestor:${LitJsSdk.uint8arrayToString(
    //   LitJsSdk.uint8arrayFromString(rmOx(requestor), "utf8"),
    //   "base64urlpad"
    // )}`,
    `litParam:uuids:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(`[${uuidStr}]`, "utf8"),
      "base64urlpad"
    )}`,
    `litParam:signature:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx(signature), "utf8"),
      "base64urlpad"
    )}`,
    `litParam:args1:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString("[]", "utf8"),
      "base64urlpad"
    )}`,
    `litParam:args2:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString("[]", "utf8"),
      "base64urlpad"
    )}`,
  ]);

  console.log("authSig", authSig);

  const _symmetricKey = await litNodeClient.getEncryptionKey({
    evmContractConditions,
    toDecrypt:
      "0672507b482017ca5d0a7a4e0b6134b51b6c21d44cfd43c17abdb82bae8ec0659b7ee1ea63f7baee01456d203d951b1921393a1e7efbc80f970178df65802987388f92da29e62509992210605c4dd8012e6831197d90b77c348c3ae3236fca95158761fd2c96b752f81b8c3345adc245e9d913146bd3a6464295d6a65b029e2c000000000000002046f2ffff9b24547d7da2faf689d0f9059d22a80af4842f6f58397cf2b5d15d808286d02e25824d8b5912112e29fbcf87",
    chain: CHAIN,
    authSig,
  });

  let decryptedString;

  // try {
  //   decryptedString = await LitJsSdk.decryptString(
  //     encryptedString,
  //     _symmetricKey
  //   );
  // } catch (e) {
  //   console.log(e);
  // }

  // console.warn("decryptedString:", decryptedString);
}

test();

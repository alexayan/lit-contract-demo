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

const getWallet = () => {
  const privKey =
    "03fc1e1d4a0db3ee7254ca41e6f1a4305d878f34c986b8ca8eab089653d68bf8";
  const privKeyBuffer = u8a.fromString(privKey, "base16");
  const wallet = new ethers.Wallet(privKeyBuffer);
  return wallet;
};

const signAuthMessage = async (resources) => {
  const wallet = getWallet();

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

export function projectMessageHash(user, uuids, requestor, nonce) {
  const message = ethers.utils.defaultAbiCoder.encode(
    ["address", "address", "uint256[]", "uint256"],
    [user, requestor, uuids.sort(), nonce]
  );
  const hash = ethers.utils.keccak256(message);
  return hash;
}

async function main() {
  const symmetricKey = "";
  const user = "0x2c11613DC6668fc000b31d8fDf9588a60053B6cc";
  const requestor = "";
  const uuids = [
    "75682235775716889169053958985018289655377006682129274549968445093521439609384",
    "93233475074686709017445900781235473934510624688497742929719674483975924837873",
  ];
  const msgHash = projectMessageHash(user, uuids, requestor, 0);
  const wallet = getWallet();
  const signature = await wallet.signMessage({
    message: ethers.utils.arrayify(msgHash),
  });
  const litNodeClient = new LitJsSdk.LitNodeClientNodeJs({
    litNetwork: "jalapeno",
  });
  await litNodeClient.connect();
  const messageToEncrypt = "Lit is 🔥";

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

  const uuidStr = uuids
    .sort()
    .map((str) => {
      return rmOx(str);
    })
    .join(",");

  console.log("uuidStr", uuidStr);

  const authSig = await signAuthMessage([
    `litParam:sceneIndex:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString("1", "utf8"),
      "base64urlpad"
    )}`,
    `litParam:user:${LitJsSdk.uint8arrayToString(
      LitJsSdk.uint8arrayFromString(rmOx(user), "utf8"),
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
    toDecrypt: symmetricKey,
    chain: CHAIN,
    authSig,
  });
}

test();

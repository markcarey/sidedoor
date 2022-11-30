var functions = require('firebase-functions');
var firebase = require('firebase-admin');
var storage = firebase.storage();
const bucket = storage.bucket("sidedoor");
var db = firebase.firestore();

const express = require("express");
const api = express();

const fetch = require('node-fetch');

var imageDataURI = require("image-data-uri");
var textToImage = require("text-to-image");
var text2png = require('text2png');
var sigUtil = require("eth-sig-util");

const { ethers } = require("ethers");
const { nextTick } = require('async');

var uniqid = require('uniqid');
var notp = require('notp');
var base32 = require('thirty-two');
var QRCode = require('qrcode');

var Mailgen = require('mailgen');
var postmark = require("postmark");

const safeCoreSDK = require('@gnosis.pm/safe-core-sdk');
const Safe = safeCoreSDK.default;
const SafeFactory = safeCoreSDK.SafeFactory;

const safeEthersLib = require('@gnosis.pm/safe-ethers-lib');
const { getAccountPath } = require('ethers/lib/utils');
const EthersAdapter = safeEthersLib.default;

const TV_FACTORY = process.env.TV_FACTORY_GOERLI;
const API_URL_MUMBAI = process.env.API_URL_MUMBAI;
const API_URL_GOERLI = process.env.API_URL_GOERLI;

const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

var providers = [];
providers[0] = new ethers.providers.JsonRpcProvider({"url": API_URL_GOERLI});

const vestorJSON = require(__base + 'sidedoor/abis/TokenVestor.json');
const vestorFactoryJSON = require(__base + 'sidedoor/abis/VestingFactory.json');
const tokenJSON = require(__base + 'sidedoor/abis/IERC20.json');

var signer, vestorFactory;

const gasOptions = {"maxPriorityFeePerGas": "45000000000", "maxFeePerGas": "45000000016" };

function getContracts(pk, provider) {
  signer = new ethers.Wallet(pk, provider);
  vestorFactory = new ethers.Contract(
    TV_FACTORY,
    vestorFactoryJSON.abi,
    signer
  );
}

async function otp() {
  const key = "just testing for now";
  var encoded = base32.encode(key);
  var encodedForGoogle = encoded.toString().replace(/=/g,'');
  var uri = 'otpauth://totp/Sidedoor:bob@sak.com?issuer=Sidedoor&label=Sidedoor&secret=' + encodedForGoogle;
  var qr = await QRCode.toDataURL(encodeURIComponent(uri));
  console.log("otp qr", qr);
  return notp.totp.gen(key);
}

function getParams(req, res, next) {
  var params;
  if (req.method === 'POST') {
    params = req.body;
  } else {
    params = req.query;
  }
  req.q = params;
  next();
}

async function getAuth(req, res, next) {
  req.user = null;
  var apiKey = null;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    console.log('Found "Authorization" header');
    // Read the API key from the Authorization header.
    apiKey = req.headers.authorization.split('Bearer ')[1];
  } else {
    //console.log(req.q);
    if ("api_key" in req.q) {
      apiKey = req.q.api_key;  // TODO: disable api keys in url params for production?
    }
  } // if req.headers
  if (apiKey) {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('key', '==', apiKey).get();
    if (snapshot.empty) {
      return res.status(403).send('');
    }  
    snapshot.forEach(user => {
      req.user = user.data();
    });
  }
  // TODO: logging API usage by key
  next();
}

async function checkOTP(req, res, next) {
  var valid = notp.totp.verify(req.q.otp, req.user.secret);
  if (!valid) {
    return res.json({"result": "error", "error": "invalid or missing one-time password"});
  }
  next();
}

function flowToObject(f) {
  var flow = {
      "cliffEnd": f.cliffEnd,
      "flowRate": f.flowRate,
      "permanent": f.permanent,
      "recipient": f.recipient,
      "starttime": f.starttime,
      "state": f.state,
      "vestingDuration": f.vestingDuration,
      "ref": f.ref
  };
  return flow;
}

function hasContract(user, contractAddress) {
  var allowed = false;
  if ("contracts" in user) {
    allowed = user.contracts.includes(contractAddress);
  } 
  return allowed;
}

function cors(req, res, next) {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') {
    // Send response to OPTIONS requests
    res.set('Access-Control-Allow-Methods', 'GET, POST');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '3600');
    return res.status(204).send('');
  } else {
    // Set CORS headers for the main request
    res.set('Access-Control-Allow-Origin', '*');
  }
  next();
}

api.use(cors);
//api.use(getAuth);
api.use(getParams);

api.get("/", async function (req, res) {
  return res.json({"what": "sidedoor.tools", "why": "helping bring users into web3 through the sidedoor"});
});

api.get("/auth/user/new", async function (req, res) {
  const email = req.q.email;
  const address = req.q.address;
  if (!email || !address) {
    return res.json({ "result": "error", "error": "email and address required"});
  }
  const userRef = db.collection('users').doc(address);
  const user = await userRef.get();
  if (user.exists) {
    return res.json({ "result": "error", "error": "user already exists"});
  }
  const secret = uniqid();
  var data = {
    "address": address,
    "email": email,
    "secret": secret
  };
  await db.collection('users').doc(address).set(data);
  const otp = notp.totp.gen(secret);
  // send email verification
  var pmEmail = {
    "From": "auth@sidedoor.tools",
    "To": email,
    "Subject": "Verify your email address",
    "TextBody": `Please enter this code to verify your email: ${otp}`
  };
  var mailer = new postmark.ServerClient(process.env.POSTMARK_TOKEN);
  var response = await mailer.sendEmail(pmEmail);
  return res.json({ "result": "ok", "message": "user created, email verififcation sent"});
}); // /auth/user/new

api.get("/auth/qrcode", getAuth, async function (req, res) {
  if (!req.user) {
    res.json({"result": "error", "error": "unknown address" });
  }
  const user = req.user;
  const key = user.secret;
  if (!key) {
    res.json({"result": "error", "error": "no api key, please verify email first" });
  }
  var encoded = base32.encode(key);
  var encodedForGoogle = encoded.toString().replace(/=/g,'');
  var uri = `otpauth://totp/Sidedoor:${user.email}?issuer=Sidedoor&label=Sidedoor&secret=${encodedForGoogle}`;
  var qr = await QRCode.toDataURL(encodeURIComponent(uri));
  if (req.q.format == "image") {
    var base64Data = qr.replace(/^data:image\/png;base64,/, '');
    var img = Buffer.from(base64Data, 'base64');
    res.writeHead(200, {
      'Content-Type': 'image/png',
      'Content-Length': img.length
    });
    return res.end(img);
  } else {
    return res.json({"result": "ok", "qrcode": qr, "uri": uri, "base32": encodedForGoogle, "message": "scan QR code in authenctaior app"});
  }
}); // /auth/qrcode

api.get("/auth/check", async function (req, res) {
  const address = req.q.address;
  const userRef = db.collection('users').doc(address);
  const user = await userRef.get();
  if (!user.exists) {
    res.json({"result": "error", "error": "unknown address" });
  }
  const key = user.data().secret;
  var valid = notp.totp.verify(req.q.otp, key);
  console.log("valid decoded", valid);
  if ( valid ) {
    if ( user.data().key ) {
      return res.json({"result": "ok", "key": user.data().key});
    } else {
      const apiKey = uniqid();
      const result = await userRef.set({
        "key": apiKey
      }, { merge: true });
      return res.json({"result": "ok", "key": apiKey, "message": "this is your api-key to use for Bearer auth"});
    }
  } else {
    return res.json({"result": "error", "error": "otp code not verified"});
  }
}); // /auth/check

api.get("/wallets/safe/new", getAuth, async function (req, res) {
  getContracts(process.env.ALLOWER_PK, providers[0]);
  const ethAdapter = new EthersAdapter({
    ethers,
    "signer": signer
  });
  const safeFactory = await SafeFactory.create({ ethAdapter });
  var owners = [process.env.SIDEDOOR_HOT, process.env.SIDEDOOR_COLD];
  if (req.user) {
    if ("address" in req.user) {
      owners.push(req.user.address);
    }
  }
  const threshold = 1;
  const safeAccountConfig = {
    owners,
    threshold
  };
  const mySafe = await safeFactory.deploySafe({ safeAccountConfig });
  const newSafeAddress = mySafe.getAddress();
  return res.json({"result": "ok", "address": newSafeAddress, "message": "new Gnosis Safe wallet created at this address"});
}); // /wallets/safe/new

api.get("/streams/vestor/new", getAuth, checkOTP, async function (req, res) {
  getContracts(process.env.ALLOWER_PK, providers[0]);
  //const tokenAddress = "0xF2d68898557cCb2Cf4C10c3Ef2B034b2a69DAD00";  // fDAIx on Goerli
  const host = "0x22ff293e14F1EC3A09B137e9e06084AFd63adDF9"; // superfluid host Goerli
  const cfa = "0xEd6BcbF6907D4feEEe8a8875543249bEa9D308E8"; // superfluid cfa Goerli
  const tokenAddress = req.q.token; // superToken address
  await (await vestorFactory.createVestor(tokenAddress, host, cfa)).wait();
  // TODO: add user address as MANAGER role on Vestor
  const vestors = await vestorFactory.getAllVestors();
  const vestorAddress = vestors[vestors.length -1];
  console.log(vestorAddress);
  var contracts = [];
  if ( "contracts" in req.user ) {
    contracts = req.user.contracts;
  }
  contracts.push(vestorAddress);
  const userRef = db.collection('users').doc(req.user.address);
  const result = await userRef.set({
    "contracts": contracts
  }, { merge: true });
  return res.json({"result": "ok", "address": vestorAddress, "message": "address for new Vestor contract to manage streams"});
}); // /streams/vestor/new

api.get("/streams/vestor/deposit", getAuth, checkOTP, async function (req, res) {
  getContracts(process.env.ALLOWER_PK, providers[0]);
  const userContract = hasContract(req.user, req.q.vestor);
  if (!userContract) {
    return res.json({"result": "error", "message": "user does not have permission to this vestor contract"});
  }
  const vestor = new ethers.Contract(
    req.q.vestor,
    vestorJSON.abi,
    signer
  );
  //const tokenAddress = "0x88271d333C72e51516B67f5567c728E702b3eeE8"; // fDAI on Goerli
  const tokenAddress = req.q.token; // underlying (not Super) token address
  const token = new ethers.Contract(
    tokenAddress,
    tokenJSON.abi,
    signer
  );
  // TODO: check that user has permission to depoit this amount from Sidedoor EOA
  await token.approve(req.q.vestor, req.q.amount);
  console.log(tokenAddress, req.q.amount, req.q.vestor);
  await vestor.deposit(tokenAddress, req.q.amount);
  return res.json({"result": "ok", "message": "deposit successful and upgraded to Super token"});
}); // /streams/vestor/deposit

api.get("/streams/flow/new", getAuth, checkOTP, async function (req, res) {
  getContracts(process.env.ALLOWER_PK, providers[0]);
  const userContract = hasContract(req.user, req.q.vestor);
  if (!userContract) {
    return res.json({"result": "error", "message": "user does not have permission to this vestor contract"});
  }
  const vestor = new ethers.Contract(
    req.q.vestor,
    vestorJSON.abi,
    signer
  );
  await (await vestor.registerFlow(req.q.recipient, req.q.flowrate, false, req.q.start, req.q.duration, req.q.lumpsum, ethers.utils.formatBytes32String(req.q.ref))).wait();
  const flows = await vestor.getFlowRecipient(req.q.recipient);
  return res.json({"result": "ok", "flow": flowToObject(flows[0]), "message": "flow has been added"});
}); // /streams/flow/new

api.get("/streams/flow/replace", getAuth, checkOTP, async function (req, res) {
  getContracts(process.env.ALLOWER_PK, providers[0]);
  const userContract = hasContract(req.user, req.q.vestor);
  if (!userContract) {
    return res.json({"result": "error", "message": "user does not have permission to this vestor contract"});
  }
  const vestor = new ethers.Contract(
    req.q.vestor,
    vestorJSON.abi,
    signer
  );
  var flows = await vestor.getFlowRecipient(req.q.recipient);
  var flow = {};
  if (flows.length > 0) {
    for (let i = 0; i < flows.length; i++) {
      var f = flowToObject(flows[i]);
      f.flowIndex = i;
      //console.log("f", f);
      if ( f.ref == ethers.utils.formatBytes32String(req.q.ref) ){
        flow = f;
      }
    }
  }
  //console.log("flow", flow);
  if (flow) {
    await (await vestor.closeStream(req.q.recipient, flow.flowIndex)).wait();
  }
  await (await vestor.registerFlow(req.q.recipient, req.q.flowrate, false, req.q.start, req.q.duration, req.q.lumpsum, ethers.utils.formatBytes32String(req.q.ref))).wait();
  flows = await vestor.getFlowRecipient(req.q.recipient);
  return res.json({"result": "ok", "flow": flowToObject(flows[flows.length -1]), "message": "flow replaced"});
}); // /streams/flow/replace

api.get("/streams/flow/stop", getAuth, checkOTP, async function (req, res) {
  getContracts(process.env.ALLOWER_PK, providers[0]);
  const userContract = hasContract(req.user, req.q.vestor);
  if (!userContract) {
    return res.json({"result": "error", "message": "user does not have permission to this vestor contract"});
  }
  const vestor = new ethers.Contract(
    req.q.vestor,
    vestorJSON.abi,
    signer
  );
  var flows = await vestor.getFlowRecipient(req.q.recipient);
  var flow = {};
  if (flows.length > 0) {
    for (let i = 0; i < flows.length; i++) {
      var f = flowToObject(flows[i]);
      f.flowIndex = i;
      //console.log("f", f);
      if ( f.ref == ethers.utils.formatBytes32String(req.q.ref) ){
        flow = f;
      }
    }
  }
  //console.log("flow", flow);
  var name = "";
  if (flow) {
    name = ethers.utils.parseBytes32String(flow.ref);
    //console.log("name", name);
    await (await vestor.closeStream(req.q.recipient, flow.flowIndex)).wait();
  }
  return res.json({"result": "ok", "message": `flow ${name} stopped`});
}); // /streams/flow/stop

module.exports.api = api;
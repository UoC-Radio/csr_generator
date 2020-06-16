import * as asn1js from "asn1js";
import { arrayBufferToString, toBase64 } from "pvutils";
import { getCrypto, getAlgorithmParameters, setEngine } from "pkijs/src/common.js";
import CertificationRequest from "pkijs/src/CertificationRequest.js";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue.js";


/***************\
* CSR GENERATOR *
\***************/

/*
 * This is basically a cleaned-up version of PKI.js's PKCS10 example
 */

/*********\
* HELPERS *
\*********/

function formatPEM(pemString)
{
	/// <summary>Format string in order to have each line with length equal to 64</summary>
	/// <param name="pemString" type="String">String to format</param>
	
	const stringLength = pemString.length;
	let resultString = "";
	
	for(let i = 0, count = 0; i < stringLength; i++, count++)
	{
		if(count > 63)
		{
			resultString = `${resultString}\r\n`;
			count = 0;
		}
		
		resultString = `${resultString}${pemString[i]}`;
	}
	
	return resultString;
}


/*************\
* ENTRY POINT *
\*************/

function createPKCS10()
{
	//Initialize variables
	let sequence = Promise.resolve();

	const hashAlg = "SHA-256";
	const signAlg = "ECDSA";
	
	const pkcs10 = new CertificationRequest();
	
	let publicKey;
	let privateKey;
	
	//Get a "crypto" extension
	const crypto = getCrypto();
	if(typeof crypto === "undefined")
		return Promise.reject("No WebCrypto extension found");
	
	//Put a static CN, the backend ignores it anyway
	pkcs10.version = 0;
	pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3",
		value: new asn1js.PrintableString({ value: "user" })
	}));
	
	pkcs10.attributes = [];
	
	//Create a new key pair
	sequence = sequence.then(() =>
		{
			//Get default algorithm parameters for key generation
			const algorithm = getAlgorithmParameters(signAlg, "generatekey");
			if("hash" in algorithm.algorithm)
				algorithm.algorithm.hash.name = hashAlg;
			
			return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
		}
	);
	
	//Store new key in an interim variables
	sequence = sequence.then(keyPair =>
		{
			publicKey = keyPair.publicKey;
			privateKey = keyPair.privateKey;
		},
		error => Promise.reject(`Error during key generation: ${error}`)
	);
	
	//Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
	sequence = sequence.then(() => 
		{
			return pkcs10.subjectPublicKeyInfo.importKey(publicKey);
		},
		error => Promise.reject(`Error during exporting public key: ${error}`)
	);
		
	//Signing final PKCS#10 request
	sequence = sequence.then(() =>
		{
			return pkcs10.sign(privateKey, hashAlg);
		},
		error => Promise.reject(`Error while signing CSR: ${error}`)
	);

	//Put signed CSR to the text area
	sequence = sequence.then(() =>
		{
			let pkcs10Buffer = pkcs10.toSchema().toBER(false);
			let csrString = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
			csrString = `${csrString}${formatPEM(toBase64(arrayBufferToString(pkcs10Buffer)))}`;
			csrString = `${csrString}\r\n-----END CERTIFICATE REQUEST-----\r\n`;
			document.getElementById("pem-csr-block").value = csrString;
		
		},
		error => Promise.reject(`Error while formating CSR: ${error}`)
	);

	//Convert private key to PKCS8 format
	sequence = sequence.then(() =>
		{
			return crypto.exportKey("pkcs8", privateKey);
		},
		error => Promise.reject(`Error exporting private key to PKCS8 format: ${error}`)
	);

	//Format private key and put it to the text area
	return sequence.then(result =>
		{
			let tmp = String.fromCharCode.apply(null, new Uint8Array(result));
			let privKeyString = "-----BEGIN PRIVATE KEY-----\r\n";
			privKeyString = `${privKeyString}${formatPEM(toBase64(tmp))}`;
			privKeyString = `${privKeyString}\r\n-----END PRIVATE KEY-----\r\n`;
			document.getElementById("pem-pkey-block").value = privKeyString;
		},
		error => Promise.reject(`Error while formating private key: ${error}`)
	);
}
context("Hack for Rollup.js", () =>
{
	return;
	
	createPKCS10();
	setEngine();
});


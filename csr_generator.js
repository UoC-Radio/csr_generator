//**************************************************************************************
/**
 * Get value for input parameters, or set a default value
 * @param {Object} parameters
 * @param {string} name
 * @param defaultValue
 */
function getParametersValue(parameters, name, defaultValue)
{
	if((parameters instanceof Object) === false)
		return defaultValue;
	
	if(name in parameters)
		return parameters[name];
	
	return defaultValue;
}
//**************************************************************************************
/**
 * Converts "ArrayBuffer" into a hexdecimal string
 * @param {ArrayBuffer} inputBuffer
 * @param {number} [inputOffset=0]
 * @param {number} [inputLength=inputBuffer.byteLength]
 * @returns {string}
 */
function bufferToHexCodes(inputBuffer, inputOffset = 0, inputLength = inputBuffer.byteLength)
{
	let result = "";
	
	for(const item of (new Uint8Array(inputBuffer, inputOffset, inputLength)))
	{
		const str = item.toString(16).toUpperCase();
		result = result + ((str.length === 1) ? "0" : "") + str;
	}
	
	return result;
}
//**************************************************************************************
/**
 * Check input "ArrayBuffer" for common functions
 * @param {LocalBaseBlock} baseBlock
 * @param {ArrayBuffer} inputBuffer
 * @param {number} inputOffset
 * @param {number} inputLength
 * @returns {boolean}
 */
function checkBufferParams(baseBlock, inputBuffer, inputOffset, inputLength)
{
	if((inputBuffer instanceof ArrayBuffer) === false)
	{
		baseBlock.error = "Wrong parameter: inputBuffer must be \"ArrayBuffer\"";
		return false;
	}
	
	if(inputBuffer.byteLength === 0)
	{
		baseBlock.error = "Wrong parameter: inputBuffer has zero length";
		return false;
	}
	
	if(inputOffset < 0)
	{
		baseBlock.error = "Wrong parameter: inputOffset less than zero";
		return false;
	}
	
	if(inputLength < 0)
	{
		baseBlock.error = "Wrong parameter: inputLength less than zero";
		return false;
	}
	
	if((inputBuffer.byteLength - inputOffset - inputLength) < 0)
	{
		baseBlock.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";
		return false;
	}
	
	return true;
}
//**************************************************************************************
/**
 * Convert number from 2^base to 2^10
 * @param {Uint8Array} inputBuffer
 * @param {number} inputBase
 * @returns {number}
 */
function utilFromBase(inputBuffer, inputBase)
{
	let result = 0;
	
	for(let i = (inputBuffer.length - 1); i >= 0; i--)
		result += inputBuffer[(inputBuffer.length - 1) - i] * Math.pow(2, inputBase * i);
	
	return result;
}
//**************************************************************************************
/**
 * Convert number from 2^10 to 2^base
 * @param {!number} value The number to convert
 * @param {!number} base The base for 2^base
 * @param {number} [reserved=0] Pre-defined number of bytes in output array (-1 = limited by function itself)
 * @returns {ArrayBuffer}
 */
function utilToBase(value, base, reserved = 0)
{
	const internalReserved = reserved || (-1);
	let internalValue = value;
	
	let result = 0;
	let biggest = Math.pow(2, base);
	
	for(let i = 1; i < 8; i++)
	{
		if(value < biggest)
		{
			let retBuf;
			
			if(internalReserved < 0)
			{
				retBuf = new ArrayBuffer(i);
				result = i;
			}
			else
			{
				if(internalReserved < i)
					return (new ArrayBuffer(0));
				
				retBuf = new ArrayBuffer(internalReserved);
				
				result = internalReserved;
			}
			
			const retView = new Uint8Array(retBuf);
			
			for(let j = (i - 1); j >= 0; j--)
			{
				const basis = Math.pow(2, j * base);
				
				retView[result - j - 1] = Math.floor(internalValue / basis);
				internalValue -= (retView[result - j - 1]) * basis;
			}
			
			return retBuf;
		}
		
		biggest *= Math.pow(2, base);
	}
	
	return new ArrayBuffer(0);
}
//**************************************************************************************
/**
 * Concatenate two ArrayBuffers
 * @param {...ArrayBuffer} buffers First ArrayBuffer (first part of concatenated array)
 */
function utilConcatBuf(...buffers)
{
	//region Initial variables
	let outputLength = 0;
	let prevLength = 0;
	//endregion
	
	//region Calculate output length
	
	for(const buffer of buffers)
		outputLength += buffer.byteLength;
	//endregion
	
	const retBuf = new ArrayBuffer(outputLength);
	const retView = new Uint8Array(retBuf);
	
	for(const buffer of buffers)
	{
		retView.set(new Uint8Array(buffer), prevLength);
		prevLength += buffer.byteLength;
	}
	
	return retBuf;
}
//**************************************************************************************
/**
 * Decoding of "two complement" values
 * The function must be called in scope of instance of "hexBlock" class ("valueHex" and "warnings" properties must be present)
 * @returns {number}
 */
function utilDecodeTC()
{
	const buf = new Uint8Array(this.valueHex);
	
	if(this.valueHex.byteLength >= 2)
	{
		//noinspection JSBitwiseOperatorUsage
		const condition1 = (buf[0] === 0xFF) && (buf[1] & 0x80);
		const condition2 = (buf[0] === 0x00) && ((buf[1] & 0x80) === 0x00);
		
		if(condition1 || condition2)
			this.warnings.push("Needlessly long format");
	}
	
	//region Create big part of the integer
	const bigIntBuffer = new ArrayBuffer(this.valueHex.byteLength);
	const bigIntView = new Uint8Array(bigIntBuffer);
	for(let i = 0; i < this.valueHex.byteLength; i++)
		bigIntView[i] = 0;
	
	bigIntView[0] = (buf[0] & 0x80); // mask only the biggest bit
	
	const bigInt = utilFromBase(bigIntView, 8);
	//endregion
	
	//region Create small part of the integer
	const smallIntBuffer = new ArrayBuffer(this.valueHex.byteLength);
	const smallIntView = new Uint8Array(smallIntBuffer);
	for(let j = 0; j < this.valueHex.byteLength; j++)
		smallIntView[j] = buf[j];
	
	smallIntView[0] &= 0x7F; // mask biggest bit
	
	const smallInt = utilFromBase(smallIntView, 8);
	//endregion
	
	return (smallInt - bigInt);
}
//**************************************************************************************
/**
 * Encode integer value to "two complement" format
 * @param {number} value Value to encode
 * @returns {ArrayBuffer}
 */
function utilEncodeTC(value)
{
	const modValue = (value < 0) ? (value * (-1)) : value;
	let bigInt = 128;
	
	for(let i = 1; i < 8; i++)
	{
		if(modValue <= bigInt)
		{
			if(value < 0)
			{
				const smallInt = bigInt - modValue;
				
				const retBuf = utilToBase(smallInt, 8, i);
				const retView = new Uint8Array(retBuf);
				
				retView[0] |= 0x80;
				
				return retBuf;
			}
			
			let retBuf = utilToBase(modValue, 8, i);
			let retView = new Uint8Array(retBuf);
			
			//noinspection JSBitwiseOperatorUsage
			if(retView[0] & 0x80)
			{
				//noinspection JSCheckFunctionSignatures
				const tempBuf = retBuf.slice(0);
				const tempView = new Uint8Array(tempBuf);
				
				retBuf = new ArrayBuffer(retBuf.byteLength + 1);
				retView = new Uint8Array(retBuf);
				
				for(let k = 0; k < tempBuf.byteLength; k++)
					retView[k + 1] = tempView[k];
				
				retView[0] = 0x00;
			}
			
			return retBuf;
		}
		
		bigInt *= Math.pow(2, 8);
	}
	
	return (new ArrayBuffer(0));
}
//**************************************************************************************
/**
 * Compare two array buffers
 * @param {!ArrayBuffer} inputBuffer1
 * @param {!ArrayBuffer} inputBuffer2
 * @returns {boolean}
 */
function isEqualBuffer(inputBuffer1, inputBuffer2)
{
	if(inputBuffer1.byteLength !== inputBuffer2.byteLength)
		return false;
	
	const view1 = new Uint8Array(inputBuffer1);
	const view2 = new Uint8Array(inputBuffer2);
	
	for(let i = 0; i < view1.length; i++)
	{
		if(view1[i] !== view2[i])
			return false;
	}
	
	return true;
}
//**************************************************************************************
/**
 * Pad input number with leade "0" if needed
 * @returns {string}
 * @param {number} inputNumber
 * @param {number} fullLength
 */
function padNumber(inputNumber, fullLength)
{
	const str = inputNumber.toString(10);
	const dif = fullLength - str.length;
	
	const padding = new Array(dif);
	for(let i = 0; i < dif; i++)
		padding[i] = "0";
	
	const paddingString = padding.join("");
	
	return paddingString.concat(str);
}
//**************************************************************************************
const base64Template = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const base64UrlTemplate = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
//**************************************************************************************
/**
 * Encode string into BASE64 (or "base64url")
 * @param {string} input
 * @param {boolean} useUrlTemplate If "true" then output would be encoded using "base64url"
 * @param {boolean} skipPadding Skip BASE-64 padding or not
 * @param {boolean} skipLeadingZeros Skip leading zeros in input data or not
 * @returns {string}
 */
function toBase64(input, useUrlTemplate = false, skipPadding = false, skipLeadingZeros = false)
{
	let i = 0;
	
	let flag1 = 0;
	let flag2 = 0;
	
	let output = "";
	
	const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;
	
	if(skipLeadingZeros)
	{
		let nonZeroPosition = 0;
		
		for(let i = 0; i < input.length; i++)
		{
			if(input.charCodeAt(i) !== 0)
			{
				nonZeroPosition = i;
				break;
			}
		}
		
		input = input.slice(nonZeroPosition);
	}
	
	while(i < input.length)
	{
		const chr1 = input.charCodeAt(i++);
		if(i >= input.length)
			flag1 = 1;
		const chr2 = input.charCodeAt(i++);
		if(i >= input.length)
			flag2 = 1;
		const chr3 = input.charCodeAt(i++);
		
		const enc1 = chr1 >> 2;
		const enc2 = ((chr1 & 0x03) << 4) | (chr2 >> 4);
		let enc3 = ((chr2 & 0x0F) << 2) | (chr3 >> 6);
		let enc4 = chr3 & 0x3F;
		
		if(flag1 === 1)
			enc3 = enc4 = 64;
		else
		{
			if(flag2 === 1)
				enc4 = 64;
		}
		
		if(skipPadding)
		{
			if(enc3 === 64)
				output += `${template.charAt(enc1)}${template.charAt(enc2)}`;
			else
			{
				if(enc4 === 64)
					output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}`;
				else
					output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;
			}
		}
		else
			output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;
	}
	
	return output;
}
//**************************************************************************************
/**
 * Decode string from BASE64 (or "base64url")
 * @param {string} input
 * @param {boolean} [useUrlTemplate=false] If "true" then output would be encoded using "base64url"
 * @param {boolean} [cutTailZeros=false] If "true" then cut tailing zeroz from function result
 * @returns {string}
 */
function fromBase64(input, useUrlTemplate = false, cutTailZeros = false)
{
	const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;
	
	//region Aux functions
	function indexof(toSearch)
	{
		for(let i = 0; i < 64; i++)
		{
			if(template.charAt(i) === toSearch)
				return i;
		}
		
		return 64;
	}
	
	function test(incoming)
	{
		return ((incoming === 64) ? 0x00 : incoming);
	}
	//endregion
	
	let i = 0;
	
	let output = "";
	
	while(i < input.length)
	{
		const enc1 = indexof(input.charAt(i++));
		const enc2 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		const enc3 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		const enc4 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		
		const chr1 = (test(enc1) << 2) | (test(enc2) >> 4);
		const chr2 = ((test(enc2) & 0x0F) << 4) | (test(enc3) >> 2);
		const chr3 = ((test(enc3) & 0x03) << 6) | test(enc4);
		
		output += String.fromCharCode(chr1);
		
		if(enc3 !== 64)
			output += String.fromCharCode(chr2);
		
		if(enc4 !== 64)
			output += String.fromCharCode(chr3);
	}
	
	if(cutTailZeros)
	{
		const outputLength = output.length;
		let nonZeroStart = (-1);
		
		for(let i = (outputLength - 1); i >= 0; i--)
		{
			if(output.charCodeAt(i) !== 0)
			{
				nonZeroStart = i;
				break;
			}
		}
		
		if(nonZeroStart !== (-1))
			output = output.slice(0, nonZeroStart + 1);
	}
	
	return output;
}
//**************************************************************************************
function arrayBufferToString(buffer)
{
	let resultString = "";
	const view = new Uint8Array(buffer);
	
	for(const element of view)
		resultString = resultString + String.fromCharCode(element);
	
	return resultString;
}
//**************************************************************************************
function stringToArrayBuffer(str)
{
	const stringLength = str.length;
	
	const resultBuffer = new ArrayBuffer(stringLength);
	const resultView = new Uint8Array(resultBuffer);
	
	for(let i = 0; i < stringLength; i++)
		resultView[i] = str.charCodeAt(i);
	
	return resultBuffer;
}

//**************************************************************************************
//region Declaration for "LocalBaseBlock" class
//**************************************************************************************
/**
 * Class used as a base block for all remaining ASN.1 classes
 * @typedef LocalBaseBlock
 * @interface
 * @property {number} blockLength
 * @property {string} error
 * @property {Array.<string>} warnings
 * @property {ArrayBuffer} valueBeforeDecode
 */
class LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBaseBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueBeforeDecode]
	 */
	constructor(parameters = {})
	{
		/**
		 * @type {number} blockLength
		 */
		this.blockLength = getParametersValue(parameters, "blockLength", 0);
		/**
		 * @type {string} error
		 */
		this.error = getParametersValue(parameters, "error", "");
		/**
		 * @type {Array.<string>} warnings
		 */
		this.warnings = getParametersValue(parameters, "warnings", []);
		//noinspection JSCheckFunctionSignatures
		/**
		 * @type {ArrayBuffer} valueBeforeDecode
		 */
		if("valueBeforeDecode" in parameters)
			this.valueBeforeDecode = parameters.valueBeforeDecode.slice(0);
		else
			this.valueBeforeDecode = new ArrayBuffer(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "baseBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		return {
			blockName: this.constructor.blockName(),
			blockLength: this.blockLength,
			error: this.error,
			warnings: this.warnings,
			valueBeforeDecode: bufferToHexCodes(this.valueBeforeDecode, 0, this.valueBeforeDecode.byteLength)
		};
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Description for "LocalHexBlock" class
//**************************************************************************************
/**
 * Class used as a base block for all remaining ASN.1 classes
 * @extends LocalBaseBlock
 * @typedef LocalHexBlock
 * @property {number} blockLength
 * @property {string} error
 * @property {Array.<string>} warnings
 * @property {ArrayBuffer} valueBeforeDecode
 * @property {boolean} isHexOnly
 * @property {ArrayBuffer} valueHex
 */
//noinspection JSUnusedLocalSymbols
const LocalHexBlock = BaseClass => class LocalHexBlockMixin extends BaseClass
{
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Constructor for "LocalHexBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		/**
		 * @type {boolean}
		 */
		this.isHexOnly = getParametersValue(parameters, "isHexOnly", false);
		/**
		 * @type {ArrayBuffer}
		 */
		if("valueHex" in parameters)
			this.valueHex = parameters.valueHex.slice(0);
		else
			this.valueHex = new ArrayBuffer(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "hexBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.warnings.push("Zero buffer length");
			return inputOffset;
		}
		//endregion

		//region Copy input buffer to internal buffer
		this.valueHex = inputBuffer.slice(inputOffset, inputOffset + inputLength);
		//endregion

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		if(this.isHexOnly !== true)
		{
			this.error = "Flag \"isHexOnly\" is not set, abort";
			return new ArrayBuffer(0);
		}

		if(sizeOnly === true)
			return new ArrayBuffer(this.valueHex.byteLength);

		//noinspection JSCheckFunctionSignatures
		return this.valueHex.slice(0);
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.blockName = this.constructor.blockName();
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
};
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of identification block class
//**************************************************************************************
class LocalIdentificationBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBaseBlock" class
	 * @param {Object} [parameters={}]
	 * @property {Object} [idBlock]
	 */
	constructor(parameters = {})
	{
		super();

		if("idBlock" in parameters)
		{
			//region Properties from hexBlock class
			this.isHexOnly = getParametersValue(parameters.idBlock, "isHexOnly", false);
			this.valueHex = getParametersValue(parameters.idBlock, "valueHex", new ArrayBuffer(0));
			//endregion

			this.tagClass = getParametersValue(parameters.idBlock, "tagClass", (-1));
			this.tagNumber = getParametersValue(parameters.idBlock, "tagNumber", (-1));
			this.isConstructed = getParametersValue(parameters.idBlock, "isConstructed", false);
		}
		else
		{
			this.tagClass = (-1);
			this.tagNumber = (-1);
			this.isConstructed = false;
		}
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "identificationBlock";
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Initial variables
		let firstOctet = 0;
		let retBuf;
		let retView;
		//endregion

		switch(this.tagClass)
		{
			case 1:
				firstOctet |= 0x00; // UNIVERSAL
				break;
			case 2:
				firstOctet |= 0x40; // APPLICATION
				break;
			case 3:
				firstOctet |= 0x80; // CONTEXT-SPECIFIC
				break;
			case 4:
				firstOctet |= 0xC0; // PRIVATE
				break;
			default:
				this.error = "Unknown tag class";
				return (new ArrayBuffer(0));
		}

		if(this.isConstructed)
			firstOctet |= 0x20;

		if((this.tagNumber < 31) && (!this.isHexOnly))
		{
			retBuf = new ArrayBuffer(1);
			retView = new Uint8Array(retBuf);

			if(!sizeOnly)
			{
				let number = this.tagNumber;
				number &= 0x1F;
				firstOctet |= number;

				retView[0] = firstOctet;
			}

			return retBuf;
		}

		if(this.isHexOnly === false)
		{
			const encodedBuf = utilToBase(this.tagNumber, 7);
			const encodedView = new Uint8Array(encodedBuf);
			const size = encodedBuf.byteLength;

			retBuf = new ArrayBuffer(size + 1);
			retView = new Uint8Array(retBuf);
			retView[0] = (firstOctet | 0x1F);

			if(!sizeOnly)
			{
				for(let i = 0; i < (size - 1); i++)
					retView[i + 1] = encodedView[i] | 0x80;

				retView[size] = encodedView[size - 1];
			}

			return retBuf;
		}

		retBuf = new ArrayBuffer(this.valueHex.byteLength + 1);
		retView = new Uint8Array(retBuf);

		retView[0] = (firstOctet | 0x1F);

		if(sizeOnly === false)
		{
			const curView = new Uint8Array(this.valueHex);

			for(let i = 0; i < (curView.length - 1); i++)
				retView[i + 1] = curView[i] | 0x80;

			retView[this.valueHex.byteLength] = curView[curView.length - 1];
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.error = "Zero buffer length";
			return (-1);
		}
		//endregion

		//region Find tag class
		const tagClassMask = intBuffer[0] & 0xC0;

		switch(tagClassMask)
		{
			case 0x00:
				this.tagClass = (1); // UNIVERSAL
				break;
			case 0x40:
				this.tagClass = (2); // APPLICATION
				break;
			case 0x80:
				this.tagClass = (3); // CONTEXT-SPECIFIC
				break;
			case 0xC0:
				this.tagClass = (4); // PRIVATE
				break;
			default:
				this.error = "Unknown tag class";
				return (-1);
		}
		//endregion

		//region Find it's constructed or not
		this.isConstructed = (intBuffer[0] & 0x20) === 0x20;
		//endregion

		//region Find tag number
		this.isHexOnly = false;

		const tagNumberMask = intBuffer[0] & 0x1F;

		//region Simple case (tag number < 31)
		if(tagNumberMask !== 0x1F)
		{
			this.tagNumber = (tagNumberMask);
			this.blockLength = 1;
		}
		//endregion
		//region Tag number bigger or equal to 31
		else
		{
			let count = 1;

			this.valueHex = new ArrayBuffer(255);
			let tagNumberBufferMaxLength = 255;
			let intTagNumberBuffer = new Uint8Array(this.valueHex);

			//noinspection JSBitwiseOperatorUsage
			while(intBuffer[count] & 0x80)
			{
				intTagNumberBuffer[count - 1] = intBuffer[count] & 0x7F;
				count++;

				if(count >= intBuffer.length)
				{
					this.error = "End of input reached before message was fully decoded";
					return (-1);
				}

				//region In case if tag number length is greater than 255 bytes (rare but possible case)
				if(count === tagNumberBufferMaxLength)
				{
					tagNumberBufferMaxLength += 255;

					const tempBuffer = new ArrayBuffer(tagNumberBufferMaxLength);
					const tempBufferView = new Uint8Array(tempBuffer);

					for(let i = 0; i < intTagNumberBuffer.length; i++)
						tempBufferView[i] = intTagNumberBuffer[i];

					this.valueHex = new ArrayBuffer(tagNumberBufferMaxLength);
					intTagNumberBuffer = new Uint8Array(this.valueHex);
				}
				//endregion
			}

			this.blockLength = (count + 1);
			intTagNumberBuffer[count - 1] = intBuffer[count] & 0x7F; // Write last byte to buffer

			//region Cut buffer
			const tempBuffer = new ArrayBuffer(count);
			const tempBufferView = new Uint8Array(tempBuffer);

			for(let i = 0; i < count; i++)
				tempBufferView[i] = intTagNumberBuffer[i];

			this.valueHex = new ArrayBuffer(count);
			intTagNumberBuffer = new Uint8Array(this.valueHex);
			intTagNumberBuffer.set(tempBufferView);
			//endregion

			//region Try to convert long tag number to short form
			if(this.blockLength <= 9)
				this.tagNumber = utilFromBase(intTagNumberBuffer, 7);
			else
			{
				this.isHexOnly = true;
				this.warnings.push("Tag too long, represented as hex-coded");
			}
			//endregion
		}
		//endregion
		//endregion

		//region Check if constructed encoding was using for primitive type
		if(((this.tagClass === 1)) &&
			(this.isConstructed))
		{
			switch(this.tagNumber)
			{
				case 1:  // Boolean
				case 2:  // REAL
				case 5:  // Null
				case 6:  // OBJECT IDENTIFIER
				case 9:  // REAL
				case 14: // Time
				case 23:
				case 24:
				case 31:
				case 32:
				case 33:
				case 34:
					this.error = "Constructed encoding used for primitive type";
					return (-1);
				default:
			}
		}
		//endregion

		return (inputOffset + this.blockLength); // Return current offset in input buffer
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName: string,
	 *  tagClass: number,
	 *  tagNumber: number,
	 *  isConstructed: boolean,
	 *  isHexOnly: boolean,
	 *  valueHex: ArrayBuffer,
	 *  blockLength: number,
	 *  error: string, warnings: Array.<string>,
	 *  valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.blockName = this.constructor.blockName();
		object.tagClass = this.tagClass;
		object.tagNumber = this.tagNumber;
		object.isConstructed = this.isConstructed;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of length block class
//**************************************************************************************
class LocalLengthBlock extends LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalLengthBlock" class
	 * @param {Object} [parameters={}]
	 * @property {Object} [lenBlock]
	 */
	constructor(parameters = {})
	{
		super();

		if("lenBlock" in parameters)
		{
			this.isIndefiniteForm = getParametersValue(parameters.lenBlock, "isIndefiniteForm", false);
			this.longFormUsed = getParametersValue(parameters.lenBlock, "longFormUsed", false);
			this.length = getParametersValue(parameters.lenBlock, "length", 0);
		}
		else
		{
			this.isIndefiniteForm = false;
			this.longFormUsed = false;
			this.length = 0;
		}
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "lengthBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.error = "Zero buffer length";
			return (-1);
		}

		if(intBuffer[0] === 0xFF)
		{
			this.error = "Length block 0xFF is reserved by standard";
			return (-1);
		}
		//endregion

		//region Check for length form type
		this.isIndefiniteForm = intBuffer[0] === 0x80;
		//endregion

		//region Stop working in case of indefinite length form
		if(this.isIndefiniteForm === true)
		{
			this.blockLength = 1;
			return (inputOffset + this.blockLength);
		}
		//endregion

		//region Check is long form of length encoding using
		this.longFormUsed = !!(intBuffer[0] & 0x80);
		//endregion

		//region Stop working in case of short form of length value
		if(this.longFormUsed === false)
		{
			this.length = (intBuffer[0]);
			this.blockLength = 1;
			return (inputOffset + this.blockLength);
		}
		//endregion

		//region Calculate length value in case of long form
		const count = intBuffer[0] & 0x7F;

		if(count > 8) // Too big length value
		{
			this.error = "Too big integer";
			return (-1);
		}

		if((count + 1) > intBuffer.length)
		{
			this.error = "End of input reached before message was fully decoded";
			return (-1);
		}

		const lengthBufferView = new Uint8Array(count);

		for(let i = 0; i < count; i++)
			lengthBufferView[i] = intBuffer[i + 1];

		if(lengthBufferView[count - 1] === 0x00)
			this.warnings.push("Needlessly long encoded length");

		this.length = utilFromBase(lengthBufferView, 8);

		if(this.longFormUsed && (this.length <= 127))
			this.warnings.push("Unneccesary usage of long length form");

		this.blockLength = count + 1;
		//endregion

		return (inputOffset + this.blockLength); // Return current offset in input buffer
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Initial variables
		let retBuf;
		let retView;
		//endregion

		if(this.length > 127)
			this.longFormUsed = true;

		if(this.isIndefiniteForm)
		{
			retBuf = new ArrayBuffer(1);

			if(sizeOnly === false)
			{
				retView = new Uint8Array(retBuf);
				retView[0] = 0x80;
			}

			return retBuf;
		}

		if(this.longFormUsed === true)
		{
			const encodedBuf = utilToBase(this.length, 8);

			if(encodedBuf.byteLength > 127)
			{
				this.error = "Too big length";
				return (new ArrayBuffer(0));
			}

			retBuf = new ArrayBuffer(encodedBuf.byteLength + 1);

			if(sizeOnly === true)
				return retBuf;

			const encodedView = new Uint8Array(encodedBuf);
			retView = new Uint8Array(retBuf);

			retView[0] = encodedBuf.byteLength | 0x80;

			for(let i = 0; i < encodedBuf.byteLength; i++)
				retView[i + 1] = encodedView[i];

			return retBuf;
		}

		retBuf = new ArrayBuffer(1);

		if(sizeOnly === false)
		{
			retView = new Uint8Array(retBuf);

			retView[0] = this.length;
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.blockName = this.constructor.blockName();
		object.isIndefiniteForm = this.isIndefiniteForm;
		object.longFormUsed = this.longFormUsed;
		object.length = this.length;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of value block class
//**************************************************************************************
class LocalValueBlock extends LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "valueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols,JSUnusedLocalSymbols,JSUnusedLocalSymbols
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Throw an exception for a function which needs to be specified in extended classes
		throw TypeError("User need to make a specific function in a class which extends \"LocalValueBlock\"");
		//endregion
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Throw an exception for a function which needs to be specified in extended classes
		throw TypeError("User need to make a specific function in a class which extends \"LocalValueBlock\"");
		//endregion
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of basic ASN.1 block class
//**************************************************************************************
class BaseBlock extends LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "BaseBlock" class
	 * @param {Object} [parameters={}]
	 * @property {Object} [primitiveSchema]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 * @param valueBlockType Type of value block
	 */
	constructor(parameters = {}, valueBlockType = LocalValueBlock)
	{
		super(parameters);

		if("name" in parameters)
			this.name = parameters.name;
		if("optional" in parameters)
			this.optional = parameters.optional;
		if("primitiveSchema" in parameters)
			this.primitiveSchema = parameters.primitiveSchema;

		this.idBlock = new LocalIdentificationBlock(parameters);
		this.lenBlock = new LocalLengthBlock(parameters);
		this.valueBlock = new valueBlockType(parameters);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BaseBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		let retBuf;

		const idBlockBuf = this.idBlock.toBER(sizeOnly);
		const valueBlockSizeBuf = this.valueBlock.toBER(true);

		this.lenBlock.length = valueBlockSizeBuf.byteLength;
		const lenBlockBuf = this.lenBlock.toBER(sizeOnly);

		retBuf = utilConcatBuf(idBlockBuf, lenBlockBuf);

		let valueBlockBuf;

		if(sizeOnly === false)
			valueBlockBuf = this.valueBlock.toBER(sizeOnly);
		else
			valueBlockBuf = new ArrayBuffer(this.lenBlock.length);

		retBuf = utilConcatBuf(retBuf, valueBlockBuf);

		if(this.lenBlock.isIndefiniteForm === true)
		{
			const indefBuf = new ArrayBuffer(2);

			if(sizeOnly === false)
			{
				const indefView = new Uint8Array(indefBuf);

				indefView[0] = 0x00;
				indefView[1] = 0x00;
			}

			retBuf = utilConcatBuf(retBuf, indefBuf);
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.idBlock = this.idBlock.toJSON();
		object.lenBlock = this.lenBlock.toJSON();
		object.valueBlock = this.valueBlock.toJSON();

		if("name" in this)
			object.name = this.name;
		if("optional" in this)
			object.optional = this.optional;
		if("primitiveSchema" in this)
			object.primitiveSchema = this.primitiveSchema.toJSON();

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of basic block for all PRIMITIVE types
//**************************************************************************************
class LocalPrimitiveValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalPrimitiveValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueBeforeDecode]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		//region Variables from "hexBlock" class
		if("valueHex" in parameters)
			this.valueHex = parameters.valueHex.slice(0);
		else
			this.valueHex = new ArrayBuffer(0);

		this.isHexOnly = getParametersValue(parameters, "isHexOnly", true);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.warnings.push("Zero buffer length");
			return inputOffset;
		}
		//endregion

		//region Copy input buffer into internal buffer
		this.valueHex = new ArrayBuffer(intBuffer.length);
		const valueHexView = new Uint8Array(this.valueHex);

		for(let i = 0; i < intBuffer.length; i++)
			valueHexView[i] = intBuffer[i];
		//endregion

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return this.valueHex.slice(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "PrimitiveValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);
		object.isHexOnly = this.isHexOnly;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Primitive extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Primitive" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalPrimitiveValueBlock);

		this.idBlock.isConstructed = false;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "PRIMITIVE";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of basic block for all CONSTRUCTED types
//**************************************************************************************
class LocalConstructedValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalConstructedValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.value = getParametersValue(parameters, "value", []);
		this.isIndefiniteForm = getParametersValue(parameters, "isIndefiniteForm", false);
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Store initial offset and length
		const initialOffset = inputOffset;
		const initialLength = inputLength;
		//endregion

		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.warnings.push("Zero buffer length");
			return inputOffset;
		}
		//endregion

		//region Aux function
		function checkLen(indefiniteLength, length)
		{
			if(indefiniteLength === true)
				return 1;

			return length;
		}
		//endregion

		let currentOffset = inputOffset;

		while(checkLen(this.isIndefiniteForm, inputLength) > 0)
		{
			const returnObject = LocalFromBER(inputBuffer, currentOffset, inputLength);
			if(returnObject.offset === (-1))
			{
				this.error = returnObject.result.error;
				this.warnings.concat(returnObject.result.warnings);
				return (-1);
			}

			currentOffset = returnObject.offset;

			this.blockLength += returnObject.result.blockLength;
			inputLength -= returnObject.result.blockLength;

			this.value.push(returnObject.result);

			if((this.isIndefiniteForm === true) && (returnObject.result.constructor.blockName() === EndOfContent.blockName()))
				break;
		}

		if(this.isIndefiniteForm === true)
		{
			if(this.value[this.value.length - 1].constructor.blockName() === EndOfContent.blockName())
				this.value.pop();
			else
				this.warnings.push("No EndOfContent block encoded");
		}

		//region Copy "inputBuffer" to "valueBeforeDecode"
		this.valueBeforeDecode = inputBuffer.slice(initialOffset, initialOffset + initialLength);
		//endregion

		return currentOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		let retBuf = new ArrayBuffer(0);

		for(let i = 0; i < this.value.length; i++)
		{
			const valueBuf = this.value[i].toBER(sizeOnly);
			retBuf = utilConcatBuf(retBuf, valueBuf);
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "ConstructedValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.isIndefiniteForm = this.isIndefiniteForm;
		object.value = [];
		for(let i = 0; i < this.value.length; i++)
			object.value.push(this.value[i].toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Constructed extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Constructed" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalConstructedValueBlock);

		this.idBlock.isConstructed = true;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "CONSTRUCTED";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;

		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 EndOfContent type class
//**************************************************************************************
class LocalEndOfContentValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalEndOfContentValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols,JSUnusedLocalSymbols
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region There is no "value block" for EndOfContent type and we need to return the same offset
		return inputOffset;
		//endregion
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return new ArrayBuffer(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "EndOfContentValueBlock";
	}
	//**********************************************************************************
}
//**************************************************************************************
class EndOfContent extends BaseBlock
{
	//**********************************************************************************
	constructor(paramaters = {})
	{
		super(paramaters, LocalEndOfContentValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 0; // EndOfContent
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "EndOfContent";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Boolean type class
//**************************************************************************************
class LocalBooleanValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBooleanValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		this.value = getParametersValue(parameters, "value", false);
		this.isHexOnly = getParametersValue(parameters, "isHexOnly", false);
		
		if("valueHex" in parameters)
			this.valueHex = parameters.valueHex.slice(0);
		else
		{
			this.valueHex = new ArrayBuffer(1);
			if(this.value === true)
			{
				var view = new Uint8Array(this.valueHex);
				view[0] = 0xFF;
			}
		}
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		if(inputLength > 1)
			this.warnings.push("Boolean value encoded in more then 1 octet");

		this.value = intBuffer[0] !== 0x00;

		this.isHexOnly = true;

		//region Copy input buffer to internal array
		this.valueHex = new ArrayBuffer(intBuffer.length);
		const view = new Uint8Array(this.valueHex);

		for(let i = 0; i < intBuffer.length; i++)
			view[i] = intBuffer[i];
		//endregion

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return this.valueHex;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BooleanValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Boolean extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Boolean" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBooleanValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 1; // Boolean
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Boolean";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Sequence and Set type classes
//**************************************************************************************
class Sequence extends Constructed
{
	//**********************************************************************************
	/**
	 * Constructor for "Sequence" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 16; // Sequence
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Sequence";
	}
	//**********************************************************************************
}
//**************************************************************************************
class Set extends Constructed
{
	//**********************************************************************************
	/**
	 * Constructor for "Set" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 17; // Set
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Set";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Null type class
//**************************************************************************************
class Null extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Null" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBaseBlock); // We will not have a call to "Null value block" because of specified "fromBER" and "toBER" functions

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 5; // Null
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Null";
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		if(this.lenBlock.length > 0)
			this.warnings.push("Non-zero length of value block for Null type");

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		this.blockLength += inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		const retBuf = new ArrayBuffer(2);

		if(sizeOnly === true)
			return retBuf;

		const retView = new Uint8Array(retBuf);
		retView[0] = 0x05;
		retView[1] = 0x00;

		return retBuf;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 OctetString type class
//**************************************************************************************
class LocalOctetStringValueBlock extends LocalHexBlock(LocalConstructedValueBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalOctetStringValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isConstructed = getParametersValue(parameters, "isConstructed", false);
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		let resultOffset = 0;

		if(this.isConstructed === true)
		{
			this.isHexOnly = false;

			resultOffset = LocalConstructedValueBlock.prototype.fromBER.call(this, inputBuffer, inputOffset, inputLength);
			if(resultOffset === (-1))
				return resultOffset;

			for(let i = 0; i < this.value.length; i++)
			{
				const currentBlockName = this.value[i].constructor.blockName();

				if(currentBlockName === EndOfContent.blockName())
				{
					if(this.isIndefiniteForm === true)
						break;
					else
					{
						this.error = "EndOfContent is unexpected, OCTET STRING may consists of OCTET STRINGs only";
						return (-1);
					}
				}

				if(currentBlockName !== OctetString.blockName())
				{
					this.error = "OCTET STRING may consists of OCTET STRINGs only";
					return (-1);
				}
			}
		}
		else
		{
			this.isHexOnly = true;

			resultOffset = super.fromBER(inputBuffer, inputOffset, inputLength);
			this.blockLength = inputLength;
		}

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		if(this.isConstructed === true)
			return LocalConstructedValueBlock.prototype.toBER.call(this, sizeOnly);

		let retBuf = new ArrayBuffer(this.valueHex.byteLength);

		if(sizeOnly === true)
			return retBuf;

		if(this.valueHex.byteLength === 0)
			return retBuf;

		retBuf = this.valueHex.slice(0);

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "OctetStringValueBlock";
	}
	//**********************************************************************************
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.isConstructed = this.isConstructed;
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class OctetString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "OctetString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalOctetStringValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 4; // OctetString
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		this.valueBlock.isConstructed = this.idBlock.isConstructed;
		this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;

		//region Ability to encode empty OCTET STRING
		if(inputLength === 0)
		{
			if(this.idBlock.error.length === 0)
				this.blockLength += this.idBlock.blockLength;

			if(this.lenBlock.error.length === 0)
				this.blockLength += this.lenBlock.blockLength;

			return inputOffset;
		}
		//endregion

		return super.fromBER(inputBuffer, inputOffset, inputLength);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "OctetString";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Checking that two OCTETSTRINGs are equal
	 * @param {OctetString} octetString
	 */
	isEqual(octetString)
	{
		//region Check input type
		if((octetString instanceof OctetString) === false)
			return false;
		//endregion

		//region Compare two JSON strings
		if(JSON.stringify(this) !== JSON.stringify(octetString))
			return false;
		//endregion

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 BitString type class
//**************************************************************************************
class LocalBitStringValueBlock extends LocalHexBlock(LocalConstructedValueBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBitStringValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.unusedBits = getParametersValue(parameters, "unusedBits", 0);
		this.isConstructed = getParametersValue(parameters, "isConstructed", false);
		this.blockLength = this.valueHex.byteLength + 1; // "+1" for "unusedBits"
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Ability to decode zero-length BitString value
		if(inputLength === 0)
			return inputOffset;
		//endregion

		let resultOffset = (-1);

		//region If the BISTRING supposed to be a constructed value
		if(this.isConstructed === true)
		{
			resultOffset = LocalConstructedValueBlock.prototype.fromBER.call(this, inputBuffer, inputOffset, inputLength);
			if(resultOffset === (-1))
				return resultOffset;

			for(let i = 0; i < this.value.length; i++)
			{
				const currentBlockName = this.value[i].constructor.blockName();

				if(currentBlockName === EndOfContent.blockName())
				{
					if(this.isIndefiniteForm === true)
						break;
					else
					{
						this.error = "EndOfContent is unexpected, BIT STRING may consists of BIT STRINGs only";
						return (-1);
					}
				}

				if(currentBlockName !== BitString.blockName())
				{
					this.error = "BIT STRING may consists of BIT STRINGs only";
					return (-1);
				}

				if((this.unusedBits > 0) && (this.value[i].unusedBits > 0))
				{
					this.error = "Usign of \"unused bits\" inside constructive BIT STRING allowed for least one only";
					return (-1);
				}

				this.unusedBits = this.value[i].unusedBits;
				if(this.unusedBits > 7)
				{
					this.error = "Unused bits for BitString must be in range 0-7";
					return (-1);
				}
			}

			return resultOffset;
		}
		//endregion
		//region If the BitString supposed to be a primitive value
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);

		this.unusedBits = intBuffer[0];
		if(this.unusedBits > 7)
		{
			this.error = "Unused bits for BitString must be in range 0-7";
			return (-1);
		}

		//region Copy input buffer to internal buffer
		this.valueHex = new ArrayBuffer(intBuffer.length - 1);
		const view = new Uint8Array(this.valueHex);
		for(let i = 0; i < (inputLength - 1); i++)
			view[i] = intBuffer[i + 1];
		//endregion

		this.blockLength = intBuffer.length;

		return (inputOffset + inputLength);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		if(this.isConstructed === true)
			return LocalConstructedValueBlock.prototype.toBER.call(this, sizeOnly);

		if(sizeOnly === true)
			return (new ArrayBuffer(this.valueHex.byteLength + 1));

		if(this.valueHex.byteLength === 0)
			return (new ArrayBuffer(0));

		const curView = new Uint8Array(this.valueHex);

		const retBuf = new ArrayBuffer(this.valueHex.byteLength + 1);
		const retView = new Uint8Array(retBuf);

		retView[0] = this.unusedBits;

		for(let i = 0; i < this.valueHex.byteLength; i++)
			retView[i + 1] = curView[i];

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BitStringValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.unusedBits = this.unusedBits;
		object.isConstructed = this.isConstructed;
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class BitString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "BitString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBitStringValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 3; // BitString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BitString";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Ability to encode empty BitString
		if(inputLength === 0)
			return inputOffset;
		//endregion

		this.valueBlock.isConstructed = this.idBlock.isConstructed;
		this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;

		return super.fromBER(inputBuffer, inputOffset, inputLength);
	}
	//**********************************************************************************
	/**
	 * Checking that two BITSTRINGs are equal
	 * @param {BitString} bitString
	 */
	isEqual(bitString)
	{
		//region Check input type
		if((bitString instanceof BitString) === false)
			return false;
		//endregion

		//region Compare two JSON strings
		if(JSON.stringify(this) !== JSON.stringify(bitString))
			return false;
		//endregion

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Integer type class
//**************************************************************************************
/**
 * @extends LocalValueBlock
 */
class LocalIntegerValueBlock extends LocalHexBlock(LocalValueBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalIntegerValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		if("value" in parameters)
			this.valueDec = parameters.value;
	}
	//**********************************************************************************
	/**
	 * Setter for "valueHex"
	 * @param {ArrayBuffer} _value
	 */
	set valueHex(_value)
	{
		this._valueHex = _value.slice(0);

		if(_value.byteLength >= 4)
		{
			this.warnings.push("Too big Integer for decoding, hex only");
			this.isHexOnly = true;
			this._valueDec = 0;
		}
		else
		{
			this.isHexOnly = false;

			if(_value.byteLength > 0)
				this._valueDec = utilDecodeTC.call(this);
		}
	}
	//**********************************************************************************
	/**
	 * Getter for "valueHex"
	 * @returns {ArrayBuffer}
	 */
	get valueHex()
	{
		return this._valueHex;
	}
	//**********************************************************************************
	/**
	 * Getter for "valueDec"
	 * @param {number} _value
	 */
	set valueDec(_value)
	{
		this._valueDec = _value;

		this.isHexOnly = false;
		this._valueHex = utilEncodeTC(_value);
	}
	//**********************************************************************************
	/**
	 * Getter for "valueDec"
	 * @returns {number}
	 */
	get valueDec()
	{
		return this._valueDec;
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from DER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 DER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 DER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @param {number} [expectedLength=0] Expected length of converted "valueHex" buffer
	 * @returns {number} Offset after least decoded byte
	 */
	fromDER(inputBuffer, inputOffset, inputLength, expectedLength = 0)
	{
		const offset = this.fromBER(inputBuffer, inputOffset, inputLength);
		if(offset === (-1))
			return offset;

		const view = new Uint8Array(this._valueHex);

		if((view[0] === 0x00) && ((view[1] & 0x80) !== 0))
		{
			const updatedValueHex = new ArrayBuffer(this._valueHex.byteLength - 1);
			const updatedView = new Uint8Array(updatedValueHex);

			updatedView.set(new Uint8Array(this._valueHex, 1, this._valueHex.byteLength - 1));

			this._valueHex = updatedValueHex.slice(0);
		}
		else
		{
			if(expectedLength !== 0)
			{
				if(this._valueHex.byteLength < expectedLength)
				{
					if((expectedLength - this._valueHex.byteLength) > 1)
						expectedLength = this._valueHex.byteLength + 1;
					
					const updatedValueHex = new ArrayBuffer(expectedLength);
					const updatedView = new Uint8Array(updatedValueHex);

					updatedView.set(view, expectedLength - this._valueHex.byteLength);

					this._valueHex = updatedValueHex.slice(0);
				}
			}
		}

		return offset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (DER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toDER(sizeOnly = false)
	{
		const view = new Uint8Array(this._valueHex);

		switch(true)
		{
			case ((view[0] & 0x80) !== 0):
				{
					const updatedValueHex = new ArrayBuffer(this._valueHex.byteLength + 1);
					const updatedView = new Uint8Array(updatedValueHex);

					updatedView[0] = 0x00;
					updatedView.set(view, 1);

					this._valueHex = updatedValueHex.slice(0);
				}
				break;
			case ((view[0] === 0x00) && ((view[1] & 0x80) === 0)):
				{
					const updatedValueHex = new ArrayBuffer(this._valueHex.byteLength - 1);
					const updatedView = new Uint8Array(updatedValueHex);

					updatedView.set(new Uint8Array(this._valueHex, 1, this._valueHex.byteLength - 1));

					this._valueHex = updatedValueHex.slice(0);
				}
				break;
			default:
		}

		return this.toBER(sizeOnly);
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = super.fromBER(inputBuffer, inputOffset, inputLength);
		if(resultOffset === (-1))
			return resultOffset;

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//noinspection JSCheckFunctionSignatures
		return this.valueHex.slice(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "IntegerValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.valueDec = this.valueDec;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Integer extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Integer" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalIntegerValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 2; // Integer
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Integer";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Compare two Integer object, or Integer and ArrayBuffer objects
	 * @param {!Integer|ArrayBuffer} otherValue
	 * @returns {boolean}
	 */
	isEqual(otherValue)
	{
		if(otherValue instanceof Integer)
		{
			if(this.valueBlock.isHexOnly && otherValue.valueBlock.isHexOnly) // Compare two ArrayBuffers
				return isEqualBuffer(this.valueBlock.valueHex, otherValue.valueBlock.valueHex);

			if(this.valueBlock.isHexOnly === otherValue.valueBlock.isHexOnly)
				return (this.valueBlock.valueDec === otherValue.valueBlock.valueDec);

			return false;
		}
		
		if(otherValue instanceof ArrayBuffer)
			return isEqualBuffer(this.valueBlock.valueHex, otherValue);

		return false;
	}
	//**********************************************************************************
	/**
	 * Convert current Integer value from BER into DER format
	 * @returns {Integer}
	 */
	convertToDER()
	{
		const integer = new Integer({ valueHex: this.valueBlock.valueHex });
		integer.valueBlock.toDER();

		return integer;
	}
	//**********************************************************************************
	/**
	 * Convert current Integer value from DER to BER format
	 * @returns {Integer}
	 */
	convertFromDER()
	{
		const expectedLength = (this.valueBlock.valueHex.byteLength % 2) ? (this.valueBlock.valueHex.byteLength + 1) : this.valueBlock.valueHex.byteLength;
		const integer = new Integer({ valueHex: this.valueBlock.valueHex });
		integer.valueBlock.fromDER(integer.valueBlock.valueHex, 0, integer.valueBlock.valueHex.byteLength, expectedLength);
		
		return integer;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Enumerated type class
//**************************************************************************************
class Enumerated extends Integer
{
	//**********************************************************************************
	/**
	 * Constructor for "Enumerated" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 10; // Enumerated
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Enumerated";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 ObjectIdentifier type class
//**************************************************************************************
class LocalSidValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalSidValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {number} [valueDec]
	 * @property {boolean} [isFirstSid]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.valueDec = getParametersValue(parameters, "valueDec", -1);
		this.isFirstSid = getParametersValue(parameters, "isFirstSid", false);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "sidBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		if(inputLength === 0)
			return inputOffset;

		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);

		this.valueHex = new ArrayBuffer(inputLength);
		let view = new Uint8Array(this.valueHex);

		for(let i = 0; i < inputLength; i++)
		{
			view[i] = intBuffer[i] & 0x7F;

			this.blockLength++;

			if((intBuffer[i] & 0x80) === 0x00)
				break;
		}

		//region Ajust size of valueHex buffer
		const tempValueHex = new ArrayBuffer(this.blockLength);
		const tempView = new Uint8Array(tempValueHex);

		for(let i = 0; i < this.blockLength; i++)
			tempView[i] = view[i];

		//noinspection JSCheckFunctionSignatures
		this.valueHex = tempValueHex.slice(0);
		view = new Uint8Array(this.valueHex);
		//endregion

		if((intBuffer[this.blockLength - 1] & 0x80) !== 0x00)
		{
			this.error = "End of input reached before message was fully decoded";
			return (-1);
		}

		if(view[0] === 0x00)
			this.warnings.push("Needlessly long format of SID encoding");

		if(this.blockLength <= 8)
			this.valueDec = utilFromBase(view, 7);
		else
		{
			this.isHexOnly = true;
			this.warnings.push("Too big SID for decoding, hex only");
		}

		return (inputOffset + this.blockLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Initial variables
		let retBuf;
		let retView;
		//endregion

		if(this.isHexOnly)
		{
			if(sizeOnly === true)
				return (new ArrayBuffer(this.valueHex.byteLength));

			const curView = new Uint8Array(this.valueHex);

			retBuf = new ArrayBuffer(this.blockLength);
			retView = new Uint8Array(retBuf);

			for(let i = 0; i < (this.blockLength - 1); i++)
				retView[i] = curView[i] | 0x80;

			retView[this.blockLength - 1] = curView[this.blockLength - 1];

			return retBuf;
		}

		const encodedBuf = utilToBase(this.valueDec, 7);
		if(encodedBuf.byteLength === 0)
		{
			this.error = "Error during encoding SID value";
			return (new ArrayBuffer(0));
		}

		retBuf = new ArrayBuffer(encodedBuf.byteLength);

		if(sizeOnly === false)
		{
			const encodedView = new Uint8Array(encodedBuf);
			retView = new Uint8Array(retBuf);

			for(let i = 0; i < (encodedBuf.byteLength - 1); i++)
				retView[i] = encodedView[i] | 0x80;

			retView[encodedBuf.byteLength - 1] = encodedView[encodedBuf.byteLength - 1];
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Create string representation of current SID block
	 * @returns {string}
	 */
	toString()
	{
		let result = "";

		if(this.isHexOnly === true)
			result = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);
		else
		{
			if(this.isFirstSid)
			{
				let sidValue = this.valueDec;

				if(this.valueDec <= 39)
					result = "0.";
				else
				{
					if(this.valueDec <= 79)
					{
						result = "1.";
						sidValue -= 40;
					}
					else
					{
						result = "2.";
						sidValue -= 80;
					}
				}

				result = result + sidValue.toString();
			}
			else
				result = this.valueDec.toString();
		}

		return result;
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.valueDec = this.valueDec;
		object.isFirstSid = this.isFirstSid;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class LocalObjectIdentifierValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalObjectIdentifierValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.fromString(getParametersValue(parameters, "value", ""));
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		let resultOffset = inputOffset;

		while(inputLength > 0)
		{
			const sidBlock = new LocalSidValueBlock();
			resultOffset = sidBlock.fromBER(inputBuffer, resultOffset, inputLength);
			if(resultOffset === (-1))
			{
				this.blockLength = 0;
				this.error = sidBlock.error;
				return resultOffset;
			}

			if(this.value.length === 0)
				sidBlock.isFirstSid = true;

			this.blockLength += sidBlock.blockLength;
			inputLength -= sidBlock.blockLength;

			this.value.push(sidBlock);
		}

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		let retBuf = new ArrayBuffer(0);

		for(let i = 0; i < this.value.length; i++)
		{
			const valueBuf = this.value[i].toBER(sizeOnly);
			if(valueBuf.byteLength === 0)
			{
				this.error = this.value[i].error;
				return (new ArrayBuffer(0));
			}

			retBuf = utilConcatBuf(retBuf, valueBuf);
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Create "LocalObjectIdentifierValueBlock" class from string
	 * @param {string} string Input string to convert from
	 * @returns {boolean}
	 */
	fromString(string)
	{
		this.value = []; // Clear existing SID values

		let pos1 = 0;
		let pos2 = 0;

		let sid = "";

		let flag = false;

		do
		{
			pos2 = string.indexOf(".", pos1);
			if(pos2 === (-1))
				sid = string.substr(pos1);
			else
				sid = string.substr(pos1, pos2 - pos1);

			pos1 = pos2 + 1;

			if(flag)
			{
				const sidBlock = this.value[0];

				let plus = 0;

				switch(sidBlock.valueDec)
				{
					case 0:
						break;
					case 1:
						plus = 40;
						break;
					case 2:
						plus = 80;
						break;
					default:
						this.value = []; // clear SID array
						return false; // ???
				}

				const parsedSID = parseInt(sid, 10);
				if(isNaN(parsedSID))
					return true;

				sidBlock.valueDec = parsedSID + plus;

				flag = false;
			}
			else
			{
				const sidBlock = new LocalSidValueBlock();
				sidBlock.valueDec = parseInt(sid, 10);
				if(isNaN(sidBlock.valueDec))
					return true;

				if(this.value.length === 0)
				{
					sidBlock.isFirstSid = true;
					flag = true;
				}

				this.value.push(sidBlock);
			}
		} while(pos2 !== (-1));

		return true;
	}
	//**********************************************************************************
	/**
	 * Converts "LocalObjectIdentifierValueBlock" class to string
	 * @returns {string}
	 */
	toString()
	{
		let result = "";
		let isHexOnly = false;

		for(let i = 0; i < this.value.length; i++)
		{
			isHexOnly = this.value[i].isHexOnly;

			let sidStr = this.value[i].toString();

			if(i !== 0)
				result = `${result}.`;

			if(isHexOnly)
			{
				sidStr = `{${sidStr}}`;

				if(this.value[i].isFirstSid)
					result = `2.{${sidStr} - 80}`;
				else
					result = result + sidStr;
			}
			else
				result = result + sidStr;
		}

		return result;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "ObjectIdentifierValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.toString();
		object.sidArray = [];
		for(let i = 0; i < this.value.length; i++)
			object.sidArray.push(this.value[i].toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class ObjectIdentifier extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "ObjectIdentifier" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalObjectIdentifierValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 6; // OBJECT IDENTIFIER
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "ObjectIdentifier";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of all string's classes
//**************************************************************************************
class LocalUtf8StringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Constructor for "LocalUtf8StringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isHexOnly = true;
		this.value = ""; // String representation of decoded ArrayBuffer
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Utf8StringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class Utf8String extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Utf8String" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalUtf8StringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 12; // Utf8String
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Utf8String";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.valueBlock.value = String.fromCharCode.apply(null, new Uint8Array(inputBuffer));

		try
		{
			//noinspection JSDeprecatedSymbols
			this.valueBlock.value = decodeURIComponent(escape(this.valueBlock.value));
		}
		catch(ex)
		{
			this.warnings.push(`Error during \"decodeURIComponent\": ${ex}, using raw string`);
		}
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		//noinspection JSDeprecatedSymbols
		const str = unescape(encodeURIComponent(inputString));
		const strLen = str.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLen);
		const view = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLen; i++)
			view[i] = str.charCodeAt(i);

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalBaseBlock
 * @extends LocalHexBlock
 */
class LocalBmpStringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBmpStringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isHexOnly = true;
		this.value = "";
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BmpStringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class BmpString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "BmpString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBmpStringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 30; // BmpString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BmpString";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		//noinspection JSCheckFunctionSignatures
		const copyBuffer = inputBuffer.slice(0);
		const valueView = new Uint8Array(copyBuffer);

		for(let i = 0; i < valueView.length; i = i + 2)
		{
			const temp = valueView[i];

			valueView[i] = valueView[i + 1];
			valueView[i + 1] = temp;
		}

		this.valueBlock.value = String.fromCharCode.apply(null, new Uint16Array(copyBuffer));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		const strLength = inputString.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLength * 2);
		const valueHexView = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLength; i++)
		{
			const codeBuf = utilToBase(inputString.charCodeAt(i), 8);
			const codeView = new Uint8Array(codeBuf);
			if(codeView.length > 2)
				continue;

			const dif = 2 - codeView.length;

			for(let j = (codeView.length - 1); j >= 0; j--)
				valueHexView[i * 2 + j + dif] = codeView[j];
		}

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
class LocalUniversalStringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalUniversalStringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isHexOnly = true;
		this.value = "";
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "UniversalStringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class UniversalString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "UniversalString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalUniversalStringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 28; // UniversalString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "UniversalString";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		//noinspection JSCheckFunctionSignatures
		const copyBuffer = inputBuffer.slice(0);
		const valueView = new Uint8Array(copyBuffer);

		for(let i = 0; i < valueView.length; i = i + 4)
		{
			valueView[i] = valueView[i + 3];
			valueView[i + 1] = valueView[i + 2];
			valueView[i + 2] = 0x00;
			valueView[i + 3] = 0x00;
		}

		this.valueBlock.value = String.fromCharCode.apply(null, new Uint32Array(copyBuffer));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		const strLength = inputString.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLength * 4);
		const valueHexView = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLength; i++)
		{
			const codeBuf = utilToBase(inputString.charCodeAt(i), 8);
			const codeView = new Uint8Array(codeBuf);
			if(codeView.length > 4)
				continue;

			const dif = 4 - codeView.length;

			for(let j = (codeView.length - 1); j >= 0; j--)
				valueHexView[i * 4 + j + dif] = codeView[j];
		}

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
class LocalSimpleStringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalSimpleStringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.value = "";
		this.isHexOnly = true;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "SimpleStringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class LocalSimpleStringBlock extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalSimpleStringBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalSimpleStringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "SIMPLESTRING";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.valueBlock.value = String.fromCharCode.apply(null, new Uint8Array(inputBuffer));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		const strLen = inputString.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLen);
		const view = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLen; i++)
			view[i] = inputString.charCodeAt(i);

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class NumericString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "NumericString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 18; // NumericString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "NumericString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class PrintableString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "PrintableString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 19; // PrintableString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "PrintableString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class TeletexString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "TeletexString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 20; // TeletexString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "TeletexString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class VideotexString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "VideotexString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 21; // VideotexString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "VideotexString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class IA5String extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "IA5String" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 22; // IA5String
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "IA5String";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class GraphicString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "GraphicString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 25; // GraphicString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "GraphicString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class VisibleString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "VisibleString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 26; // VisibleString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "VisibleString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class GeneralString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "GeneralString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 27; // GeneralString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "GeneralString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class CharacterString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "CharacterString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 29; // CharacterString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "CharacterString";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of all date and time classes
//**************************************************************************************
/**
 * @extends VisibleString
 */
class UTCTime extends VisibleString
{
	//**********************************************************************************
	/**
	 * Constructor for "UTCTime" class
	 * @param {Object} [parameters={}]
	 * @property {string} [value] String representatio of the date
	 * @property {Date} [valueDate] JavaScript "Date" object
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.year = 0;
		this.month = 0;
		this.day = 0;
		this.hour = 0;
		this.minute = 0;
		this.second = 0;

		//region Create UTCTime from ASN.1 UTC string value
		if("value" in parameters)
		{
			this.fromString(parameters.value);

			this.valueBlock.valueHex = new ArrayBuffer(parameters.value.length);
			const view = new Uint8Array(this.valueBlock.valueHex);

			for(let i = 0; i < parameters.value.length; i++)
				view[i] = parameters.value.charCodeAt(i);
		}
		//endregion
		//region Create GeneralizedTime from JavaScript Date type
		if("valueDate" in parameters)
		{
			this.fromDate(parameters.valueDate);
			this.valueBlock.valueHex = this.toBuffer();
		}
		//endregion

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 23; // UTCTime
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.fromString(String.fromCharCode.apply(null, new Uint8Array(inputBuffer)));
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal string into ArrayBuffer
	 * @returns {ArrayBuffer}
	 */
	toBuffer()
	{
		const str = this.toString();

		const buffer = new ArrayBuffer(str.length);
		const view = new Uint8Array(buffer);

		for(let i = 0; i < str.length; i++)
			view[i] = str.charCodeAt(i);

		return buffer;
	}
	//**********************************************************************************
	/**
	 * Function converting "Date" object into ASN.1 internal string
	 * @param {!Date} inputDate JavaScript "Date" object
	 */
	fromDate(inputDate)
	{
		this.year = inputDate.getUTCFullYear();
		this.month = inputDate.getUTCMonth() + 1;
		this.day = inputDate.getUTCDate();
		this.hour = inputDate.getUTCHours();
		this.minute = inputDate.getUTCMinutes();
		this.second = inputDate.getUTCSeconds();
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Function converting ASN.1 internal string into "Date" object
	 * @returns {Date}
	 */
	toDate()
	{
		return (new Date(Date.UTC(this.year, this.month - 1, this.day, this.hour, this.minute, this.second)));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		//region Parse input string
		const parser = /(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/ig;
		const parserArray = parser.exec(inputString);
		if(parserArray === null)
		{
			this.error = "Wrong input string for convertion";
			return;
		}
		//endregion

		//region Store parsed values
		const year = parseInt(parserArray[1], 10);
		if(year >= 50)
			this.year = 1900 + year;
		else
			this.year = 2000 + year;

		this.month = parseInt(parserArray[2], 10);
		this.day = parseInt(parserArray[3], 10);
		this.hour = parseInt(parserArray[4], 10);
		this.minute = parseInt(parserArray[5], 10);
		this.second = parseInt(parserArray[6], 10);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal class into JavaScript string
	 * @returns {string}
	 */
	toString()
	{
		const outputArray = new Array(7);

		outputArray[0] = padNumber(((this.year < 2000) ? (this.year - 1900) : (this.year - 2000)), 2);
		outputArray[1] = padNumber(this.month, 2);
		outputArray[2] = padNumber(this.day, 2);
		outputArray[3] = padNumber(this.hour, 2);
		outputArray[4] = padNumber(this.minute, 2);
		outputArray[5] = padNumber(this.second, 2);
		outputArray[6] = "Z";

		return outputArray.join("");
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "UTCTime";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.year = this.year;
		object.month = this.month;
		object.day = this.day;
		object.hour = this.hour;
		object.minute = this.minute;
		object.second = this.second;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends VisibleString
 */
class GeneralizedTime extends VisibleString
{
	//**********************************************************************************
	/**
	 * Constructor for "GeneralizedTime" class
	 * @param {Object} [parameters={}]
	 * @property {string} [value] String representatio of the date
	 * @property {Date} [valueDate] JavaScript "Date" object
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.year = 0;
		this.month = 0;
		this.day = 0;
		this.hour = 0;
		this.minute = 0;
		this.second = 0;
		this.millisecond = 0;

		//region Create UTCTime from ASN.1 UTC string value
		if("value" in parameters)
		{
			this.fromString(parameters.value);

			this.valueBlock.valueHex = new ArrayBuffer(parameters.value.length);
			const view = new Uint8Array(this.valueBlock.valueHex);

			for(let i = 0; i < parameters.value.length; i++)
				view[i] = parameters.value.charCodeAt(i);
		}
		//endregion
		//region Create GeneralizedTime from JavaScript Date type
		if("valueDate" in parameters)
		{
			this.fromDate(parameters.valueDate);
			this.valueBlock.valueHex = this.toBuffer();
		}
		//endregion

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 24; // GeneralizedTime
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.fromString(String.fromCharCode.apply(null, new Uint8Array(inputBuffer)));
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal string into ArrayBuffer
	 * @returns {ArrayBuffer}
	 */
	toBuffer()
	{
		const str = this.toString();

		const buffer = new ArrayBuffer(str.length);
		const view = new Uint8Array(buffer);

		for(let i = 0; i < str.length; i++)
			view[i] = str.charCodeAt(i);

		return buffer;
	}
	//**********************************************************************************
	/**
	 * Function converting "Date" object into ASN.1 internal string
	 * @param {!Date} inputDate JavaScript "Date" object
	 */
	fromDate(inputDate)
	{
		this.year = inputDate.getUTCFullYear();
		this.month = inputDate.getUTCMonth() + 1;
		this.day = inputDate.getUTCDate();
		this.hour = inputDate.getUTCHours();
		this.minute = inputDate.getUTCMinutes();
		this.second = inputDate.getUTCSeconds();
		this.millisecond = inputDate.getUTCMilliseconds();
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Function converting ASN.1 internal string into "Date" object
	 * @returns {Date}
	 */
	toDate()
	{
		return (new Date(Date.UTC(this.year, this.month - 1, this.day, this.hour, this.minute, this.second, this.millisecond)));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		//region Initial variables
		let isUTC = false;

		let timeString = "";
		let dateTimeString = "";
		let fractionPart = 0;

		let parser;

		let hourDifference = 0;
		let minuteDifference = 0;
		//endregion

		//region Convert as UTC time
		if(inputString[inputString.length - 1] === "Z")
		{
			timeString = inputString.substr(0, inputString.length - 1);

			isUTC = true;
		}
		//endregion
		//region Convert as local time
		else
		{
			//noinspection JSPrimitiveTypeWrapperUsage
			const number = new Number(inputString[inputString.length - 1]);

			if(isNaN(number.valueOf()))
				throw new Error("Wrong input string for convertion");

			timeString = inputString;
		}
		//endregion

		//region Check that we do not have a "+" and "-" symbols inside UTC time
		if(isUTC)
		{
			if(timeString.indexOf("+") !== (-1))
				throw new Error("Wrong input string for convertion");

			if(timeString.indexOf("-") !== (-1))
				throw new Error("Wrong input string for convertion");
		}
		//endregion
		//region Get "UTC time difference" in case of local time
		else
		{
			let multiplier = 1;
			let differencePosition = timeString.indexOf("+");
			let differenceString = "";

			if(differencePosition === (-1))
			{
				differencePosition = timeString.indexOf("-");
				multiplier = (-1);
			}

			if(differencePosition !== (-1))
			{
				differenceString = timeString.substr(differencePosition + 1);
				timeString = timeString.substr(0, differencePosition);

				if((differenceString.length !== 2) && (differenceString.length !== 4))
					throw new Error("Wrong input string for convertion");

				//noinspection JSPrimitiveTypeWrapperUsage
				let number = new Number(differenceString.substr(0, 2));

				if(isNaN(number.valueOf()))
					throw new Error("Wrong input string for convertion");

				hourDifference = multiplier * number;

				if(differenceString.length === 4)
				{
					//noinspection JSPrimitiveTypeWrapperUsage
					number = new Number(differenceString.substr(2, 2));

					if(isNaN(number.valueOf()))
						throw new Error("Wrong input string for convertion");

					minuteDifference = multiplier * number;
				}
			}
		}
		//endregion

		//region Get position of fraction point
		let fractionPointPosition = timeString.indexOf("."); // Check for "full stop" symbol
		if(fractionPointPosition === (-1))
			fractionPointPosition = timeString.indexOf(","); // Check for "comma" symbol
		//endregion

		//region Get fraction part
		if(fractionPointPosition !== (-1))
		{
			//noinspection JSPrimitiveTypeWrapperUsage
			const fractionPartCheck = new Number(`0${timeString.substr(fractionPointPosition)}`);

			if(isNaN(fractionPartCheck.valueOf()))
				throw new Error("Wrong input string for convertion");

			fractionPart = fractionPartCheck.valueOf();

			dateTimeString = timeString.substr(0, fractionPointPosition);
		}
		else
			dateTimeString = timeString;
		//endregion

		//region Parse internal date
		switch(true)
		{
			case (dateTimeString.length === 8): // "YYYYMMDD"
				parser = /(\d{4})(\d{2})(\d{2})/ig;
				if(fractionPointPosition !== (-1))
					throw new Error("Wrong input string for convertion"); // Here we should not have a "fraction point"
				break;
			case (dateTimeString.length === 10): // "YYYYMMDDHH"
				parser = /(\d{4})(\d{2})(\d{2})(\d{2})/ig;

				if(fractionPointPosition !== (-1))
				{
					let fractionResult = 60 * fractionPart;
					this.minute = Math.floor(fractionResult);

					fractionResult = 60 * (fractionResult - this.minute);
					this.second = Math.floor(fractionResult);

					fractionResult = 1000 * (fractionResult - this.second);
					this.millisecond = Math.floor(fractionResult);
				}
				break;
			case (dateTimeString.length === 12): // "YYYYMMDDHHMM"
				parser = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/ig;

				if(fractionPointPosition !== (-1))
				{
					let fractionResult = 60 * fractionPart;
					this.second = Math.floor(fractionResult);

					fractionResult = 1000 * (fractionResult - this.second);
					this.millisecond = Math.floor(fractionResult);
				}
				break;
			case (dateTimeString.length === 14): // "YYYYMMDDHHMMSS"
				parser = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/ig;

				if(fractionPointPosition !== (-1))
				{
					const fractionResult = 1000 * fractionPart;
					this.millisecond = Math.floor(fractionResult);
				}
				break;
			default:
				throw new Error("Wrong input string for convertion");
		}
		//endregion

		//region Put parsed values at right places
		const parserArray = parser.exec(dateTimeString);
		if(parserArray === null)
			throw new Error("Wrong input string for convertion");

		for(let j = 1; j < parserArray.length; j++)
		{
			switch(j)
			{
				case 1:
					this.year = parseInt(parserArray[j], 10);
					break;
				case 2:
					this.month = parseInt(parserArray[j], 10);
					break;
				case 3:
					this.day = parseInt(parserArray[j], 10);
					break;
				case 4:
					this.hour = parseInt(parserArray[j], 10) + hourDifference;
					break;
				case 5:
					this.minute = parseInt(parserArray[j], 10) + minuteDifference;
					break;
				case 6:
					this.second = parseInt(parserArray[j], 10);
					break;
				default:
					throw new Error("Wrong input string for convertion");
			}
		}
		//endregion

		//region Get final date
		if(isUTC === false)
		{
			const tempDate = new Date(this.year, this.month, this.day, this.hour, this.minute, this.second, this.millisecond);

			this.year = tempDate.getUTCFullYear();
			this.month = tempDate.getUTCMonth();
			this.day = tempDate.getUTCDay();
			this.hour = tempDate.getUTCHours();
			this.minute = tempDate.getUTCMinutes();
			this.second = tempDate.getUTCSeconds();
			this.millisecond = tempDate.getUTCMilliseconds();
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal class into JavaScript string
	 * @returns {string}
	 */
	toString()
	{
		const outputArray = [];

		outputArray.push(padNumber(this.year, 4));
		outputArray.push(padNumber(this.month, 2));
		outputArray.push(padNumber(this.day, 2));
		outputArray.push(padNumber(this.hour, 2));
		outputArray.push(padNumber(this.minute, 2));
		outputArray.push(padNumber(this.second, 2));
		if(this.millisecond !== 0)
		{
			outputArray.push(".");
			outputArray.push(padNumber(this.millisecond, 3));
		}
		outputArray.push("Z");

		return outputArray.join("");
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "GeneralizedTime";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.year = this.year;
		object.month = this.month;
		object.day = this.day;
		object.hour = this.hour;
		object.minute = this.minute;
		object.second = this.second;
		object.millisecond = this.millisecond;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class DATE extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "DATE" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 31; // DATE
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "DATE";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class TimeOfDay extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "TimeOfDay" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 32; // TimeOfDay
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "TimeOfDay";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class DateTime extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "DateTime" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 33; // DateTime
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "DateTime";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class Duration extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "Duration" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 34; // Duration
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Duration";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class TIME extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "Time" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 14; // Time
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "TIME";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type Choice
//**************************************************************************************
class Choice
{
	//**********************************************************************************
	/**
	 * Constructor for "Choice" class
	 * @param {Object} [parameters={}]
	 * @property {Array} [value] Array of ASN.1 types for make a choice from
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.value = getParametersValue(parameters, "value", []);
		this.optional = getParametersValue(parameters, "optional", false);
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type Any
//**************************************************************************************
class Any
{
	//**********************************************************************************
	/**
	 * Constructor for "Any" class
	 * @param {Object} [parameters={}]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.name = getParametersValue(parameters, "name", "");
		this.optional = getParametersValue(parameters, "optional", false);
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type Repeated
//**************************************************************************************
class Repeated
{
	//**********************************************************************************
	/**
	 * Constructor for "Repeated" class
	 * @param {Object} [parameters={}]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.name = getParametersValue(parameters, "name", "");
		this.optional = getParametersValue(parameters, "optional", false);
		this.value = getParametersValue(parameters, "value", new Any());
		this.local = getParametersValue(parameters, "local", false); // Could local or global array to store elements
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type RawData
//**************************************************************************************
/**
 * @description Special class providing ability to have "toBER/fromBER" for raw ArrayBuffer
 */
class RawData
{
	//**********************************************************************************
	/**
	 * Constructor for "Repeated" class
	 * @param {Object} [parameters={}]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.data = getParametersValue(parameters, "data", new ArrayBuffer(0));
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		this.data = inputBuffer.slice(inputOffset, inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return this.data;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Major ASN.1 BER decoding function
//**************************************************************************************
/**
 * Internal library function for decoding ASN.1 BER
 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
 * @returns {{offset: number, result: Object}}
 */
function LocalFromBER(inputBuffer, inputOffset, inputLength)
{
	const incomingOffset = inputOffset; // Need to store initial offset since "inputOffset" is changing in the function

	//region Local function changing a type for ASN.1 classes
	function localChangeType(inputObject, newType)
	{
		if(inputObject instanceof newType)
			return inputObject;

		const newObject = new newType();
		newObject.idBlock = inputObject.idBlock;
		newObject.lenBlock = inputObject.lenBlock;
		newObject.warnings = inputObject.warnings;
		//noinspection JSCheckFunctionSignatures
		newObject.valueBeforeDecode = inputObject.valueBeforeDecode.slice(0);

		return newObject;
	}
	//endregion

	//region Create a basic ASN.1 type since we need to return errors and warnings from the function
	let returnObject = new BaseBlock({}, Object);
	//endregion

	//region Basic check for parameters
	if(checkBufferParams(new LocalBaseBlock(), inputBuffer, inputOffset, inputLength) === false)
	{
		returnObject.error = "Wrong input parameters";
		return {
			offset: (-1),
			result: returnObject
		};
	}
	//endregion

	//region Getting Uint8Array from ArrayBuffer
	const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
	//endregion

	//region Initial checks
	if(intBuffer.length === 0)
	{
		this.error = "Zero buffer length";
		return {
			offset: (-1),
			result: returnObject
		};
	}
	//endregion

	//region Decode indentifcation block of ASN.1 BER structure
	let resultOffset = returnObject.idBlock.fromBER(inputBuffer, inputOffset, inputLength);
	returnObject.warnings.concat(returnObject.idBlock.warnings);
	if(resultOffset === (-1))
	{
		returnObject.error = returnObject.idBlock.error;
		return {
			offset: (-1),
			result: returnObject
		};
	}

	inputOffset = resultOffset;
	inputLength -= returnObject.idBlock.blockLength;
	//endregion

	//region Decode length block of ASN.1 BER structure
	resultOffset = returnObject.lenBlock.fromBER(inputBuffer, inputOffset, inputLength);
	returnObject.warnings.concat(returnObject.lenBlock.warnings);
	if(resultOffset === (-1))
	{
		returnObject.error = returnObject.lenBlock.error;
		return {
			offset: (-1),
			result: returnObject
		};
	}

	inputOffset = resultOffset;
	inputLength -= returnObject.lenBlock.blockLength;
	//endregion

	//region Check for usign indefinite length form in encoding for primitive types
	if((returnObject.idBlock.isConstructed === false) &&
		(returnObject.lenBlock.isIndefiniteForm === true))
	{
		returnObject.error = "Indefinite length form used for primitive encoding form";
		return {
			offset: (-1),
			result: returnObject
		};
	}
	//endregion

	//region Switch ASN.1 block type
	let newASN1Type = BaseBlock;

	switch(returnObject.idBlock.tagClass)
	{
		//region UNIVERSAL
		case 1:
			//region Check for reserved tag numbers
			if((returnObject.idBlock.tagNumber >= 37) &&
				(returnObject.idBlock.isHexOnly === false))
			{
				returnObject.error = "UNIVERSAL 37 and upper tags are reserved by ASN.1 standard";
				return {
					offset: (-1),
					result: returnObject
				};
			}
			//endregion

			switch(returnObject.idBlock.tagNumber)
			{
				//region EndOfContent type
				case 0:
					//region Check for EndOfContent type
					if((returnObject.idBlock.isConstructed === true) &&
						(returnObject.lenBlock.length > 0))
					{
						returnObject.error = "Type [UNIVERSAL 0] is reserved";
						return {
							offset: (-1),
							result: returnObject
						};
					}
					//endregion

					newASN1Type = EndOfContent;

					break;
				//endregion
				//region Boolean type
				case 1:
					newASN1Type = Boolean;
					break;
				//endregion
				//region Integer type
				case 2:
					newASN1Type = Integer;
					break;
				//endregion
				//region BitString type
				case 3:
					newASN1Type = BitString;
					break;
				//endregion
				//region OctetString type
				case 4:
					newASN1Type = OctetString;
					break;
				//endregion
				//region Null type
				case 5:
					newASN1Type = Null;
					break;
				//endregion
				//region OBJECT IDENTIFIER type
				case 6:
					newASN1Type = ObjectIdentifier;
					break;
				//endregion
				//region Enumerated type
				case 10:
					newASN1Type = Enumerated;
					break;
				//endregion
				//region Utf8String type
				case 12:
					newASN1Type = Utf8String;
					break;
				//endregion
				//region Time type
				case 14:
					newASN1Type = TIME;
					break;
				//endregion
				//region ASN.1 reserved type
				case 15:
					returnObject.error = "[UNIVERSAL 15] is reserved by ASN.1 standard";
					return {
						offset: (-1),
						result: returnObject
					};
				//endregion
				//region Sequence type
				case 16:
					newASN1Type = Sequence;
					break;
				//endregion
				//region Set type
				case 17:
					newASN1Type = Set;
					break;
				//endregion
				//region NumericString type
				case 18:
					newASN1Type = NumericString;
					break;
				//endregion
				//region PrintableString type
				case 19:
					newASN1Type = PrintableString;
					break;
				//endregion
				//region TeletexString type
				case 20:
					newASN1Type = TeletexString;
					break;
				//endregion
				//region VideotexString type
				case 21:
					newASN1Type = VideotexString;
					break;
				//endregion
				//region IA5String type
				case 22:
					newASN1Type = IA5String;
					break;
				//endregion
				//region UTCTime type
				case 23:
					newASN1Type = UTCTime;
					break;
				//endregion
				//region GeneralizedTime type
				case 24:
					newASN1Type = GeneralizedTime;
					break;
				//endregion
				//region GraphicString type
				case 25:
					newASN1Type = GraphicString;
					break;
				//endregion
				//region VisibleString type
				case 26:
					newASN1Type = VisibleString;
					break;
				//endregion
				//region GeneralString type
				case 27:
					newASN1Type = GeneralString;
					break;
				//endregion
				//region UniversalString type
				case 28:
					newASN1Type = UniversalString;
					break;
				//endregion
				//region CharacterString type
				case 29:
					newASN1Type = CharacterString;
					break;
				//endregion
				//region BmpString type
				case 30:
					newASN1Type = BmpString;
					break;
				//endregion
				//region DATE type
				case 31:
					newASN1Type = DATE;
					break;
				//endregion
				//region TimeOfDay type
				case 32:
					newASN1Type = TimeOfDay;
					break;
				//endregion
				//region Date-Time type
				case 33:
					newASN1Type = DateTime;
					break;
				//endregion
				//region Duration type
				case 34:
					newASN1Type = Duration;
					break;
				//endregion
				//region default
				default:
					{
						let newObject;

						if(returnObject.idBlock.isConstructed === true)
							newObject = new Constructed();
						else
							newObject = new Primitive();

						newObject.idBlock = returnObject.idBlock;
						newObject.lenBlock = returnObject.lenBlock;
						newObject.warnings = returnObject.warnings;

						returnObject = newObject;

						resultOffset = returnObject.fromBER(inputBuffer, inputOffset, inputLength);
					}
				//endregion
			}
			break;
		//endregion
		//region All other tag classes
		case 2: // APPLICATION
		case 3: // CONTEXT-SPECIFIC
		case 4: // PRIVATE
		default:
			{
				if(returnObject.idBlock.isConstructed === true)
					newASN1Type = Constructed;
				else
					newASN1Type = Primitive;
			}
		//endregion
	}
	//endregion

	//region Change type and perform BER decoding
	returnObject = localChangeType(returnObject, newASN1Type);
	resultOffset = returnObject.fromBER(inputBuffer, inputOffset, (returnObject.lenBlock.isIndefiniteForm === true) ? inputLength : returnObject.lenBlock.length);
	//endregion

	//region Coping incoming buffer for entire ASN.1 block
	returnObject.valueBeforeDecode = inputBuffer.slice(incomingOffset, incomingOffset + returnObject.blockLength);
	//endregion

	return {
		offset: resultOffset,
		result: returnObject
	};
}
//**************************************************************************************
/**
 * Major function for decoding ASN.1 BER array into internal library structuries
 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array of bytes
 */
function fromBER(inputBuffer)
{
	if(inputBuffer.byteLength === 0)
	{
		const result = new BaseBlock({}, Object);
		result.error = "Input buffer has zero length";

		return {
			offset: (-1),
			result
		};
	}

	return LocalFromBER(inputBuffer, 0, inputBuffer.byteLength);
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Major scheme verification function
//**************************************************************************************
/**
 * Compare of two ASN.1 object trees
 * @param {!Object} root Root of input ASN.1 object tree
 * @param {!Object} inputData Input ASN.1 object tree
 * @param {!Object} inputSchema Input ASN.1 schema to compare with
 * @return {{verified: boolean}|{verified:boolean, result: Object}}
 */
function compareSchema(root, inputData, inputSchema)
{
	//region Special case for Choice schema element type
	if(inputSchema instanceof Choice)
	{
		const choiceResult = false;

		for(let j = 0; j < inputSchema.value.length; j++)
		{
			const result = compareSchema(root, inputData, inputSchema.value[j]);
			if(result.verified === true)
			{
				return {
					verified: true,
					result: root
				};
			}
		}

		if(choiceResult === false)
		{
			const _result = {
				verified: false,
				result: {
					error: "Wrong values for Choice type"
				}
			};

			if(inputSchema.hasOwnProperty("name"))
				_result.name = inputSchema.name;

			return _result;
		}
	}
	//endregion

	//region Special case for Any schema element type
	if(inputSchema instanceof Any)
	{
		//region Add named component of ASN.1 schema
		if(inputSchema.hasOwnProperty("name"))
			root[inputSchema.name] = inputData;
		//endregion

		return {
			verified: true,
			result: root
		};
	}
	//endregion

	//region Initial check
	if((root instanceof Object) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong root object" }
		};
	}

	if((inputData instanceof Object) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 data" }
		};
	}

	if((inputSchema instanceof Object) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(("idBlock" in inputSchema) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}
	//endregion

	//region Comparing idBlock properties in ASN.1 data and ASN.1 schema
	//region Encode and decode ASN.1 schema idBlock
	/// <remarks>This encoding/decoding is neccessary because could be an errors in schema definition</remarks>
	if(("fromBER" in inputSchema.idBlock) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(("toBER" in inputSchema.idBlock) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	const encodedId = inputSchema.idBlock.toBER(false);
	if(encodedId.byteLength === 0)
	{
		return {
			verified: false,
			result: { error: "Error encoding idBlock for ASN.1 schema" }
		};
	}

	const decodedOffset = inputSchema.idBlock.fromBER(encodedId, 0, encodedId.byteLength);
	if(decodedOffset === (-1))
	{
		return {
			verified: false,
			result: { error: "Error decoding idBlock for ASN.1 schema" }
		};
	}
	//endregion

	//region tagClass
	if(inputSchema.idBlock.hasOwnProperty("tagClass") === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.tagClass !== inputData.idBlock.tagClass)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region tagNumber
	if(inputSchema.idBlock.hasOwnProperty("tagNumber") === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.tagNumber !== inputData.idBlock.tagNumber)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region isConstructed
	if(inputSchema.idBlock.hasOwnProperty("isConstructed") === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.isConstructed !== inputData.idBlock.isConstructed)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region isHexOnly
	if(("isHexOnly" in inputSchema.idBlock) === false) // Since 'isHexOnly' is an inhirited property
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.isHexOnly !== inputData.idBlock.isHexOnly)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region valueHex
	if(inputSchema.idBlock.isHexOnly === true)
	{
		if(("valueHex" in inputSchema.idBlock) === false) // Since 'valueHex' is an inhirited property
		{
			return {
				verified: false,
				result: { error: "Wrong ASN.1 schema" }
			};
		}

		const schemaView = new Uint8Array(inputSchema.idBlock.valueHex);
		const asn1View = new Uint8Array(inputData.idBlock.valueHex);

		if(schemaView.length !== asn1View.length)
		{
			return {
				verified: false,
				result: root
			};
		}

		for(let i = 0; i < schemaView.length; i++)
		{
			if(schemaView[i] !== asn1View[1])
			{
				return {
					verified: false,
					result: root
				};
			}
		}
	}
	//endregion
	//endregion

	//region Add named component of ASN.1 schema
	if(inputSchema.hasOwnProperty("name"))
	{
		inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
		if(inputSchema.name !== "")
			root[inputSchema.name] = inputData;
	}
	//endregion

	//region Getting next ASN.1 block for comparition
	if(inputSchema.idBlock.isConstructed === true)
	{
		let admission = 0;
		let result = { verified: false };

		let maxLength = inputSchema.valueBlock.value.length;

		if(maxLength > 0)
		{
			if(inputSchema.valueBlock.value[0] instanceof Repeated)
				maxLength = inputData.valueBlock.value.length;
		}

		//region Special case when constructive value has no elements
		if(maxLength === 0)
		{
			return {
				verified: true,
				result: root
			};
		}
		//endregion

		//region Special case when "inputData" has no values and "inputSchema" has all optional values
		if((inputData.valueBlock.value.length === 0) &&
			(inputSchema.valueBlock.value.length !== 0))
		{
			let _optional = true;

			for(let i = 0; i < inputSchema.valueBlock.value.length; i++)
				_optional = _optional && (inputSchema.valueBlock.value[i].optional || false);

			if(_optional === true)
			{
				return {
					verified: true,
					result: root
				};
			}

			//region Delete early added name of block
			if(inputSchema.hasOwnProperty("name"))
			{
				inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
				if(inputSchema.name !== "")
					delete root[inputSchema.name];
			}
			//endregion

			root.error = "Inconsistent object length";

			return {
				verified: false,
				result: root
			};
		}
		//endregion

		for(let i = 0; i < maxLength; i++)
		{
			//region Special case when there is an "optional" element of ASN.1 schema at the end
			if((i - admission) >= inputData.valueBlock.value.length)
			{
				if(inputSchema.valueBlock.value[i].optional === false)
				{
					const _result = {
						verified: false,
						result: root
					};

					root.error = "Inconsistent length between ASN.1 data and schema";

					//region Delete early added name of block
					if(inputSchema.hasOwnProperty("name"))
					{
						inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
						if(inputSchema.name !== "")
						{
							delete root[inputSchema.name];
							_result.name = inputSchema.name;
						}
					}
					//endregion

					return _result;
				}
			}
			//endregion
			else
			{
				//region Special case for Repeated type of ASN.1 schema element
				if(inputSchema.valueBlock.value[0] instanceof Repeated)
				{
					result = compareSchema(root, inputData.valueBlock.value[i], inputSchema.valueBlock.value[0].value);
					if(result.verified === false)
					{
						if(inputSchema.valueBlock.value[0].optional === true)
							admission++;
						else
						{
							//region Delete early added name of block
							if(inputSchema.hasOwnProperty("name"))
							{
								inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
								if(inputSchema.name !== "")
									delete root[inputSchema.name];
							}
							//endregion

							return result;
						}
					}

					if(("name" in inputSchema.valueBlock.value[0]) && (inputSchema.valueBlock.value[0].name.length > 0))
					{
						let arrayRoot = {};

						if(("local" in inputSchema.valueBlock.value[0]) && (inputSchema.valueBlock.value[0].local === true))
							arrayRoot = inputData;
						else
							arrayRoot = root;

						if(typeof arrayRoot[inputSchema.valueBlock.value[0].name] === "undefined")
							arrayRoot[inputSchema.valueBlock.value[0].name] = [];

						arrayRoot[inputSchema.valueBlock.value[0].name].push(inputData.valueBlock.value[i]);
					}
				}
				//endregion
				else
				{
					result = compareSchema(root, inputData.valueBlock.value[i - admission], inputSchema.valueBlock.value[i]);
					if(result.verified === false)
					{
						if(inputSchema.valueBlock.value[i].optional === true)
							admission++;
						else
						{
							//region Delete early added name of block
							if(inputSchema.hasOwnProperty("name"))
							{
								inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
								if(inputSchema.name !== "")
									delete root[inputSchema.name];
							}
							//endregion

							return result;
						}
					}
				}
			}
		}

		if(result.verified === false) // The situation may take place if last element is "optional" and verification failed
		{
			const _result = {
				verified: false,
				result: root
			};

			//region Delete early added name of block
			if(inputSchema.hasOwnProperty("name"))
			{
				inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
				if(inputSchema.name !== "")
				{
					delete root[inputSchema.name];
					_result.name = inputSchema.name;
				}
			}
			//endregion

			return _result;
		}

		return {
			verified: true,
			result: root
		};
	}
	//endregion
	//region Ability to parse internal value for primitive-encoded value (value of OctetString, for example)
	if(("primitiveSchema" in inputSchema) &&
		("valueHex" in inputData.valueBlock))
	{
		//region Decoding of raw ASN.1 data
		const asn1 = fromBER(inputData.valueBlock.valueHex);
		if(asn1.offset === (-1))
		{
			const _result = {
				verified: false,
				result: asn1.result
			};

			//region Delete early added name of block
			if(inputSchema.hasOwnProperty("name"))
			{
				inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
				if(inputSchema.name !== "")
				{
					delete root[inputSchema.name];
					_result.name = inputSchema.name;
				}
			}
			//endregion

			return _result;
		}
		//endregion

		return compareSchema(root, asn1.result, inputSchema.primitiveSchema);
	}

	return {
		verified: true,
		result: root
	};
	//endregion
}

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AlgorithmIdentifier
{
	//**********************************************************************************
	/**
	 * Constructor for AlgorithmIdentifier class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {string} [algorithmId] ObjectIdentifier for algorithm (string representation)
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description ObjectIdentifier for algorithm (string representation)
		 */
		this.algorithmId = getParametersValue(parameters, "algorithmId", AlgorithmIdentifier.defaultValues("algorithmId"));

		if("algorithmParams" in parameters)
			/**
			 * @type {Object}
			 * @description Any algorithm parameters
			 */
			this.algorithmParams = getParametersValue(parameters, "algorithmParams", AlgorithmIdentifier.defaultValues("algorithmParams"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "algorithmId":
				return "";
			case "algorithmParams":
				return new Any();
			default:
				throw new Error(`Invalid member name for AlgorithmIdentifier class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "algorithmId":
				return (memberValue === "");
			case "algorithmParams":
				return (memberValue instanceof Any);
			default:
				throw new Error(`Invalid member name for AlgorithmIdentifier class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//AlgorithmIdentifier  ::=  Sequence  {
		//    algorithm               OBJECT IDENTIFIER,
		//    parameters              ANY DEFINED BY algorithm OPTIONAL  }

		/**
		 * @type {Object}
		 * @property {string} algorithmIdentifier ObjectIdentifier for the algorithm
		 * @property {string} algorithmParams Any algorithm parameters
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			optional: (names.optional || false),
			value: [
				new ObjectIdentifier({ name: (names.algorithmIdentifier || "") }),
				new Any({ name: (names.algorithmParams || ""), optional: true })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {algorithm: Object, params: Object}}}
		 */
		const asn1 = compareSchema(schema,
			schema,
			AlgorithmIdentifier.schema({
				names: {
					algorithmIdentifier: "algorithm",
					algorithmParams: "params"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for AlgorithmIdentifier");
		//endregion

		//region Get internal properties from parsed schema
		this.algorithmId = asn1.result.algorithm.valueBlock.toString();
		if("params" in asn1.result)
			this.algorithmParams = asn1.result.params;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		outputArray.push(new ObjectIdentifier({ value: this.algorithmId }));
		if(("algorithmParams" in this) && ((this.algorithmParams instanceof Any) === false))
			outputArray.push(this.algorithmParams);
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			algorithmId: this.algorithmId
		};

		if(("algorithmParams" in this) && ((this.algorithmParams instanceof Any) === false))
			object.algorithmParams = this.algorithmParams.toJSON();

		return object;
	}
	//**********************************************************************************
	/**
	 * Check that two "AlgorithmIdentifiers" are equal
	 * @param {AlgorithmIdentifier} algorithmIdentifier
	 * @returns {boolean}
	 */
	isEqual(algorithmIdentifier)
	{
		//region Check input type
		if((algorithmIdentifier instanceof AlgorithmIdentifier) === false)
			return false;
		//endregion

		//region Check "algorithm_id"
		if(this.algorithmId !== algorithmIdentifier.algorithmId)
			return false;
		//endregion

		//region Check "algorithm_params"
		if("algorithmParams" in this)
		{
			if("algorithmParams" in algorithmIdentifier)
				return JSON.stringify(this.algorithmParams) === JSON.stringify(algorithmIdentifier.algorithmParams);

			return false;
		}

		if("algorithmParams" in algorithmIdentifier)
			return false;
		//endregion

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC4055
 */
class RSASSAPSSParams
{
	//**********************************************************************************
	/**
	 * Constructor for RSASSAPSSParams class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {AlgorithmIdentifier}
		 * @description Algorithms of hashing (DEFAULT sha1)
		 */
		this.hashAlgorithm = getParametersValue(parameters, "hashAlgorithm", RSASSAPSSParams.defaultValues("hashAlgorithm"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description Algorithm of "mask generaion function (MGF)" (DEFAULT mgf1SHA1)
		 */
		this.maskGenAlgorithm = getParametersValue(parameters, "maskGenAlgorithm", RSASSAPSSParams.defaultValues("maskGenAlgorithm"));
		/**
		 * @type {number}
		 * @description Salt length (DEFAULT 20)
		 */
		this.saltLength = getParametersValue(parameters, "saltLength", RSASSAPSSParams.defaultValues("saltLength"));
		/**
		 * @type {number}
		 * @description (DEFAULT 1)
		 */
		this.trailerField = getParametersValue(parameters, "trailerField", RSASSAPSSParams.defaultValues("trailerField"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "hashAlgorithm":
				return new AlgorithmIdentifier({
					algorithmId: "1.3.14.3.2.26", // SHA-1
					algorithmParams: new Null()
				});
			case "maskGenAlgorithm":
				return new AlgorithmIdentifier({
					algorithmId: "1.2.840.113549.1.1.8", // MGF1
					algorithmParams: (new AlgorithmIdentifier({
						algorithmId: "1.3.14.3.2.26", // SHA-1
						algorithmParams: new Null()
					})).toSchema()
				});
			case "saltLength":
				return 20;
			case "trailerField":
				return 1;
			default:
				throw new Error(`Invalid member name for RSASSAPSSParams class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RSASSA-PSS-params  ::=  Sequence  {
		//    hashAlgorithm      [0] HashAlgorithm DEFAULT sha1Identifier,
		//    maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
		//    saltLength         [2] Integer DEFAULT 20,
		//    trailerField       [3] Integer DEFAULT 1  }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [hashAlgorithm]
		 * @property {string} [maskGenAlgorithm]
		 * @property {string} [saltLength]
		 * @property {string} [trailerField]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					optional: true,
					value: [AlgorithmIdentifier.schema(names.hashAlgorithm || {})]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					optional: true,
					value: [AlgorithmIdentifier.schema(names.maskGenAlgorithm || {})]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					optional: true,
					value: [new Integer({ name: (names.saltLength || "") })]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					optional: true,
					value: [new Integer({ name: (names.trailerField || "") })]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			RSASSAPSSParams.schema({
				names: {
					hashAlgorithm: {
						names: {
							blockName: "hashAlgorithm"
						}
					},
					maskGenAlgorithm: {
						names: {
							blockName: "maskGenAlgorithm"
						}
					},
					saltLength: "saltLength",
					trailerField: "trailerField"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RSASSA_PSS_params");
		//endregion

		//region Get internal properties from parsed schema
		if("hashAlgorithm" in asn1.result)
			this.hashAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.hashAlgorithm });

		if("maskGenAlgorithm" in asn1.result)
			this.maskGenAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.maskGenAlgorithm });

		if("saltLength" in asn1.result)
			this.saltLength = asn1.result.saltLength.valueBlock.valueDec;

		if("trailerField" in asn1.result)
			this.trailerField = asn1.result.trailerField.valueBlock.valueDec;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if(!this.hashAlgorithm.isEqual(RSASSAPSSParams.defaultValues("hashAlgorithm")))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [this.hashAlgorithm.toSchema()]
			}));
		}
		
		if(!this.maskGenAlgorithm.isEqual(RSASSAPSSParams.defaultValues("maskGenAlgorithm")))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [this.maskGenAlgorithm.toSchema()]
			}));
		}
		
		if(this.saltLength !== RSASSAPSSParams.defaultValues("saltLength"))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				value: [new Integer({ value: this.saltLength })]
			}));
		}
		
		if(this.trailerField !== RSASSAPSSParams.defaultValues("trailerField"))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				value: [new Integer({ value: this.trailerField })]
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if(!this.hashAlgorithm.isEqual(RSASSAPSSParams.defaultValues("hashAlgorithm")))
			object.hashAlgorithm = this.hashAlgorithm.toJSON();

		if(!this.maskGenAlgorithm.isEqual(RSASSAPSSParams.defaultValues("maskGenAlgorithm")))
			object.maskGenAlgorithm = this.maskGenAlgorithm.toJSON();

		if(this.saltLength !== RSASSAPSSParams.defaultValues("saltLength"))
			object.saltLength = this.saltLength;

		if(this.trailerField !== RSASSAPSSParams.defaultValues("trailerField"))
			object.trailerField = this.trailerField;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5480
 */
class ECPublicKey
{
	//**********************************************************************************
	/**
	 * Constructor for ECCPublicKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {ArrayBuffer}
		 * @description type
		 */
		this.x = getParametersValue(parameters, "x", ECPublicKey.defaultValues("x"));
		/**
		 * @type {ArrayBuffer}
		 * @description values
		 */
		this.y = getParametersValue(parameters, "y", ECPublicKey.defaultValues("y"));
		/**
		 * @type {string}
		 * @description namedCurve
		 */
		this.namedCurve = getParametersValue(parameters, "namedCurve", ECPublicKey.defaultValues("namedCurve"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "x":
			case "y":
				return new ArrayBuffer(0);
			case "namedCurve":
				return "";
			default:
				throw new Error(`Invalid member name for ECCPublicKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "x":
			case "y":
				return (isEqualBuffer(memberValue, ECPublicKey.defaultValues(memberName)));
			case "namedCurve":
				return (memberValue === "");
			default:
				throw new Error(`Invalid member name for ECCPublicKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		return new RawData();
	}
	//**********************************************************************************
	/**
	 * Convert ArrayBuffer into current class
	 * @param {!ArrayBuffer} schema Special case: schema is an ArrayBuffer
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		if((schema instanceof ArrayBuffer) === false)
			throw new Error("Object's schema was not verified against input data for ECPublicKey");

		const view = new Uint8Array(schema);
		if(view[0] !== 0x04)
			throw new Error("Object's schema was not verified against input data for ECPublicKey");
		//endregion

		//region Get internal properties from parsed schema
		let coordinateLength;

		switch(this.namedCurve)
		{
			case "1.2.840.10045.3.1.7": // P-256
				coordinateLength = 32;
				break;
			case "1.3.132.0.34": // P-384
				coordinateLength = 48;
				break;
			case "1.3.132.0.35": // P-521
				coordinateLength = 66;
				break;
			default:
				throw new Error(`Incorrect curve OID: ${this.namedCurve}`);
		}

		if(schema.byteLength !== (coordinateLength * 2 + 1))
			throw new Error("Object's schema was not verified against input data for ECPublicKey");
		
		this.x = schema.slice(1, coordinateLength + 1);
		this.y = schema.slice(1 + coordinateLength, coordinateLength * 2 + 1);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		return new RawData({ data: utilConcatBuf(
			(new Uint8Array([0x04])).buffer,
			this.x,
			this.y
		)
		});
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let crvName = "";

		switch(this.namedCurve)
		{
			case "1.2.840.10045.3.1.7": // P-256
				crvName = "P-256";
				break;
			case "1.3.132.0.34": // P-384
				crvName = "P-384";
				break;
			case "1.3.132.0.35": // P-521
				crvName = "P-521";
				break;
			default:
		}

		return {
			crv: crvName,
			x: toBase64(arrayBufferToString(this.x), true, true, true),
			y: toBase64(arrayBufferToString(this.y), true, true, true)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		let coodinateLength = 0;

		if("crv" in json)
		{
			switch(json.crv.toUpperCase())
			{
				case "P-256":
					this.namedCurve = "1.2.840.10045.3.1.7";
					coodinateLength = 32;
					break;
				case "P-384":
					this.namedCurve = "1.3.132.0.34";
					coodinateLength = 48;
					break;
				case "P-521":
					this.namedCurve = "1.3.132.0.35";
					coodinateLength = 66;
					break;
				default:
			}
		}
		else
			throw new Error("Absent mandatory parameter \"crv\"");

		if("x" in json)
			this.x = stringToArrayBuffer(fromBase64(json.x, true)).slice(0, coodinateLength);
		else
			throw new Error("Absent mandatory parameter \"x\"");

		if("y" in json)
			this.y = stringToArrayBuffer(fromBase64(json.y, true)).slice(0, coodinateLength);
		else
			throw new Error("Absent mandatory parameter \"y\"");
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC3447
 */
class RSAPublicKey
{
	//**********************************************************************************
	/**
	 * Constructor for RSAPublicKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {Integer} [modulus]
	 * @property {Integer} [publicExponent]
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Integer}
		 * @description Modulus part of RSA public key
		 */
		this.modulus = getParametersValue(parameters, "modulus", RSAPublicKey.defaultValues("modulus"));
		/**
		 * @type {Integer}
		 * @description Public exponent of RSA public key
		 */
		this.publicExponent = getParametersValue(parameters, "publicExponent", RSAPublicKey.defaultValues("publicExponent"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "modulus":
				return new Integer();
			case "publicExponent":
				return new Integer();
			default:
				throw new Error(`Invalid member name for RSAPublicKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RSAPublicKey ::= Sequence {
		//    modulus           Integer,  -- n
		//    publicExponent    Integer   -- e
		//}

		/**
		 * @type {Object}
		 * @property {string} utcTimeName Name for "utcTimeName" choice
		 * @property {string} generalTimeName Name for "generalTimeName" choice
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.modulus || "") }),
				new Integer({ name: (names.publicExponent || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			RSAPublicKey.schema({
				names: {
					modulus: "modulus",
					publicExponent: "publicExponent"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RSAPublicKey");
		//endregion

		//region Get internal properties from parsed schema
		this.modulus = asn1.result.modulus.convertFromDER(256);
		this.publicExponent = asn1.result.publicExponent;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.modulus.convertToDER(),
				this.publicExponent
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			n: toBase64(arrayBufferToString(this.modulus.valueBlock.valueHex), true, true, true),
			e: toBase64(arrayBufferToString(this.publicExponent.valueBlock.valueHex), true, true, true)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("n" in json)
			this.modulus = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.n, true)).slice(0, 256) });
		else
			throw new Error("Absent mandatory parameter \"n\"");

		if("e" in json)
			this.publicExponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.e, true)).slice(0, 3) });
		else
			throw new Error("Absent mandatory parameter \"e\"");
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PublicKeyInfo 
{
	//**********************************************************************************
	/**
	 * Constructor for PublicKeyInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {AlgorithmIdentifier}
		 * @description Algorithm identifier
		 */
		this.algorithm = getParametersValue(parameters, "algorithm", PublicKeyInfo.defaultValues("algorithm"));
		/**
		 * @type {BitString}
		 * @description Subject public key value
		 */
		this.subjectPublicKey = getParametersValue(parameters, "subjectPublicKey", PublicKeyInfo.defaultValues("subjectPublicKey"));
		
		if("parsedKey" in parameters)
			/**
			 * @type {ECPublicKey|RSAPublicKey}
			 * @description Parsed public key value
			 */
			this.parsedKey = getParametersValue(parameters, "parsedKey", PublicKeyInfo.defaultValues("parsedKey"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "algorithm":
				return new AlgorithmIdentifier();
			case "subjectPublicKey":
				return new BitString();
			default:
				throw new Error(`Invalid member name for PublicKeyInfo class: ${memberName}`);
		}
	}
	
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//SubjectPublicKeyInfo  ::=  Sequence  {
		//    algorithm            AlgorithmIdentifier,
		//    subjectPublicKey     BIT STRING  }
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [algorithm]
		 * @property {string} [subjectPublicKey]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				AlgorithmIdentifier.schema(names.algorithm || {}),
				new BitString({ name: (names.subjectPublicKey || "") })
			]
		}));
	}
	
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PublicKeyInfo.schema({
				names: {
					algorithm: {
						names: {
							blockName: "algorithm"
						}
					},
					subjectPublicKey: "subjectPublicKey"
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PUBLIC_KEY_INFO");
		//endregion
		
		//region Get internal properties from parsed schema
		this.algorithm = new AlgorithmIdentifier({ schema: asn1.result.algorithm });
		this.subjectPublicKey = asn1.result.subjectPublicKey;
		
		switch(this.algorithm.algorithmId)
		{
			case "1.2.840.10045.2.1": // ECDSA
				if("algorithmParams" in this.algorithm)
				{
					if(this.algorithm.algorithmParams instanceof ObjectIdentifier)
					{
						this.parsedKey = new ECPublicKey({
							namedCurve: this.algorithm.algorithmParams.valueBlock.toString(),
							schema: this.subjectPublicKey.valueBlock.valueHex
						});
					}
				}
				break;
			case "1.2.840.113549.1.1.1": // RSA
				{
					const publicKeyASN1 = fromBER(this.subjectPublicKey.valueBlock.valueHex);
					if(publicKeyASN1.offset !== (-1))
						this.parsedKey = new RSAPublicKey({ schema: publicKeyASN1.result });
				}
				break;
			default:
		}
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.algorithm.toSchema(),
				this.subjectPublicKey
			]
		}));
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		//region Return common value in case we do not have enough info fo making JWK
		if(("parsedKey" in this) === false)
		{
			return {
				algorithm: this.algorithm.toJSON(),
				subjectPublicKey: this.subjectPublicKey.toJSON()
			};
		}
		//endregion
		
		//region Making JWK
		const jwk = {};
		
		switch(this.algorithm.algorithmId)
		{
			case "1.2.840.10045.2.1": // ECDSA
				jwk.kty = "EC";
				break;
			case "1.2.840.113549.1.1.1": // RSA
				jwk.kty = "RSA";
				break;
			default:
		}
		
		const publicKeyJWK = this.parsedKey.toJSON();
		
		for(const key of Object.keys(publicKeyJWK))
			jwk[key] = publicKeyJWK[key];
		
		return jwk;
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("kty" in json)
		{
			switch(json.kty.toUpperCase())
			{
				case "EC":
					this.parsedKey = new ECPublicKey({ json });
					
					this.algorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.10045.2.1",
						algorithmParams: new ObjectIdentifier({ value: this.parsedKey.namedCurve })
					});
					break;
				case "RSA":
					this.parsedKey = new RSAPublicKey({ json });
					
					this.algorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.113549.1.1.1",
						algorithmParams: new Null()
					});
					break;
				default:
					throw new Error(`Invalid value for \"kty\" parameter: ${json.kty}`);
			}
			
			this.subjectPublicKey = new BitString({ valueHex: this.parsedKey.toSchema().toBER(false) });
		}
	}
	
	//**********************************************************************************
	importKey(publicKey)
	{
		//region Initial variables
		let sequence = Promise.resolve();
		const _this = this;
		//endregion
		
		//region Initial check
		if(typeof publicKey === "undefined")
			return Promise.reject("Need to provide publicKey input parameter");
		//endregion
		
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			return Promise.reject("Unable to create WebCrypto object");
		//endregion
		
		//region Export public key
		sequence = sequence.then(() =>
			crypto.exportKey("spki", publicKey));
		//endregion
		
		//region Initialize internal variables by parsing exported value
		sequence = sequence.then(exportedKey =>
		{
			const asn1 = fromBER(exportedKey);
			try
				{
					_this.fromSchema(asn1.result);
				}
				catch(exception)
				{
					return Promise.reject("Error during initializing object from schema");
				}
				
			return undefined;
		}, error => Promise.reject(`Error during exporting public key: ${error}`)
		);
		//endregion
		
		return sequence;
	}
	
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC2986
 */
class Attribute {
	//**********************************************************************************
	/**
	 * Constructor for Attribute class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description type
		 */
		this.type = getParametersValue(parameters, "type", Attribute.defaultValues("type"));
		/**
		 * @type {Array}
		 * @description values
		 */
		this.values = getParametersValue(parameters, "values", Attribute.defaultValues("values"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "type":
				return "";
			case "values":
				return [];
			default:
				throw new Error(`Invalid member name for Attribute class: ${memberName}`);
		}
	}
	
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "type":
				return (memberValue === "");
			case "values":
				return (memberValue.length === 0);
			default:
				throw new Error(`Invalid member name for Attribute class: ${memberName}`);
		}
	}
	
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
		//    type   ATTRIBUTE.&id({IOSet}),
		//    values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
		//}
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [type]
		 * @property {string} [setName]
		 * @property {string} [values]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.type || "") }),
				new Set({
					name: (names.setName || ""),
					value: [
						new Repeated({
							name: (names.values || ""),
							value: new Any()
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			Attribute.schema({
				names: {
					type: "type",
					values: "values"
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ATTRIBUTE");
		//endregion
		
		//region Get internal properties from parsed schema
		this.type = asn1.result.type.valueBlock.toString();
		this.values = asn1.result.values;
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.type }),
				new Set({
					value: this.values
				})
			]
		}));
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			type: this.type,
			values: Array.from(this.values, element => element.toJSON())
		};
	}
	
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5915
 */
class ECPrivateKey
{
	//**********************************************************************************
	/**
	 * Constructor for ECCPrivateKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", ECPrivateKey.defaultValues("version"));
		/**
		 * @type {OctetString}
		 * @description privateKey
		 */
		this.privateKey = getParametersValue(parameters, "privateKey", ECPrivateKey.defaultValues("privateKey"));

		if("namedCurve" in parameters)
			/**
			 * @type {string}
			 * @description namedCurve
			 */
			this.namedCurve = getParametersValue(parameters, "namedCurve", ECPrivateKey.defaultValues("namedCurve"));

		if("publicKey" in parameters)
			/**
			 * @type {ECPublicKey}
			 * @description publicKey
			 */
			this.publicKey = getParametersValue(parameters, "publicKey", ECPrivateKey.defaultValues("publicKey"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "version":
				return 1;
			case "privateKey":
				return new OctetString();
			case "namedCurve":
				return "";
			case "publicKey":
				return new ECPublicKey();
			default:
				throw new Error(`Invalid member name for ECCPrivateKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "version":
				return (memberValue === ECPrivateKey.defaultValues(memberName));
			case "privateKey":
				return (memberValue.isEqual(ECPrivateKey.defaultValues(memberName)));
			case "namedCurve":
				return (memberValue === "");
			case "publicKey":
				return ((ECPublicKey.compareWithDefault("namedCurve", memberValue.namedCurve)) &&
						(ECPublicKey.compareWithDefault("x", memberValue.x)) &&
						(ECPublicKey.compareWithDefault("y", memberValue.y)));
			default:
				throw new Error(`Invalid member name for ECCPrivateKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// ECPrivateKey ::= SEQUENCE {
		// version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
		// privateKey     OCTET STRING,
		// parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
		// publicKey  [1] BIT STRING OPTIONAL
		// }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [version]
		 * @property {string} [privateKey]
		 * @property {string} [namedCurve]
		 * @property {string} [publicKey]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.version || "") }),
				new OctetString({ name: (names.privateKey || "") }),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new ObjectIdentifier({ name: (names.namedCurve || "") })
					]
				}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [
						new BitString({ name: (names.publicKey || "") })
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			ECPrivateKey.schema({
				names: {
					version: "version",
					privateKey: "privateKey",
					namedCurve: "namedCurve",
					publicKey: "publicKey"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ECPrivateKey");
		//endregion

		//region Get internal properties from parsed schema
		this.version = asn1.result.version.valueBlock.valueDec;
		this.privateKey = asn1.result.privateKey;

		if("namedCurve" in asn1.result)
			this.namedCurve = asn1.result.namedCurve.valueBlock.toString();

		if("publicKey" in asn1.result)
		{
			const publicKeyData = { schema: asn1.result.publicKey.valueBlock.valueHex };
			if("namedCurve" in this)
				publicKeyData.namedCurve = this.namedCurve;

			this.publicKey = new ECPublicKey(publicKeyData);
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		const outputArray = [
			new Integer({ value: this.version }),
			this.privateKey
		];

		if("namedCurve" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [
					new ObjectIdentifier({ value: this.namedCurve })
				]
			}));
		}

		if("publicKey" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [
					new BitString({ valueHex: this.publicKey.toSchema().toBER(false) })
				]
			}));
		}

		return new Sequence({
			value: outputArray
		});
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		if((("namedCurve" in this) === false) || (ECPrivateKey.compareWithDefault("namedCurve", this.namedCurve)))
			throw new Error("Not enough information for making JSON: absent \"namedCurve\" value");

		let crvName = "";

		switch(this.namedCurve)
		{
			case "1.2.840.10045.3.1.7": // P-256
				crvName = "P-256";
				break;
			case "1.3.132.0.34": // P-384
				crvName = "P-384";
				break;
			case "1.3.132.0.35": // P-521
				crvName = "P-521";
				break;
			default:
		}

		const privateKeyJSON = {
			crv: crvName,
			d: toBase64(arrayBufferToString(this.privateKey.valueBlock.valueHex), true, true, true)
		};

		if("publicKey" in this)
		{
			const publicKeyJSON = this.publicKey.toJSON();

			privateKeyJSON.x = publicKeyJSON.x;
			privateKeyJSON.y = publicKeyJSON.y;
		}

		return privateKeyJSON;
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		let coodinateLength = 0;

		if("crv" in json)
		{
			switch(json.crv.toUpperCase())
			{
				case "P-256":
					this.namedCurve = "1.2.840.10045.3.1.7";
					coodinateLength = 32;
					break;
				case "P-384":
					this.namedCurve = "1.3.132.0.34";
					coodinateLength = 48;
					break;
				case "P-521":
					this.namedCurve = "1.3.132.0.35";
					coodinateLength = 66;
					break;
				default:
			}
		}
		else
			throw new Error("Absent mandatory parameter \"crv\"");

		if("d" in json)
			this.privateKey = new OctetString({ valueHex: stringToArrayBuffer(fromBase64(json.d, true)).slice(0, coodinateLength) });
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if(("x" in json) && ("y" in json))
			this.publicKey = new ECPublicKey({ json });
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC3447
 */
class OtherPrimeInfo
{
	//**********************************************************************************
	/**
	 * Constructor for OtherPrimeInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Integer}
		 * @description prime
		 */
		this.prime = getParametersValue(parameters, "prime", OtherPrimeInfo.defaultValues("prime"));
		/**
		 * @type {Integer}
		 * @description exponent
		 */
		this.exponent = getParametersValue(parameters, "exponent", OtherPrimeInfo.defaultValues("exponent"));
		/**
		 * @type {Integer}
		 * @description coefficient
		 */
		this.coefficient = getParametersValue(parameters, "coefficient", OtherPrimeInfo.defaultValues("coefficient"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "prime":
				return new Integer();
			case "exponent":
				return new Integer();
			case "coefficient":
				return new Integer();
			default:
				throw new Error(`Invalid member name for OtherPrimeInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//OtherPrimeInfo ::= Sequence {
		//    prime             Integer,  -- ri
		//    exponent          Integer,  -- di
		//    coefficient       Integer   -- ti
		//}

		/**
		 * @type {Object}
		 * @property {string} prime
		 * @property {string} exponent
		 * @property {string} coefficient
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.prime || "") }),
				new Integer({ name: (names.exponent || "") }),
				new Integer({ name: (names.coefficient || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			OtherPrimeInfo.schema({
				names: {
					prime: "prime",
					exponent: "exponent",
					coefficient: "coefficient"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for OtherPrimeInfo");
		//endregion

		//region Get internal properties from parsed schema
		this.prime = asn1.result.prime.convertFromDER();
		this.exponent = asn1.result.exponent.convertFromDER();
		this.coefficient = asn1.result.coefficient.convertFromDER();
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.prime.convertToDER(),
				this.exponent.convertToDER(),
				this.coefficient.convertToDER()
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			r: toBase64(arrayBufferToString(this.prime.valueBlock.valueHex), true, true),
			d: toBase64(arrayBufferToString(this.exponent.valueBlock.valueHex), true, true),
			t: toBase64(arrayBufferToString(this.coefficient.valueBlock.valueHex), true, true)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("r" in json)
			this.prime = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.r, true)) });
		else
			throw new Error("Absent mandatory parameter \"r\"");

		if("d" in json)
			this.exponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.d, true)) });
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if("t" in json)
			this.coefficient = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.t, true)) });
		else
			throw new Error("Absent mandatory parameter \"t\"");
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC3447
 */
class RSAPrivateKey
{
	//**********************************************************************************
	/**
	 * Constructor for RSAPrivateKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", RSAPrivateKey.defaultValues("version"));
		/**
		 * @type {Integer}
		 * @description modulus
		 */
		this.modulus = getParametersValue(parameters, "modulus", RSAPrivateKey.defaultValues("modulus"));
		/**
		 * @type {Integer}
		 * @description publicExponent
		 */
		this.publicExponent = getParametersValue(parameters, "publicExponent", RSAPrivateKey.defaultValues("publicExponent"));
		/**
		 * @type {Integer}
		 * @description privateExponent
		 */
		this.privateExponent = getParametersValue(parameters, "privateExponent", RSAPrivateKey.defaultValues("privateExponent"));
		/**
		 * @type {Integer}
		 * @description prime1
		 */
		this.prime1 = getParametersValue(parameters, "prime1", RSAPrivateKey.defaultValues("prime1"));
		/**
		 * @type {Integer}
		 * @description prime2
		 */
		this.prime2 = getParametersValue(parameters, "prime2", RSAPrivateKey.defaultValues("prime2"));
		/**
		 * @type {Integer}
		 * @description exponent1
		 */
		this.exponent1 = getParametersValue(parameters, "exponent1", RSAPrivateKey.defaultValues("exponent1"));
		/**
		 * @type {Integer}
		 * @description exponent2
		 */
		this.exponent2 = getParametersValue(parameters, "exponent2", RSAPrivateKey.defaultValues("exponent2"));
		/**
		 * @type {Integer}
		 * @description coefficient
		 */
		this.coefficient = getParametersValue(parameters, "coefficient", RSAPrivateKey.defaultValues("coefficient"));

		if("otherPrimeInfos" in parameters)
			/**
			 * @type {Array.<OtherPrimeInfo>}
			 * @description otherPrimeInfos
			 */
			this.otherPrimeInfos = getParametersValue(parameters, "otherPrimeInfos", RSAPrivateKey.defaultValues("otherPrimeInfos"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "version":
				return 0;
			case "modulus":
				return new Integer();
			case "publicExponent":
				return new Integer();
			case "privateExponent":
				return new Integer();
			case "prime1":
				return new Integer();
			case "prime2":
				return new Integer();
			case "exponent1":
				return new Integer();
			case "exponent2":
				return new Integer();
			case "coefficient":
				return new Integer();
			case "otherPrimeInfos":
				return [];
			default:
				throw new Error(`Invalid member name for RSAPrivateKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RSAPrivateKey ::= Sequence {
		//    version           Version,
		//    modulus           Integer,  -- n
		//    publicExponent    Integer,  -- e
		//    privateExponent   Integer,  -- d
		//    prime1            Integer,  -- p
		//    prime2            Integer,  -- q
		//    exponent1         Integer,  -- d mod (p-1)
		//    exponent2         Integer,  -- d mod (q-1)
		//    coefficient       Integer,  -- (inverse of q) mod p
		//    otherPrimeInfos   OtherPrimeInfos OPTIONAL
		//}
		//
		//OtherPrimeInfos ::= Sequence SIZE(1..MAX) OF OtherPrimeInfo

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [version]
		 * @property {string} [modulus]
		 * @property {string} [publicExponent]
		 * @property {string} [privateExponent]
		 * @property {string} [prime1]
		 * @property {string} [prime2]
		 * @property {string} [exponent1]
		 * @property {string} [exponent2]
		 * @property {string} [coefficient]
		 * @property {string} [otherPrimeInfosName]
		 * @property {Object} [otherPrimeInfo]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.version || "") }),
				new Integer({ name: (names.modulus || "") }),
				new Integer({ name: (names.publicExponent || "") }),
				new Integer({ name: (names.privateExponent || "") }),
				new Integer({ name: (names.prime1 || "") }),
				new Integer({ name: (names.prime2 || "") }),
				new Integer({ name: (names.exponent1 || "") }),
				new Integer({ name: (names.exponent2 || "") }),
				new Integer({ name: (names.coefficient || "") }),
				new Sequence({
					optional: true,
					value: [
						new Repeated({
							name: (names.otherPrimeInfosName || ""),
							value: OtherPrimeInfo.schema(names.otherPrimeInfo || {})
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			RSAPrivateKey.schema({
				names: {
					version: "version",
					modulus: "modulus",
					publicExponent: "publicExponent",
					privateExponent: "privateExponent",
					prime1: "prime1",
					prime2: "prime2",
					exponent1: "exponent1",
					exponent2: "exponent2",
					coefficient: "coefficient",
					otherPrimeInfo: {
						names: {
							blockName: "otherPrimeInfos"
						}
					}
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RSAPrivateKey");
		//endregion

		//region Get internal properties from parsed schema
		this.version = asn1.result.version.valueBlock.valueDec;
		this.modulus = asn1.result.modulus.convertFromDER(256);
		this.publicExponent = asn1.result.publicExponent;
		this.privateExponent = asn1.result.privateExponent.convertFromDER(256);
		this.prime1 = asn1.result.prime1.convertFromDER(128);
		this.prime2 = asn1.result.prime2.convertFromDER(128);
		this.exponent1 = asn1.result.exponent1.convertFromDER(128);
		this.exponent2 = asn1.result.exponent2.convertFromDER(128);
		this.coefficient = asn1.result.coefficient.convertFromDER(128);

		if("otherPrimeInfos" in asn1.result)
			this.otherPrimeInfos = Array.from(asn1.result.otherPrimeInfos, element => new OtherPrimeInfo({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		outputArray.push(new Integer({ value: this.version }));
		outputArray.push(this.modulus.convertToDER());
		outputArray.push(this.publicExponent);
		outputArray.push(this.privateExponent.convertToDER());
		outputArray.push(this.prime1.convertToDER());
		outputArray.push(this.prime2.convertToDER());
		outputArray.push(this.exponent1.convertToDER());
		outputArray.push(this.exponent2.convertToDER());
		outputArray.push(this.coefficient.convertToDER());
		
		if("otherPrimeInfos" in this)
		{
			outputArray.push(new Sequence({
				value: Array.from(this.otherPrimeInfos, element => element.toSchema())
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const jwk = {
			n: toBase64(arrayBufferToString(this.modulus.valueBlock.valueHex), true, true, true),
			e: toBase64(arrayBufferToString(this.publicExponent.valueBlock.valueHex), true, true, true),
			d: toBase64(arrayBufferToString(this.privateExponent.valueBlock.valueHex), true, true, true),
			p: toBase64(arrayBufferToString(this.prime1.valueBlock.valueHex), true, true, true),
			q: toBase64(arrayBufferToString(this.prime2.valueBlock.valueHex), true, true, true),
			dp: toBase64(arrayBufferToString(this.exponent1.valueBlock.valueHex), true, true, true),
			dq: toBase64(arrayBufferToString(this.exponent2.valueBlock.valueHex), true, true, true),
			qi: toBase64(arrayBufferToString(this.coefficient.valueBlock.valueHex), true, true, true)
		};

		if("otherPrimeInfos" in this)
			jwk.oth = Array.from(this.otherPrimeInfos, element => element.toJSON());

		return jwk;
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("n" in json)
			this.modulus = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.n, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"n\"");

		if("e" in json)
			this.publicExponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.e, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"e\"");

		if("d" in json)
			this.privateExponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.d, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if("p" in json)
			this.prime1 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.p, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"p\"");

		if("q" in json)
			this.prime2 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.q, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"q\"");

		if("dp" in json)
			this.exponent1 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.dp, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"dp\"");

		if("dq" in json)
			this.exponent2 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.dq, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"dq\"");

		if("qi" in json)
			this.coefficient = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.qi, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"qi\"");

		if("oth" in json)
			this.otherPrimeInfos = Array.from(json.oth, element => new OtherPrimeInfo({ json: element }));
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5208
 */
class PrivateKeyInfo
{
	//**********************************************************************************
	/**
	 * Constructor for PrivateKeyInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", PrivateKeyInfo.defaultValues("version"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description privateKeyAlgorithm
		 */
		this.privateKeyAlgorithm = getParametersValue(parameters, "privateKeyAlgorithm", PrivateKeyInfo.defaultValues("privateKeyAlgorithm"));
		/**
		 * @type {OctetString}
		 * @description privateKey
		 */
		this.privateKey = getParametersValue(parameters, "privateKey", PrivateKeyInfo.defaultValues("privateKey"));

		if("attributes" in parameters)
			/**
			 * @type {Array.<Attribute>}
			 * @description attributes
			 */
			this.attributes = getParametersValue(parameters, "attributes", PrivateKeyInfo.defaultValues("attributes"));

		if("parsedKey" in parameters)
			/**
			 * @type {ECPrivateKey|RSAPrivateKey}
			 * @description Parsed public key value
			 */
			this.parsedKey = getParametersValue(parameters, "parsedKey", PrivateKeyInfo.defaultValues("parsedKey"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "version":
				return 0;
			case "privateKeyAlgorithm":
				return new AlgorithmIdentifier();
			case "privateKey":
				return new OctetString();
			case "attributes":
				return [];
			default:
				throw new Error(`Invalid member name for PrivateKeyInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PrivateKeyInfo ::= SEQUENCE {
		//    version Version,
		//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
		//    privateKey PrivateKey,
		//    attributes [0] Attributes OPTIONAL }
		//
		//Version ::= INTEGER {v1(0)} (v1,...)
		//
		//PrivateKey ::= OCTET STRING
		//
		//Attributes ::= SET OF Attribute

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [version]
		 * @property {string} [privateKeyAlgorithm]
		 * @property {string} [privateKey]
		 * @property {string} [attributes]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.version || "") }),
				AlgorithmIdentifier.schema(names.privateKeyAlgorithm || {}),
				new OctetString({ name: (names.privateKey || "") }),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new Repeated({
							name: (names.attributes || ""),
							value: Attribute.schema()
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PrivateKeyInfo.schema({
				names: {
					version: "version",
					privateKeyAlgorithm: {
						names: {
							blockName: "privateKeyAlgorithm"
						}
					},
					privateKey: "privateKey",
					attributes: "attributes"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PKCS8");
		//endregion

		//region Get internal properties from parsed schema
		this.version = asn1.result.version.valueBlock.valueDec;
		this.privateKeyAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.privateKeyAlgorithm });
		this.privateKey = asn1.result.privateKey;

		if("attributes" in asn1.result)
			this.attributes = Array.from(asn1.result.attributes, element => new Attribute({ schema: element }));

		switch(this.privateKeyAlgorithm.algorithmId)
		{
			case "1.2.840.113549.1.1.1": // RSA
				{
					const privateKeyASN1 = fromBER(this.privateKey.valueBlock.valueHex);
					if(privateKeyASN1.offset !== (-1))
						this.parsedKey = new RSAPrivateKey({ schema: privateKeyASN1.result });
				}
				break;
			case "1.2.840.10045.2.1": // ECDSA
				if("algorithmParams" in this.privateKeyAlgorithm)
				{
					if(this.privateKeyAlgorithm.algorithmParams instanceof ObjectIdentifier)
					{
						const privateKeyASN1 = fromBER(this.privateKey.valueBlock.valueHex);
						if(privateKeyASN1.offset !== (-1))
						{
							this.parsedKey = new ECPrivateKey({
								namedCurve: this.privateKeyAlgorithm.algorithmParams.valueBlock.toString(),
								schema: privateKeyASN1.result
							});
						}
					}
				}
				break;
			default:
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [
			new Integer({ value: this.version }),
			this.privateKeyAlgorithm.toSchema(),
			this.privateKey
		];

		if("attributes" in this)
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: Array.from(this.attributes, element => element.toSchema())
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		//region Return common value in case we do not have enough info fo making JWK
		if(("parsedKey" in this) === false)
		{
			const object = {
				version: this.version,
				privateKeyAlgorithm: this.privateKeyAlgorithm.toJSON(),
				privateKey: this.privateKey.toJSON()
			};

			if("attributes" in this)
				object.attributes = Array.from(this.attributes, element => element.toJSON());

			return object;
		}
		//endregion

		//region Making JWK
		const jwk = {};

		switch(this.privateKeyAlgorithm.algorithmId)
		{
			case "1.2.840.10045.2.1": // ECDSA
				jwk.kty = "EC";
				break;
			case "1.2.840.113549.1.1.1": // RSA
				jwk.kty = "RSA";
				break;
			default:
		}

		const publicKeyJWK = this.parsedKey.toJSON();

		for(const key of Object.keys(publicKeyJWK))
			jwk[key] = publicKeyJWK[key];

		return jwk;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("kty" in json)
		{
			switch(json.kty.toUpperCase())
			{
				case "EC":
					this.parsedKey = new ECPrivateKey({ json });

					this.privateKeyAlgorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.10045.2.1",
						algorithmParams: new ObjectIdentifier({ value: this.parsedKey.namedCurve })
					});
					break;
				case "RSA":
					this.parsedKey = new RSAPrivateKey({ json });

					this.privateKeyAlgorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.113549.1.1.1",
						algorithmParams: new Null()
					});
					break;
				default:
					throw new Error(`Invalid value for \"kty\" parameter: ${json.kty}`);
			}

			this.privateKey = new OctetString({ valueHex: this.parsedKey.toSchema().toBER(false) });
		}
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
class CryptoEngine
{
	//**********************************************************************************
	/**
	 * Constructor for CryptoEngine class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description Usually here we are expecting "window.crypto.subtle" or an equivalent from custom "crypto engine"
		 */
		this.crypto = getParametersValue(parameters, "crypto", {});
		
		/**
		 * @type {string}
		 * @description Name of the "crypto engine"
		 */
		this.name = getParametersValue(parameters, "name", "");
		//endregion
	}
	//**********************************************************************************
	/**
	 * Import WebCrypto keys from different formats
	 * @param {string} format
	 * @param {ArrayBuffer|Object} keyData
	 * @param {Object} algorithm
	 * @param {boolean} extractable
	 * @param {Array} keyUsages
	 * @returns {Promise}
	 */
	importKey(format, keyData, algorithm, extractable, keyUsages)
	{
		//region Initial variables
		let jwk = {};
		//endregion
		
		//region Change "keyData" type if needed
		if(keyData instanceof Uint8Array)
			keyData = keyData.buffer;
		//endregion
		
		switch(format.toLowerCase())
		{
			case "raw":
				return this.crypto.importKey("raw", keyData, algorithm, extractable, keyUsages);
			case "spki":
				{
					const asn1 = fromBER(keyData);
					if(asn1.offset === (-1))
						return Promise.reject("Incorrect keyData");

					const publicKeyInfo = new PublicKeyInfo();
					try
					{
						publicKeyInfo.fromSchema(asn1.result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect keyData");
					}


					switch(algorithm.name.toUpperCase())
					{
						case "RSA-PSS":
							{
								//region Get information about used hash function
								switch(algorithm.hash.name.toUpperCase())
								{
									case "SHA-1":
										jwk.alg = "PS1";
										break;
									case "SHA-256":
										jwk.alg = "PS256";
										break;
									case "SHA-384":
										jwk.alg = "PS384";
										break;
									case "SHA-512":
										jwk.alg = "PS512";
										break;
									default:
										return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
								}
								//endregion
							}
						case "RSASSA-PKCS1-V1_5":
							{
								keyUsages = ["verify"]; // Override existing keyUsages value since the key is a public key

								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;

								if(publicKeyInfo.algorithm.algorithmId !== "1.2.840.113549.1.1.1")
									return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);

								//region Get information about used hash function
								if(("alg" in jwk) === false)
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RS1";
											break;
										case "SHA-256":
											jwk.alg = "RS256";
											break;
										case "SHA-384":
											jwk.alg = "RS384";
											break;
										case "SHA-512":
											jwk.alg = "RS512";
											break;
										default:
											return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);
									}
								}
								//endregion

								//region Create RSA Public Key elements
								const publicKeyJSON = publicKeyInfo.toJSON();

								for(const key of Object.keys(publicKeyJSON))
									jwk[key] = publicKeyJSON[key];
								//endregion
							}
							break;
						case "ECDSA":
							keyUsages = ["verify"]; // Override existing keyUsages value since the key is a public key
						case "ECDH":
							{
								//region Initial variables
								jwk = {
									kty: "EC",
									ext: extractable,
									key_ops: keyUsages
								};
								//endregion

								//region Get information about algorithm
								if(publicKeyInfo.algorithm.algorithmId !== "1.2.840.10045.2.1")
									return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);
								//endregion

								//region Create ECDSA Public Key elements
								const publicKeyJSON = publicKeyInfo.toJSON();

								for(const key of Object.keys(publicKeyJSON))
									jwk[key] = publicKeyJSON[key];
								//endregion
							}
							break;
						case "RSA-OAEP":
							{
								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;
								
								if(this.name.toLowerCase() === "safari")
									jwk.alg = "RSA-OAEP";
								else
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RSA-OAEP-1";
											break;
										case "SHA-256":
											jwk.alg = "RSA-OAEP-256";
											break;
										case "SHA-384":
											jwk.alg = "RSA-OAEP-384";
											break;
										case "SHA-512":
											jwk.alg = "RSA-OAEP-512";
											break;
										default:
											return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);
									}
								}
								
								//region Create ECDSA Public Key elements
								const publicKeyJSON = publicKeyInfo.toJSON();
								
								for(const key of Object.keys(publicKeyJSON))
									jwk[key] = publicKeyJSON[key];
								//endregion
							}
							break;
						default:
							return Promise.reject(`Incorrect algorithm name: ${algorithm.name.toUpperCase()}`);
					}
				}
				break;
			case "pkcs8":
				{
					const privateKeyInfo = new PrivateKeyInfo();

					//region Parse "PrivateKeyInfo" object
					const asn1 = fromBER(keyData);
					if(asn1.offset === (-1))
						return Promise.reject("Incorrect keyData");

					try
					{
						privateKeyInfo.fromSchema(asn1.result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect keyData");
					}
					//endregion

					switch(algorithm.name.toUpperCase())
					{
						case "RSA-PSS":
							{
								//region Get information about used hash function
								switch(algorithm.hash.name.toUpperCase())
								{
									case "SHA-1":
										jwk.alg = "PS1";
										break;
									case "SHA-256":
										jwk.alg = "PS256";
										break;
									case "SHA-384":
										jwk.alg = "PS384";
										break;
									case "SHA-512":
										jwk.alg = "PS512";
										break;
									default:
										return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
								}
								//endregion
							}
						case "RSASSA-PKCS1-V1_5":
							{
								keyUsages = ["sign"]; // Override existing keyUsages value since the key is a private key

								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;

								//region Get information about used hash function
								if(privateKeyInfo.privateKeyAlgorithm.algorithmId !== "1.2.840.113549.1.1.1")
									return Promise.reject(`Incorrect private key algorithm: ${privateKeyInfo.privateKeyAlgorithm.algorithmId}`);
								//endregion

								//region Get information about used hash function
								if(("alg" in jwk) === false)
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RS1";
											break;
										case "SHA-256":
											jwk.alg = "RS256";
											break;
										case "SHA-384":
											jwk.alg = "RS384";
											break;
										case "SHA-512":
											jwk.alg = "RS512";
											break;
										default:
											return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
									}
								}
								//endregion

								//region Create RSA Private Key elements
								const privateKeyJSON = privateKeyInfo.toJSON();

								for(const key of Object.keys(privateKeyJSON))
									jwk[key] = privateKeyJSON[key];
								//endregion
							}
							break;
						case "ECDSA":
							keyUsages = ["sign"]; // Override existing keyUsages value since the key is a private key
						case "ECDH":
							{
								//region Initial variables
								jwk = {
									kty: "EC",
									ext: extractable,
									key_ops: keyUsages
								};
								//endregion

								//region Get information about used hash function
								if(privateKeyInfo.privateKeyAlgorithm.algorithmId !== "1.2.840.10045.2.1")
									return Promise.reject(`Incorrect algorithm: ${privateKeyInfo.privateKeyAlgorithm.algorithmId}`);
								//endregion

								//region Create ECDSA Private Key elements
								const privateKeyJSON = privateKeyInfo.toJSON();

								for(const key of Object.keys(privateKeyJSON))
									jwk[key] = privateKeyJSON[key];
								//endregion
							}
							break;
						case "RSA-OAEP":
							{
								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;
								
								//region Get information about used hash function
								if(this.name.toLowerCase() === "safari")
									jwk.alg = "RSA-OAEP";
								else
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RSA-OAEP-1";
											break;
										case "SHA-256":
											jwk.alg = "RSA-OAEP-256";
											break;
										case "SHA-384":
											jwk.alg = "RSA-OAEP-384";
											break;
										case "SHA-512":
											jwk.alg = "RSA-OAEP-512";
											break;
										default:
											return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
									}
								}
								//endregion
								
								//region Create RSA Private Key elements
								const privateKeyJSON = privateKeyInfo.toJSON();
								
								for(const key of Object.keys(privateKeyJSON))
									jwk[key] = privateKeyJSON[key];
								//endregion
							}
							break;
						default:
							return Promise.reject(`Incorrect algorithm name: ${algorithm.name.toUpperCase()}`);
					}
				}
				break;
			case "jwk":
				jwk = keyData;
				break;
			default:
				return Promise.reject(`Incorrect format: ${format}`);
		}
		
		//region Special case for Safari browser (since its acting not as WebCrypto standard describes)
		if(this.name.toLowerCase() === "safari")
		{
			// Try to use both ways - import using ArrayBuffer and pure JWK (for Safari Technology Preview)
			return Promise.resolve().then(() => this.crypto.importKey("jwk", stringToArrayBuffer(JSON.stringify(jwk)), algorithm, extractable, keyUsages))
				.then(result => result, error => this.crypto.importKey("jwk", jwk, algorithm, extractable, keyUsages));
		}
		//endregion
		
		return this.crypto.importKey("jwk", jwk, algorithm, extractable, keyUsages);
	}
	//**********************************************************************************
	/**
	 * Export WebCrypto keys to different formats
	 * @param {string} format
	 * @param {Object} key
	 * @returns {Promise}
	 */
	exportKey(format, key)
	{
		let sequence = this.crypto.exportKey("jwk", key);
		
		//region Currently Safari returns ArrayBuffer as JWK thus we need an additional transformation
		if(this.name.toLowerCase() === "safari")
		{
			sequence = sequence.then(result =>
			{
				// Some additional checks for Safari Technology Preview
				if(result instanceof ArrayBuffer)
					return JSON.parse(arrayBufferToString(result))
				
				return result;
			});
		}
		//endregion
		
		switch(format.toLowerCase())
		{
			case "raw":
				return this.crypto.exportKey("raw", key);
			case "spki":
				sequence = sequence.then(result =>
				{
					const publicKeyInfo = new PublicKeyInfo();

					try
					{
						publicKeyInfo.fromJSON(result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect key data");
					}

					return publicKeyInfo.toSchema().toBER(false);
				});
				break;
			case "pkcs8":
				sequence = sequence.then(result =>
				{
					const privateKeyInfo = new PrivateKeyInfo();

					try
					{
						privateKeyInfo.fromJSON(result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect key data");
					}

					return privateKeyInfo.toSchema().toBER(false);
				});
				break;
			case "jwk":
				break;
			default:
				return Promise.reject(`Incorrect format: ${format}`);
		}

		return sequence;
	}
	//**********************************************************************************
	/**
	 * Convert WebCrypto keys between different export formats
	 * @param {string} inputFormat
	 * @param {string} outputFormat
	 * @param {ArrayBuffer|Object} keyData
	 * @param {Object} algorithm
	 * @param {boolean} extractable
	 * @param {Array} keyUsages
	 * @returns {Promise}
	 */
	convert(inputFormat, outputFormat, keyData, algorithm, extractable, keyUsages)
	{
		switch(inputFormat.toLowerCase())
		{
			case "raw":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve(keyData);
					case "spki":
						return Promise.resolve()
							.then(() => this.importKey("raw", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("spki", result));
					case "pkcs8":
						return Promise.resolve()
							.then(() => this.importKey("raw", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("pkcs8", result));
					case "jwk":
						return Promise.resolve()
							.then(() => this.importKey("raw", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("jwk", result));
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			case "spki":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve()
							.then(() => this.importKey("spki", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("raw", result));
					case "spki":
						return Promise.resolve(keyData);
					case "pkcs8":
						return Promise.reject("Impossible to convert between SPKI/PKCS8");
					case "jwk":
						return Promise.resolve()
							.then(() => this.importKey("spki", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("jwk", result));
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			case "pkcs8":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve()
							.then(() => this.importKey("pkcs8", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("raw", result));
					case "spki":
						return Promise.reject("Impossible to convert between SPKI/PKCS8");
					case "pkcs8":
						return Promise.resolve(keyData);
					case "jwk":
						return Promise.resolve()
							.then(() => this.importKey("pkcs8", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("jwk", result));
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			case "jwk":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve()
							.then(() => this.importKey("jwk", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("raw", result));
					case "spki":
						return Promise.resolve()
							.then(() => this.importKey("jwk", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("spki", result));
					case "pkcs8":
						return Promise.resolve()
							.then(() => this.importKey("jwk", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("pkcs8", result));
					case "jwk":
						return Promise.resolve(keyData);
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			default:
				return Promise.reject(`Incorrect inputFormat: ${inputFormat}`);
		}
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "encrypt"
	 * @param args
	 * @returns {Promise}
	 */
	encrypt(...args)
	{
		return this.crypto.encrypt(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "decrypt"
	 * @param args
	 * @returns {Promise}
	 */
	decrypt(...args)
	{
		return this.crypto.decrypt(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "sign"
	 * @param args
	 * @returns {Promise}
	 */
	sign(...args)
	{
		return this.crypto.sign(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "verify"
	 * @param args
	 * @returns {Promise}
	 */
	verify(...args)
	{
		return this.crypto.verify(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "digest"
	 * @param args
	 * @returns {Promise}
	 */
	digest(...args)
	{
		return this.crypto.digest(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "generateKey"
	 * @param args
	 * @returns {Promise}
	 */
	generateKey(...args)
	{
		return this.crypto.generateKey(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "deriveKey"
	 * @param args
	 * @returns {Promise}
	 */
	deriveKey(...args)
	{
		return this.crypto.deriveKey(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "deriveBits"
	 * @param args
	 * @returns {Promise}
	 */
	deriveBits(...args)
	{
		return this.crypto.deriveBits(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "wrapKey"
	 * @param args
	 * @returns {Promise}
	 */
	wrapKey(...args)
	{
		return this.crypto.wrapKey(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "unwrapKey"
	 * @param args
	 * @returns {Promise}
	 */
	unwrapKey(...args)
	{
		return this.crypto.unwrapKey(...args);
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
//region Crypto engine related function
//**************************************************************************************
let engine = {
	name: "none",
	crypto: null,
	subtle: null
};
//**************************************************************************************
function setEngine(name, crypto, subtle)
{
	engine = {
		name,
		crypto,
		subtle
	};
}
//**************************************************************************************
(function initCryptoEngine()
	{
	if(typeof self !== "undefined")
		{
		if("crypto" in self)
			{
			let engineName = "webcrypto";
				
				/**
				 * Standard crypto object
				 * @type {Object}
				 * @property {Object} [webkitSubtle] Subtle object from Apple
				 */
			const cryptoObject = self.crypto;
			let subtleObject = null;
				
				// Apple Safari support
			if("webkitSubtle" in self.crypto)
			{
				try
				{
					subtleObject = self.crypto.webkitSubtle;
				}
				catch(ex)
				{
					subtleObject = self.crypto.subtle;
				}

				engineName = "safari";
			}
				
			if("subtle" in self.crypto)
				subtleObject = self.crypto.subtle;
				
			engine = {
				name: engineName,
				crypto: cryptoObject,
				subtle: new CryptoEngine({ name: engineName, crypto: subtleObject })
			};
		}
	}
})();
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of common functions
//**************************************************************************************
/**
 * Get crypto subtle from current "crypto engine" or "undefined"
 * @returns {({decrypt, deriveKey, digest, encrypt, exportKey, generateKey, importKey, sign, unwrapKey, verify, wrapKey}|null)}
 */
function getCrypto()
{
	if(engine.subtle !== null)
		return engine.subtle;
	
	return undefined;
}
//**************************************************************************************
/**
 * Initialize input Uint8Array by random values (with help from current "crypto engine")
 * @param {!Uint8Array} view
 * @returns {*}
 */
function getRandomValues(view)
{
	if(engine.crypto !== null)
		return engine.crypto.getRandomValues(view);
	
	throw new Error("No support for Web Cryptography API");
}
//**************************************************************************************
/**
 * Get OID for each specific WebCrypto algorithm
 * @param {Object} algorithm WebCrypto algorithm
 * @returns {string}
 */
function getOIDByAlgorithm(algorithm)
{
	let result = "";
	
	switch(algorithm.name.toUpperCase())
	{
		case "RSASSA-PKCS1-V1_5":
			switch(algorithm.hash.name.toUpperCase())
			{
				case "SHA-1":
					result = "1.2.840.113549.1.1.5";
					break;
				case "SHA-256":
					result = "1.2.840.113549.1.1.11";
					break;
				case "SHA-384":
					result = "1.2.840.113549.1.1.12";
					break;
				case "SHA-512":
					result = "1.2.840.113549.1.1.13";
					break;
				default:
			}
			break;
		case "RSA-PSS":
			result = "1.2.840.113549.1.1.10";
			break;
		case "RSA-OAEP":
			result = "1.2.840.113549.1.1.7";
			break;
		case "ECDSA":
			switch(algorithm.hash.name.toUpperCase())
			{
				case "SHA-1":
					result = "1.2.840.10045.4.1";
					break;
				case "SHA-256":
					result = "1.2.840.10045.4.3.2";
					break;
				case "SHA-384":
					result = "1.2.840.10045.4.3.3";
					break;
				case "SHA-512":
					result = "1.2.840.10045.4.3.4";
					break;
				default:
			}
			break;
		case "ECDH":
			switch(algorithm.kdf.toUpperCase()) // Non-standard addition - hash algorithm of KDF function
			{
				case "SHA-1":
					result = "1.3.133.16.840.63.0.2"; // dhSinglePass-stdDH-sha1kdf-scheme
					break;
				case "SHA-256":
					result = "1.3.132.1.11.1"; // dhSinglePass-stdDH-sha256kdf-scheme
					break;
				case "SHA-384":
					result = "1.3.132.1.11.2"; // dhSinglePass-stdDH-sha384kdf-scheme
					break;
				case "SHA-512":
					result = "1.3.132.1.11.3"; // dhSinglePass-stdDH-sha512kdf-scheme
					break;
				default:
			}
			break;
		case "AES-CTR":
			break;
		case "AES-CBC":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.2";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.22";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.42";
					break;
				default:
			}
			break;
		case "AES-CMAC":
			break;
		case "AES-GCM":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.6";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.26";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.46";
					break;
				default:
			}
			break;
		case "AES-CFB":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.4";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.24";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.44";
					break;
				default:
			}
			break;
		case "AES-KW":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.5";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.25";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.45";
					break;
				default:
			}
			break;
		case "HMAC":
			switch(algorithm.hash.name.toUpperCase())
			{
				case "SHA-1":
					result = "1.2.840.113549.2.7";
					break;
				case "SHA-256":
					result = "1.2.840.113549.2.9";
					break;
				case "SHA-384":
					result = "1.2.840.113549.2.10";
					break;
				case "SHA-512":
					result = "1.2.840.113549.2.11";
					break;
				default:
			}
			break;
		case "DH":
			result = "1.2.840.113549.1.9.16.3.5";
			break;
		case "SHA-1":
			result = "1.3.14.3.2.26";
			break;
		case "SHA-256":
			result = "2.16.840.1.101.3.4.2.1";
			break;
		case "SHA-384":
			result = "2.16.840.1.101.3.4.2.2";
			break;
		case "SHA-512":
			result = "2.16.840.1.101.3.4.2.3";
			break;
		case "CONCAT":
			break;
		case "HKDF":
			break;
		case "PBKDF2":
			result = "1.2.840.113549.1.5.12";
			break;
		//region Special case - OIDs for ECC curves
		case "P-256":
			result = "1.2.840.10045.3.1.7";
			break;
		case "P-384":
			result = "1.3.132.0.34";
			break;
		case "P-521":
			result = "1.3.132.0.35";
			break;
		//endregion
		default:
	}
	
	return result;
}
//**************************************************************************************
/**
 * Get default algorithm parameters for each kind of operation
 * @param {string} algorithmName Algorithm name to get common parameters for
 * @param {string} operation Kind of operation: "sign", "encrypt", "generatekey", "importkey", "exportkey", "verify"
 * @returns {*}
 */
function getAlgorithmParameters(algorithmName, operation)
{
	let result = {
		algorithm: {},
		usages: []
	};
	
	switch(algorithmName.toUpperCase())
	{
		case "RSASSA-PKCS1-V1_5":
			switch(operation.toLowerCase())
			{
				case "generatekey":
					result = {
						algorithm: {
							name: "RSASSA-PKCS1-v1_5",
							modulusLength: 2048,
							publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["sign", "verify"]
					};
					break;
				case "verify":
				case "sign":
				case "importkey":
					result = {
						algorithm: {
							name: "RSASSA-PKCS1-v1_5",
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["verify"] // For importKey("pkcs8") usage must be "sign" only
					};
					break;
				case "exportkey":
				default:
					return {
						algorithm: {
							name: "RSASSA-PKCS1-v1_5"
						},
						usages: []
					};
			}
			break;
		case "RSA-PSS":
			switch(operation.toLowerCase())
			{
				case "sign":
				case "verify":
					result = {
						algorithm: {
							name: "RSA-PSS",
							hash: {
								name: "SHA-1"
							},
							saltLength: 20
						},
						usages: ["sign", "verify"]
					};
					break;
				case "generatekey":
					result = {
						algorithm: {
							name: "RSA-PSS",
							modulusLength: 2048,
							publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
							hash: {
								name: "SHA-1"
							}
						},
						usages: ["sign", "verify"]
					};
					break;
				case "importkey":
					result = {
						algorithm: {
							name: "RSA-PSS",
							hash: {
								name: "SHA-1"
							}
						},
						usages: ["verify"] // For importKey("pkcs8") usage must be "sign" only
					};
					break;
				case "exportkey":
				default:
					return {
						algorithm: {
							name: "RSA-PSS"
						},
						usages: []
					};
			}
			break;
		case "RSA-OAEP":
			switch(operation.toLowerCase())
			{
				case "encrypt":
				case "decrypt":
					result = {
						algorithm: {
							name: "RSA-OAEP"
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				case "generatekey":
					result = {
						algorithm: {
							name: "RSA-OAEP",
							modulusLength: 2048,
							publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "importkey":
					result = {
						algorithm: {
							name: "RSA-OAEP",
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["encrypt"] // encrypt for "spki" and decrypt for "pkcs8"
					};
					break;
				case "exportkey":
				default:
					return {
						algorithm: {
							name: "RSA-OAEP"
						},
						usages: []
					};
			}
			break;
		case "ECDSA":
			switch(operation.toLowerCase())
			{
				case "generatekey":
					result = {
						algorithm: {
							name: "ECDSA",
							namedCurve: "P-256"
						},
						usages: ["sign", "verify"]
					};
					break;
				case "importkey":
					result = {
						algorithm: {
							name: "ECDSA",
							namedCurve: "P-256"
						},
						usages: ["verify"] // "sign" for "pkcs8"
					};
					break;
				case "verify":
				case "sign":
					result = {
						algorithm: {
							name: "ECDSA",
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["sign"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "ECDSA"
						},
						usages: []
					};
			}
			break;
		case "ECDH":
			switch(operation.toLowerCase())
			{
				case "exportkey":
				case "importkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "ECDH",
							namedCurve: "P-256"
						},
						usages: ["deriveKey", "deriveBits"]
					};
					break;
				case "derivekey":
				case "derivebits":
					result = {
						algorithm: {
							name: "ECDH",
							namedCurve: "P-256",
							public: [] // Must be a "publicKey"
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "ECDH"
						},
						usages: []
					};
			}
			break;
		case "AES-CTR":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "AES-CTR",
							length: 256
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "decrypt":
				case "encrypt":
					result = {
						algorithm: {
							name: "AES-CTR",
							counter: new Uint8Array(16),
							length: 10
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-CTR"
						},
						usages: []
					};
			}
			break;
		case "AES-CBC":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "AES-CBC",
							length: 256
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "decrypt":
				case "encrypt":
					result = {
						algorithm: {
							name: "AES-CBC",
							iv: getRandomValues(new Uint8Array(16)) // For "decrypt" the value should be replaced with value got on "encrypt" step
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-CBC"
						},
						usages: []
					};
			}
			break;
		case "AES-GCM":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "AES-GCM",
							length: 256
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "decrypt":
				case "encrypt":
					result = {
						algorithm: {
							name: "AES-GCM",
							iv: getRandomValues(new Uint8Array(16)) // For "decrypt" the value should be replaced with value got on "encrypt" step
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-GCM"
						},
						usages: []
					};
			}
			break;
		case "AES-KW":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
				case "wrapkey":
				case "unwrapkey":
					result = {
						algorithm: {
							name: "AES-KW",
							length: 256
						},
						usages: ["wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-KW"
						},
						usages: []
					};
			}
			break;
		case "HMAC":
			switch(operation.toLowerCase())
			{
				case "sign":
				case "verify":
					result = {
						algorithm: {
							name: "HMAC"
						},
						usages: ["sign", "verify"]
					};
					break;
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "HMAC",
							length: 32,
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["sign", "verify"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "HMAC"
						},
						usages: []
					};
			}
			break;
		case "HKDF":
			switch(operation.toLowerCase())
			{
				case "derivekey":
					result = {
						algorithm: {
							name: "HKDF",
							hash: "SHA-256",
							salt: new Uint8Array([]),
							info: new Uint8Array([])
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "HKDF"
						},
						usages: []
					};
			}
			break;
		case "PBKDF2":
			switch(operation.toLowerCase())
			{
				case "derivekey":
					result = {
						algorithm: {
							name: "PBKDF2",
							hash: { name: "SHA-256" },
							salt: new Uint8Array([]),
							iterations: 1000
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "PBKDF2"
						},
						usages: []
					};
			}
			break;
		default:
	}
	
	return result;
}
//**************************************************************************************
/**
 * Create CMS ECDSA signature from WebCrypto ECDSA signature
 * @param {ArrayBuffer} signatureBuffer WebCrypto result of "sign" function
 * @returns {ArrayBuffer}
 */
function createCMSECDSASignature(signatureBuffer)
{
	// #region Initial check for correct length
	if((signatureBuffer.byteLength % 2) !== 0)
		return new ArrayBuffer(0);
	// #endregion
	
	// #region Initial variables
	const length = signatureBuffer.byteLength / 2; // There are two equal parts inside incoming ArrayBuffer
	
	const rBuffer = new ArrayBuffer(length);
	const rView = new Uint8Array(rBuffer);
	rView.set(new Uint8Array(signatureBuffer, 0, length));
	
	const rInteger = new Integer({ valueHex: rBuffer });
	
	const sBuffer = new ArrayBuffer(length);
	const sView = new Uint8Array(sBuffer);
	sView.set(new Uint8Array(signatureBuffer, length, length));
	
	const sInteger = new Integer({ valueHex: sBuffer });
	// #endregion
	
	return (new Sequence({
		value: [
			rInteger.convertToDER(),
			sInteger.convertToDER()
		]
	})).toBER(false);
}
//**************************************************************************************
/**
 * String preparation function. In a future here will be realization of algorithm from RFC4518
 * @param {string} inputString JavaScript string. As soon as for each ASN.1 string type we have a specific transformation function here we will work with pure JavaScript string
 * @returns {string} Formated string
 */
function stringPrep(inputString)
{
	let result = inputString.replace(/^\s+|\s+$/g, ""); // Trim input string
	result = result.replace(/\s+/g, " "); // Change all sequence of SPACE down to SPACE char
	result = result.toLowerCase();
	
	return result;
}
//**************************************************************************************
/**
 * Create a single ArrayBuffer from CMS ECDSA signature
 * @param {Sequence} cmsSignature ASN.1 SEQUENCE contains CMS ECDSA signature
 * @returns {ArrayBuffer}
 */
function createECDSASignatureFromCMS(cmsSignature)
{
	// #region Check input variables
	if((cmsSignature instanceof Sequence) === false)
		return new ArrayBuffer(0);
	
	if(cmsSignature.valueBlock.value.length !== 2)
		return new ArrayBuffer(0);
	
	if((cmsSignature.valueBlock.value[0] instanceof Integer) === false)
		return new ArrayBuffer(0);
	
	if((cmsSignature.valueBlock.value[1] instanceof Integer) === false)
		return new ArrayBuffer(0);
	// #endregion 
	
	const rValue = cmsSignature.valueBlock.value[0].convertFromDER();
	const sValue = cmsSignature.valueBlock.value[1].convertFromDER();
	
	return utilConcatBuf(rValue.valueBlock.valueHex, sValue.valueBlock.valueHex);
}
//**************************************************************************************
/**
 * Get WebCrypto algorithm by wel-known OID
 * @param {string} oid Wel-known OID to search for
 * @returns {Object}
 */
function getAlgorithmByOID(oid)
{
	switch(oid)
	{
		case "1.2.840.113549.1.1.1":
		case "1.2.840.113549.1.1.5":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-1"
				}
			};
		case "1.2.840.113549.1.1.11":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-256"
				}
			};
		case "1.2.840.113549.1.1.12":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-384"
				}
			};
		case "1.2.840.113549.1.1.13":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-512"
				}
			};
		case "1.2.840.113549.1.1.10":
			return {
				name: "RSA-PSS"
			};
		case "1.2.840.113549.1.1.7":
			return {
				name: "RSA-OAEP"
			};
		case "1.2.840.10045.2.1":
		case "1.2.840.10045.4.1":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-1"
				}
			};
		case "1.2.840.10045.4.3.2":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-256"
				}
			};
		case "1.2.840.10045.4.3.3":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-384"
				}
			};
		case "1.2.840.10045.4.3.4":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-512"
				}
			};
		case "1.3.133.16.840.63.0.2":
			return {
				name: "ECDH",
				kdf: "SHA-1"
			};
		case "1.3.132.1.11.1":
			return {
				name: "ECDH",
				kdf: "SHA-256"
			};
		case "1.3.132.1.11.2":
			return {
				name: "ECDH",
				kdf: "SHA-384"
			};
		case "1.3.132.1.11.3":
			return {
				name: "ECDH",
				kdf: "SHA-512"
			};
		case "2.16.840.1.101.3.4.1.2":
			return {
				name: "AES-CBC",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.22":
			return {
				name: "AES-CBC",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.42":
			return {
				name: "AES-CBC",
				length: 256
			};
		case "2.16.840.1.101.3.4.1.6":
			return {
				name: "AES-GCM",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.26":
			return {
				name: "AES-GCM",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.46":
			return {
				name: "AES-GCM",
				length: 256
			};
		case "2.16.840.1.101.3.4.1.4":
			return {
				name: "AES-CFB",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.24":
			return {
				name: "AES-CFB",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.44":
			return {
				name: "AES-CFB",
				length: 256
			};
		case "2.16.840.1.101.3.4.1.5":
			return {
				name: "AES-KW",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.25":
			return {
				name: "AES-KW",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.45":
			return {
				name: "AES-KW",
				length: 256
			};
		case "1.2.840.113549.2.7":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-1"
				}
			};
		case "1.2.840.113549.2.9":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-256"
				}
			};
		case "1.2.840.113549.2.10":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-384"
				}
			};
		case "1.2.840.113549.2.11":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-512"
				}
			};
		case "1.2.840.113549.1.9.16.3.5":
			return {
				name: "DH"
			};
		case "1.3.14.3.2.26":
			return {
				name: "SHA-1"
			};
		case "2.16.840.1.101.3.4.2.1":
			return {
				name: "SHA-256"
			};
		case "2.16.840.1.101.3.4.2.2":
			return {
				name: "SHA-384"
			};
		case "2.16.840.1.101.3.4.2.3":
			return {
				name: "SHA-512"
			};
		case "1.2.840.113549.1.5.12":
			return {
				name: "PBKDF2"
			};
		//region Special case - OIDs for ECC curves
		case "1.2.840.10045.3.1.7":
			return {
				name: "P-256"
			};
		case "1.3.132.0.34":
			return {
				name: "P-384"
			};
		case "1.3.132.0.35":
			return {
				name: "P-521"
			};
		//endregion
		default:
	}
	
	return {};
}
//**************************************************************************************
/**
 * Getting hash algorithm by signature algorithm
 * @param {AlgorithmIdentifier} signatureAlgorithm Signature algorithm
 * @returns {string}
 */
function getHashAlgorithm(signatureAlgorithm)
{
	let result = "";
	
	switch(signatureAlgorithm.algorithmId)
	{
		case "1.2.840.10045.4.1": // ecdsa-with-SHA1
		case "1.2.840.113549.1.1.5":
			result = "SHA-1";
			break;
		case "1.2.840.10045.4.3.2": // ecdsa-with-SHA256
		case "1.2.840.113549.1.1.11":
			result = "SHA-256";
			break;
		case "1.2.840.10045.4.3.3": // ecdsa-with-SHA384
		case "1.2.840.113549.1.1.12":
			result = "SHA-384";
			break;
		case "1.2.840.10045.4.3.4": // ecdsa-with-SHA512
		case "1.2.840.113549.1.1.13":
			result = "SHA-512";
			break;
		case "1.2.840.113549.1.1.10": // RSA-PSS
			{
				try
			{
				const params = new RSASSAPSSParams({ schema: signatureAlgorithm.algorithmParams });
				if("hashAlgorithm" in params)
				{
					const algorithm = getAlgorithmByOID(params.hashAlgorithm.algorithmId);
					if(("name" in algorithm) === false)
						return "";
					
					result = algorithm.name;
				}
				else
					result = "SHA-1";
			}
			catch(ex)
			{
			}
			}
			break;
		default:
	}
	
	return result;
}

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AttributeTypeAndValue
{
	//**********************************************************************************
	/**
	 * Constructor for AttributeTypeAndValue class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description type
		 */
		this.type = getParametersValue(parameters, "type", AttributeTypeAndValue.defaultValues("type"));
		/**
		 * @type {Object}
		 * @description Value of the AttributeTypeAndValue class
		 */
		this.value = getParametersValue(parameters, "value", AttributeTypeAndValue.defaultValues("value"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "type":
				return "";
			case "value":
				return {};
			default:
				throw new Error(`Invalid member name for AttributeTypeAndValue class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//AttributeTypeAndValue ::= Sequence {
		//    type     AttributeType,
		//    value    AttributeValue }
		//
		//AttributeType ::= OBJECT IDENTIFIER
		//
		//AttributeValue ::= ANY -- DEFINED BY AttributeType

		/**
		 * @type {Object}
		 * @property {string} [blockName] Name for entire block
		 * @property {string} [type] Name for "type" element
		 * @property {string} [value] Name for "value" element
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.type || "") }),
				new Any({ name: (names.value || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {type: Object, typeValue: Object}}}
		 */
		const asn1 = compareSchema(schema,
			schema,
			AttributeTypeAndValue.schema({
				names: {
					type: "type",
					value: "typeValue"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ATTR_TYPE_AND_VALUE");
		//endregion

		//region Get internal properties from parsed schema
		this.type = asn1.result.type.valueBlock.toString();
		this.value = asn1.result.typeValue;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.type }),
				this.value
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const _object = {
			type: this.type
		};

		if(Object.keys(this.value).length !== 0)
			_object.value = this.value.toJSON();
		else
			_object.value = this.value;

		return _object;
	}
	//**********************************************************************************
	/**
	 * Compare two AttributeTypeAndValue values, or AttributeTypeAndValue with ArrayBuffer value
	 * @param {(AttributeTypeAndValue|ArrayBuffer)} compareTo The value compare to current
	 * @returns {boolean}
	 */
	isEqual(compareTo)
	{
		if(compareTo instanceof AttributeTypeAndValue)
		{
			if(this.type !== compareTo.type)
				return false;
			
			if(((this.value instanceof Utf8String) && (compareTo.value instanceof Utf8String)) ||
				((this.value instanceof BmpString) && (compareTo.value instanceof BmpString)) ||
				((this.value instanceof UniversalString) && (compareTo.value instanceof UniversalString)) ||
				((this.value instanceof NumericString) && (compareTo.value instanceof NumericString)) ||
				((this.value instanceof PrintableString) && (compareTo.value instanceof PrintableString)) ||
				((this.value instanceof TeletexString) && (compareTo.value instanceof TeletexString)) ||
				((this.value instanceof VideotexString) && (compareTo.value instanceof VideotexString)) ||
				((this.value instanceof IA5String) && (compareTo.value instanceof IA5String)) ||
				((this.value instanceof GraphicString) && (compareTo.value instanceof GraphicString)) ||
				((this.value instanceof VisibleString) && (compareTo.value instanceof VisibleString)) ||
				((this.value instanceof GeneralString) && (compareTo.value instanceof GeneralString)) ||
				((this.value instanceof CharacterString) && (compareTo.value instanceof CharacterString)))
			{
				const value1 = stringPrep(this.value.valueBlock.value);
				const value2 = stringPrep(compareTo.value.valueBlock.value);
				
				if(value1.localeCompare(value2) !== 0)
					return false;
			}
			else // Comparing as two ArrayBuffers
			{
				if(isEqualBuffer(this.value.valueBeforeDecode, compareTo.value.valueBeforeDecode) === false)
					return false;
			}
			
			return true;
		}
		
		if(compareTo instanceof ArrayBuffer)
			return isEqualBuffer(this.value.valueBeforeDecode, compareTo);

		return false;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class RelativeDistinguishedNames
{
	//**********************************************************************************
	/**
	 * Constructor for RelativeDistinguishedNames class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {Array.<AttributeTypeAndValue>} [typesAndValues] Array of "type and value" objects
	 * @property {ArrayBuffer} [valueBeforeDecode] Value of the RDN before decoding from schema
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<AttributeTypeAndValue>}
		 * @description Array of "type and value" objects
		 */
		this.typesAndValues = getParametersValue(parameters, "typesAndValues", RelativeDistinguishedNames.defaultValues("typesAndValues"));
		/**
		 * @type {ArrayBuffer}
		 * @description Value of the RDN before decoding from schema
		 */
		this.valueBeforeDecode = getParametersValue(parameters, "valueBeforeDecode", RelativeDistinguishedNames.defaultValues("valueBeforeDecode"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "typesAndValues":
				return [];
			case "valueBeforeDecode":
				return new ArrayBuffer(0);
			default:
				throw new Error(`Invalid member name for RelativeDistinguishedNames class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "typesAndValues":
				return (memberValue.length === 0);
			case "valueBeforeDecode":
				return (memberValue.byteLength === 0);
			default:
				throw new Error(`Invalid member name for RelativeDistinguishedNames class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RDNSequence ::= Sequence OF RelativeDistinguishedName
		//
		//RelativeDistinguishedName ::=
		//SET SIZE (1..MAX) OF AttributeTypeAndValue

		/**
		 * @type {Object}
		 * @property {string} [blockName] Name for entire block
		 * @property {string} [repeatedSequence] Name for "repeatedSequence" block
		 * @property {string} [repeatedSet] Name for "repeatedSet" block
		 * @property {string} [typeAndValue] Name for "typeAndValue" block
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.repeatedSequence || ""),
					value: new Set({
						value: [
							new Repeated({
								name: (names.repeatedSet || ""),
								value: AttributeTypeAndValue.schema(names.typeAndValue || {})
							})
						]
					})
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {RDN: Object, typesAndValues: Array.<Object>}}}
		 */
		const asn1 = compareSchema(schema,
			schema,
			RelativeDistinguishedNames.schema({
				names: {
					blockName: "RDN",
					repeatedSet: "typesAndValues"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RDN");
		//endregion

		//region Get internal properties from parsed schema
		if("typesAndValues" in asn1.result) // Could be a case when there is no "types and values"
			this.typesAndValues = Array.from(asn1.result.typesAndValues, element => new AttributeTypeAndValue({ schema: element }));

		this.valueBeforeDecode = asn1.result.RDN.valueBeforeDecode;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Decode stored TBS value
		if(this.valueBeforeDecode.byteLength === 0) // No stored encoded array, create "from scratch"
		{
			return (new Sequence({
				value: [new Set({
					value: Array.from(this.typesAndValues, element => element.toSchema())
				})]
			}));
		}

		const asn1 = fromBER(this.valueBeforeDecode);
		//endregion

		//region Construct and return new ASN.1 schema for this object
		return asn1.result;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			typesAndValues: Array.from(this.typesAndValues, element => element.toJSON())
		};
	}
	//**********************************************************************************
	/**
	 * Compare two RDN values, or RDN with ArrayBuffer value
	 * @param {(RelativeDistinguishedNames|ArrayBuffer)} compareTo The value compare to current
	 * @returns {boolean}
	 */
	isEqual(compareTo)
	{
		if(compareTo instanceof RelativeDistinguishedNames)
		{
			if(this.typesAndValues.length !== compareTo.typesAndValues.length)
				return false;

			for(const [index, typeAndValue] of this.typesAndValues.entries())
			{
				if(typeAndValue.isEqual(compareTo.typesAndValues[index]) === false)
					return false;
			}

			return true;
		}

		if(compareTo instanceof ArrayBuffer)
			return isEqualBuffer(this.valueBeforeDecode, compareTo);

		return false;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
function CertificationRequestInfo(parameters = {})
{
	//CertificationRequestInfo ::= SEQUENCE {
	//    version       INTEGER { v1(0) } (v1,...),
	//    subject       Name,
	//    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	//    attributes    [0] Attributes{{ CRIAttributes }}
	//}
	
	/**
	 * @type {Object}
	 * @property {string} [blockName]
	 * @property {string} [CertificationRequestInfo]
	 * @property {string} [CertificationRequestInfoVersion]
	 * @property {string} [subject]
	 * @property {string} [CertificationRequestInfoAttributes]
	 * @property {string} [attributes]
	 */
	const names = getParametersValue(parameters, "names", {});
	
	return (new Sequence({
		name: (names.CertificationRequestInfo || "CertificationRequestInfo"),
		value: [
			new Integer({ name: (names.CertificationRequestInfoVersion || "CertificationRequestInfo.version") }),
			RelativeDistinguishedNames.schema(names.subject || {
				names: {
					blockName: "CertificationRequestInfo.subject"
				}
			}),
			PublicKeyInfo.schema({
				names: {
					blockName: "CertificationRequestInfo.subjectPublicKeyInfo"
				}
			}),
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [
					new Repeated({
						optional: true, // Because OpenSSL makes wrong "attributes" field
						name: (names.CertificationRequestInfoAttributes || "CertificationRequestInfo.attributes"),
						value: Attribute.schema(names.attributes || {})
					})
				]
			})
		]
	}));
}
//**************************************************************************************
/**
 * Class from RFC2986
 */
class CertificationRequest {
	//**********************************************************************************
	/**
	 * Constructor for Attribute class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {ArrayBuffer}
		 * @description tbs
		 */
		this.tbs = getParametersValue(parameters, "tbs", CertificationRequest.defaultValues("tbs"));
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", CertificationRequest.defaultValues("version"));
		/**
		 * @type {RelativeDistinguishedNames}
		 * @description subject
		 */
		this.subject = getParametersValue(parameters, "subject", CertificationRequest.defaultValues("subject"));
		/**
		 * @type {PublicKeyInfo}
		 * @description subjectPublicKeyInfo
		 */
		this.subjectPublicKeyInfo = getParametersValue(parameters, "subjectPublicKeyInfo", CertificationRequest.defaultValues("subjectPublicKeyInfo"));
		
		if("attributes" in parameters)
			/**
			 * @type {Array.<Attribute>}
			 * @description attributes
			 */
			this.attributes = getParametersValue(parameters, "attributes", CertificationRequest.defaultValues("attributes"));
		
		/**
		 * @type {AlgorithmIdentifier}
		 * @description signatureAlgorithm
		 */
		this.signatureAlgorithm = getParametersValue(parameters, "signatureAlgorithm", CertificationRequest.defaultValues("signatureAlgorithm"));
		/**
		 * @type {BitString}
		 * @description signatureAlgorithm
		 */
		this.signatureValue = getParametersValue(parameters, "signatureValue", CertificationRequest.defaultValues("signatureValue"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "tbs":
				return new ArrayBuffer(0);
			case "version":
				return 0;
			case "subject":
				return new RelativeDistinguishedNames();
			case "subjectPublicKeyInfo":
				return new PublicKeyInfo();
			case "attributes":
				return [];
			case "signatureAlgorithm":
				return new AlgorithmIdentifier();
			case "signatureValue":
				return new BitString();
			default:
				throw new Error(`Invalid member name for CertificationRequest class: ${memberName}`);
		}
	}
	
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//CertificationRequest ::= SEQUENCE {
		//    certificationRequestInfo CertificationRequestInfo,
		//    signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
		//    signature                BIT STRING
		//}
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [certificationRequestInfo]
		 * @property {string} [signatureAlgorithm]
		 * @property {string} [signatureValue]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			value: [
				CertificationRequestInfo(names.certificationRequestInfo || {}),
				new Sequence({
					name: (names.signatureAlgorithm || "signatureAlgorithm"),
					value: [
						new ObjectIdentifier(),
						new Any({ optional: true })
					]
				}),
				new BitString({ name: (names.signatureValue || "signatureValue") })
			]
		}));
	}
	
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			CertificationRequest.schema()
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PKCS10");
		//endregion
		
		//region Get internal properties from parsed schema
		this.tbs = asn1.result.CertificationRequestInfo.valueBeforeDecode;
		
		this.version = asn1.result["CertificationRequestInfo.version"].valueBlock.valueDec;
		this.subject = new RelativeDistinguishedNames({ schema: asn1.result["CertificationRequestInfo.subject"] });
		this.subjectPublicKeyInfo = new PublicKeyInfo({ schema: asn1.result["CertificationRequestInfo.subjectPublicKeyInfo"] });
		if("CertificationRequestInfo.attributes" in asn1.result)
			this.attributes = Array.from(asn1.result["CertificationRequestInfo.attributes"], element => new Attribute({ schema: element }));
		
		this.signatureAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.signatureAlgorithm });
		this.signatureValue = asn1.result.signatureValue;
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Aux function making ASN1js Sequence from current TBS
	 * @returns {Sequence}
	 */
	encodeTBS()
	{
		//region Create array for output sequence
		const outputArray = [
			new Integer({ value: this.version }),
			this.subject.toSchema(),
			this.subjectPublicKeyInfo.toSchema()
		];
		
		if("attributes" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: Array.from(this.attributes, element => element.toSchema())
			}));
		}
		//endregion
		
		return (new Sequence({
			value: outputArray
		}));
	}
	
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema(encodeFlag = false)
	{
		//region Decode stored TBS value
		let tbsSchema;
		
		if(encodeFlag === false)
		{
			if(this.tbs.length === 0) // No stored TBS part
				return CertificationRequest.schema();
			
			tbsSchema = fromBER(this.tbs).result;
		}
		//endregion
		//region Create TBS schema via assembling from TBS parts
		else
			tbsSchema = this.encodeTBS();
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				tbsSchema,
				this.signatureAlgorithm.toSchema(),
				this.signatureValue
			]
		}));
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			tbs: bufferToHexCodes(this.tbs, 0, this.tbs.byteLength),
			version: this.version,
			subject: this.subject.toJSON(),
			subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJSON(),
			signatureAlgorithm: this.signatureAlgorithm.toJSON(),
			signatureValue: this.signatureValue.toJSON()
		};
		
		if("attributes" in this)
			object.attributes = Array.from(this.attributes, element => element.toJSON());
		
		return object;
	}
	
	//**********************************************************************************
	/**
	 * Makes signature for currect certification request
	 * @param {Object} privateKey WebCrypto private key
	 * @param {string} [hashAlgorithm=SHA-1] String representing current hashing algorithm
	 */
	sign(privateKey, hashAlgorithm = "SHA-1")
	{
		//region Get a private key from function parameter
		if(typeof privateKey === "undefined")
			return Promise.reject("Need to provide a private key for signing");
		//endregion
		
		//region Get hashing algorithm
		const oid = getOIDByAlgorithm({ name: hashAlgorithm });
		if(oid === "")
			return Promise.reject("Unsupported hash algorithm: {$hashAlgorithm}");
		//endregion
		
		//region Get a "default parameters" for current algorithm
		const defParams = getAlgorithmParameters(privateKey.algorithm.name, "sign");
		defParams.algorithm.hash.name = hashAlgorithm;
		//endregion
		
		//region Fill internal structures base on "privateKey" and "hashAlgorithm"
		switch(privateKey.algorithm.name.toUpperCase())
		{
			case "RSASSA-PKCS1-V1_5":
			case "ECDSA":
				this.signatureAlgorithm.algorithmId = getOIDByAlgorithm(defParams.algorithm);
				break;
			case "RSA-PSS":
				{
				//region Set "saltLength" as a length (in octets) of hash function result
					switch(hashAlgorithm.toUpperCase())
				{
						case "SHA-256":
							defParams.algorithm.saltLength = 32;
							break;
						case "SHA-384":
							defParams.algorithm.saltLength = 48;
							break;
						case "SHA-512":
							defParams.algorithm.saltLength = 64;
							break;
						default:
					}
				//endregion
				
				//region Fill "RSASSA_PSS_params" object
					const paramsObject = {};
				
					if(hashAlgorithm.toUpperCase() !== "SHA-1")
				{
						const hashAlgorithmOID = getOIDByAlgorithm({ name: hashAlgorithm });
						if(hashAlgorithmOID === "")
							return Promise.reject(`Unsupported hash algorithm: ${hashAlgorithm}`);
					
						paramsObject.hashAlgorithm = new AlgorithmIdentifier({
							algorithmId: hashAlgorithmOID,
							algorithmParams: new Null()
						});
					
						paramsObject.maskGenAlgorithm = new AlgorithmIdentifier({
							algorithmId: "1.2.840.113549.1.1.8", // MGF1
							algorithmParams: paramsObject.hashAlgorithm.toSchema()
						});
					}
				
					if(defParams.algorithm.saltLength !== 20)
						paramsObject.saltLength = defParams.algorithm.saltLength;
				
					const pssParameters = new RSASSAPSSParams(paramsObject);
				//endregion
				
				//region Automatically set signature algorithm
					this.signatureAlgorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.113549.1.1.10",
						algorithmParams: pssParameters.toSchema()
					});
				//endregion
				}
				break;
			default:
				return Promise.reject(`Unsupported signature algorithm: ${privateKey.algorithm.name}`);
		}
		//endregion
		
		//region Create TBS data for signing
		this.tbs = this.encodeTBS().toBER(false);
		//endregion
		
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			return Promise.reject("Unable to create WebCrypto object");
		//endregion
		
		//region Signing TBS data on provided private key
		return crypto.sign(defParams.algorithm,
			privateKey,
			new Uint8Array(this.tbs)
		).then(result =>
			{
				//region Special case for ECDSA algorithm
			if(defParams.algorithm.name === "ECDSA")
				result = createCMSECDSASignature(result);
				//endregion
				
			this.signatureValue = new BitString({ valueHex: result });
		}, error => Promise.reject(`Signing error: ${error}`)
		);
		//endregion
	}
	
	//**********************************************************************************
	/**
	 * Verify existing certification request signature
	 * @returns {*}
	 */
	verify()
	{
		//region Global variables
		let sequence = Promise.resolve();
		
		const subjectPublicKeyInfo = this.subjectPublicKeyInfo;
		const signature = this.signatureValue;
		const tbs = this.tbs;
		//endregion
		
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			return Promise.reject("Unable to create WebCrypto object");
		//endregion
		
		//region Find a correct hashing algorithm
		const shaAlgorithm = getHashAlgorithm(this.signatureAlgorithm);
		if(shaAlgorithm === "")
			return Promise.reject(`Unsupported signature algorithm: ${this.signatureAlgorithm.algorithmId}`);
		//endregion
		
		//region Importing public key
		sequence = sequence.then(() =>
		{
			//region Get information about public key algorithm and default parameters for import
			let algorithmId;
			if(this.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10")
				algorithmId = this.signatureAlgorithm.algorithmId;
			else
				algorithmId = this.subjectPublicKeyInfo.algorithm.algorithmId;
			
			const algorithmObject = getAlgorithmByOID(algorithmId);
			if(("name" in algorithmObject) === false)
				return Promise.reject(`Unsupported public key algorithm: ${algorithmId}`);
			
			const algorithmName = algorithmObject.name;
			
			const algorithm = getAlgorithmParameters(algorithmName, "importkey");
			if("hash" in algorithm.algorithm)
				algorithm.algorithm.hash.name = shaAlgorithm;
			
			//region Special case for ECDSA
			if(algorithmObject.name === "ECDSA")
			{
				// #region Get information about named curve
				let algorithmParamsChecked = false;
				
				if(("algorithmParams" in subjectPublicKeyInfo.algorithm) === true)
				{
					if("idBlock" in subjectPublicKeyInfo.algorithm.algorithmParams)
					{
						if((subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagClass === 1) && (subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagNumber === 6))
							algorithmParamsChecked = true;
					}
				}
				
				if(algorithmParamsChecked === false)
					return Promise.reject("Incorrect type for ECDSA public key parameters");
				
				const curveObject = getAlgorithmByOID(subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
				if(("name" in curveObject) === false)
					return Promise.reject(`Unsupported named curve algorithm: ${subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString()}`);
				// #endregion
				
				algorithm.algorithm.namedCurve = curveObject.name;
			}
			//endregion
			//endregion
			
			const publicKeyInfoSchema = subjectPublicKeyInfo.toSchema();
			const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
			const publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);
			
			return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
		});
		//endregion
		
		//region Verify signature
		sequence = sequence.then(publicKey =>
		{
			//region Get default algorithm parameters for verification
			const algorithm = getAlgorithmParameters(publicKey.algorithm.name, "verify");
			if("hash" in algorithm.algorithm)
				algorithm.algorithm.hash.name = shaAlgorithm;
			//endregion
			
			//region Special case for ECDSA signatures
			let signatureValue = signature.valueBlock.valueHex;
			
			if(publicKey.algorithm.name === "ECDSA")
			{
				const asn1 = fromBER(signatureValue);
				signatureValue = createECDSASignatureFromCMS(asn1.result);
			}
			//endregion
			
			//region Special case for RSA-PSS
			if(publicKey.algorithm.name === "RSA-PSS")
			{
				let pssParameters;
				
				try
				{
					pssParameters = new RSASSAPSSParams({ schema: this.signatureAlgorithm.algorithmParams });
				}
				catch(ex)
				{
					return Promise.reject(ex);
				}
				
				if("saltLength" in pssParameters)
					algorithm.algorithm.saltLength = pssParameters.saltLength;
				else
					algorithm.algorithm.saltLength = 20;
				
				let hashAlgo = "SHA-1";
				
				if("hashAlgorithm" in pssParameters)
				{
					const hashAlgorithm = getAlgorithmByOID(pssParameters.hashAlgorithm.algorithmId);
					if(("name" in hashAlgorithm) === false)
						return Promise.reject(`Unrecognized hash algorithm: ${pssParameters.hashAlgorithm.algorithmId}`);
					
					hashAlgo = hashAlgorithm.name;
				}
				
				algorithm.algorithm.hash.name = hashAlgo;
			}
			//endregion
			
			return crypto.verify(algorithm.algorithm,
				publicKey,
				new Uint8Array(signatureValue),
				new Uint8Array(tbs));
		});
		//endregion
		
		return sequence;
	}
	
	//**********************************************************************************
}
//**************************************************************************************

/***************\
* CSR GENERATOR *
\***************/


/*********\
* HELPERS *
\*********/

function formatPEM(pemString)
{
	/// <summary>Format string in order to have each line with length equal to 63</summary>
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
	//Initial variables
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
		value: new PrintableString({ value: "user" })
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
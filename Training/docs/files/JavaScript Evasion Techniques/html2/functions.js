
// var f = require('C:\\Users\\<username>\\functions.js');
// f.ascToB64('alert(1)');
// 'YWxlcnQoMSk='


// Helper functions //
const convert = (baseFrom, baseTo) => number => parseInt(number, baseFrom).toString(baseTo);
const bin2dec = convert(2, 10);
const dec2bin = convert(10, 2);
const bin2oct = convert(2, 8);
const oct2bin = convert(8, 2);
const bin2hex = convert(2, 16);
const hex2bin = convert(16, 2);
const dec2hex = convert(10, 16);
const hex2dec = convert(16, 10);
const dec2oct = convert(10, 8);
const oct2dec = convert(8, 10);


// xor //
exports.xor = function xor(txt, key) {
	var res="";
	for(i=0;i<txt.length;i++){
		res+=String.fromCharCode(key^txt.charCodeAt(i));
	}
	return res;
}


// Base64 //
exports.ascToB64 = function ascToB64(str) {
	var encoded = new Buffer(str).toString('base64');
	return encoded;
}
exports.b64ToAsc = function b64ToAsc(str) {
	var decoded = new Buffer(str, 'base64').toString('ascii');
	return decoded;
}


// Reverse //
exports.revStr = function revStr(str) {
	return str.split("").reverse().join("");
}


// Hex //
exports.ascToHex = function ascToHex(str) {
	var encoded = new Buffer(str);
	return [...encoded].map(dec2hex);
}
exports.hexToAsc = function hexToAsc(arr) {
	d = arr.map(hex2dec);
	return String.fromCharCode.apply(String, d);
}


// Decimal //
exports.ascToDec = function ascToDec(str) {
	var arr = [];
	for (i = 0;i<str.length;i++) {
		arr.push(str[i].charCodeAt(0));
	}
	return arr;
}
exports.decToAsc = function decToAsc(arr) {
	return String.fromCharCode.apply(String, arr);
}


// Octal //
exports.ascToOct = function ascToOct(str) {
	var b = new Buffer(str);
	return [...b].map(dec2oct);
}
exports.octToAsc = function octToAsc(arr) {
	d = arr.map(oct2dec);
	return String.fromCharCode.apply(String, d);
}


// Binary //
exports.ascToBin = function ascToBin(str) {
	var b = new Buffer(str);
	return [...b].map(dec2bin);
}
exports.binToAsc = function binToAsc(arr) {
	d = arr.map(bin2dec);
	return String.fromCharCode.apply(String, d);
}



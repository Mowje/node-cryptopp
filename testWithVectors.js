var fs = require('fs');
var path = require('path');
var Buffer = require('buffer').Buffer;
var assert = require('assert');

var cryptopp = require('./');

var yell = false;

for (var i = 2; i < process.argv.length; i++){
	if (process.argv[i] == 'verbose') yell = true;
}

function log(m){
	if (yell) console.log(m);
}

function err(m){
	console.error(m);
}

var testVectorsPath = path.join(__dirname, 'testvectors');

var sharedArgMatching = /##(\w+)-here##/g;

var testVectorsFileList = fs.readdirSync(testVectorsPath);
for (var i = 0; i < testVectorsFileList.length; i++){
	log('Testing ' + testVectorsFileList[i]);
	try {
		runTestFile(testVectorsFileList[i]);
	} catch (e){
		if (e.message == 'NOT_VALID_ARRAY' || e.message == 'CANNOT_PARSE') err('Cannot run test file ' + testVectorsFileList[i] + '  -  Skipping');
		else throw e;
	}
}

function runTestFile(fName){

	var testFileData = fs.readFileSync(path.join(testVectorsPath, fName), 'utf8');
	try {
		testFileData = JSON.parse(testFileData);
	} catch (e){
		console.error(e);
		throw new Error('CANNOT_PARSE');
	}

	if (!(Array.isArray(testFileData) && testFileData.length > 0)){
		throw new TypeError('NOT_VALID_ARRAY');
	}

	for (var caseI = 0; caseI < testFileData.length; caseI++){
		var currentCase = testFileData[caseI];

		var sharedArgs = currentCase.sharedArgs;
		var calls = currentCase.calls;

		for (var i = 0; i < calls.length; i++){
			console.log('Test call: ' + i);
			var methodRef = getMethodReference(calls[i].method, cryptopp);
			var methodArgs = applySharedArgs(sharedArgs, calls[i].args);

			var methodResult = methodRef.apply(this, methodArgs);
			assert.equal(calls[i].expected, methodResult, 'Unexpected result for ' + calls[i].method + ' with args ' + JSON.stringify(calls[i].args) + ' : ' + JSON.stringify(methodResult));
		}
	}
}

function applySharedArgs(sharedArgs, args){
	if (typeof sharedArgs != 'object') throw new TypeError('sharedArgs must be an object');
	if (!Array.isArray(args)) throw new TypeError('args must be an array');

	for (var i = 0; i < args.length; i++){
		var matchResult = /##(\w+)-here##/g.exec(args[i]);
		if (matchResult && matchResult[1]){ //The arg is a shared-arg
			var sharedArgName = matchResult[1];

			if (!sharedArgs[sharedArgName]) continue; //If the sharedArgName cannot be found in sharedArgs, go to next args element

			var sharedArgValue = sharedArgs[sharedArgName];
			args[i] = sharedArgValue; //Replace the argName in the args array by its value
		}
		args[i] = sanitizeSharedArg(args[i]);
	}

	return args;
}

function sanitizeSharedArg(a){
	if (typeof a == 'string') return a;
	if (typeof a != 'object') throw new TypeError(JSON.stringify(a) + ' is not an object');

	if (a.type == 'hex' || a.type == 'base64') return a.val.replace(/ +/g, '');
	else if (a.type == 'hexToUtf8'){
		console.log('hex length: ' + a.val.replace(/ +g/, '').length);
		var bufVal = new Buffer(a.val.replace(/ +/g, ''), 'hex');
		return bufVal.toString('utf8');
	}
	else if (a.type == 'base64ToUtf8'){
		var bufVal = new Buffer(a.val.replace(/ +/g, ''), 'base64');
		return bufVal.toString('utf8');
	}
	else if (a.type == 'utf8') return a.val;
	else throw new TypeError('unknown value type: ' + a.type);
}

function getMethodReference(methodName, parent){
	if (typeof methodName == 'string') methodName = methodName.split(/\./g);
	if (methodName.length == 0) return parent;

	var nextNamePart = methodName[0];

	if (!(parent[nextNamePart])) return;

	parent = parent[nextNamePart];
	return getMethodReference(methodName.slice(1) , parent);
}

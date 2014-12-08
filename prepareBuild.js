var os = require('os');
var fs = require('fs');
var path = require('path');

var platform = os.platform();
var arch = os.arch();
var kernelVersion = os.release().split('.');
var kernelMajorVersion = kernelVersion[0];
kernelMajorVersion = Number(kernelMajorVersion);

var isOSXMavericksOrSuperior = false;

if (!isNaN(kernelMajorVersion) && kernelMajorVersion >= 13 && platform == 'darwin' && arch == 'x64') isOSXMavericksOrSuperior = true;

if (isOSXMavericksOrSuperior){
	console.log('OSX mavericks');
	fs.writeFileSync('binding.gyp', fs.readFileSync('osx13-binding.gyp'));
	fs.writeFileSync('cryptopp/GNUmakefile', fs.readFileSync('compileLibOSX13'));
} else {
	console.log('Standard binding and compilation process');
	fs.writeFileSync('binding.gyp', fs.readFileSync('std-binding.gyp'));
	fs.writeFileSync('cryptopp/GNUmakefile', fs.readFileSync('compileLib'));
}

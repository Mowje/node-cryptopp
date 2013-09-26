//Setting this module's exports as the C++ lib
var cppLib = require('./build/Release/cryptopp');
module.exports = cppLib;
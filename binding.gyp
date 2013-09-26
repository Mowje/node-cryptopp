{
	"targets" :[
		{
			"target_name": "cryptopp",
			"sources": ["node-cryptopp.cpp"],
			"include_dirs": ["/usr/include"],
			"libraries": ["-lcryptopp"],
			"library_dirs": ["/usr/lib"],
			"cflags!": ["-fno-exceptions"],
			"cflags_cc!": ["-fno-exceptions", "-fno-rtti"],
			"conditions": [
				['OS=="mac"', {
					"xcode_settings": {
						"GCC_ENABLE_CPP_EXCEPTIONS": "YES"
					}
				}]
			]
		}
	]
}
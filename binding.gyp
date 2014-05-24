{
	"targets" :[
		{
			"target_name": "cryptopp",
			"sources": ["node-cryptopp.cpp", "keyring.cc"],
			"include_dirs": ["."],
			"libraries": ["../cryptopp/libcryptopp.a"],
			"cflags!": ["-fno-exceptions"],
			"cflags_cc!": ["-fno-exceptions", "-fno-rtti"],
			"cflags_cc+": ["-frtti"],
			"conditions": [
				['OS=="mac"', {
					"xcode_settings": {
						"GCC_ENABLE_CPP_EXCEPTIONS": "YES",
						"GCC_ENABLE_CPP_RTTI": "YES"
					}
				}]
			]
		}
	]
}

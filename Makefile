clean:
	-rm -rf build
	-rm *.key

clean-all: clean
	cd cryptopp; \
	make clean

git-pull:
	-git pull
	git submodule init
	git submodule update
	git submodule status

cryptopp:
	-rm -rf cryptopp
	git clone https://github.com/Mowje/cryptopp.git

build: cryptopp
	-rm cryptopp/GNUmakefile
	#cp compileLib cryptopp/GNUmakefile
	ls
	node prepareBuild.js
	cd cryptopp && make clean && make static
	node-gyp rebuild

rebuild: clean build

test: build
	cd cryptopp && make test
	node test.js
	node keyManagerTest.js

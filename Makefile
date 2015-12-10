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
	cd cryptopp && git pull origin master

cryptopp/GNUmakefile-cross:
	git clone https://github.com/Mowje/cryptopp.git

build: cryptopp/GNUmakefile-cross
	cd cryptopp && make clean && make static
	node-gyp rebuild

rebuild: clean build

test: build
	cd cryptopp && make test
	node test.js verbose
	node keyManagerTest.js verbose

SHELL := /bin/bash
TEST = test/*.js
REPORTER = dot

CHDIR_SHELL := $(SHELL)
define chdir
	$(eval _D=$(firstword $(1) $(@D)))
	$(info $(MAKE): cd $(_D) $(eval SHELL = cd $(_D); $(CHDIR_SHELL))
endef

clean:
	rm -rf build
	rm *.key
	cd cryptopp; \
	make clean

git-pull:
	git pull
	git submodule init
	git submodule update
	git submodule status

git-getcryptopp:
	git init
	git submodule add https://github.com/Tashweesh/cryptopp.git
	git submodule update

build:
	cd cryptopp; \
	make
	node-gyp rebuild
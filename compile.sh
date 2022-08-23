g++ -o chans.out src/main.cpp -lssl -lcrypto -lcurl -lfmt -lgpgme -lboost_log `gpgme-config --cflags`

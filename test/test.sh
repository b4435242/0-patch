app_pid=$(pidof openssl)

#sudo gdbserver --attach :9953 $app_pid 

python3 ~/0-patch/src/main.py --bin openssl/apps/openssl --cmd openssl_ctr_config --port 9953 --pid $app_pid

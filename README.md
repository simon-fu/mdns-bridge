## 安装RUST编译器
```shell
curl https://sh.rustup.rs -sSf | sh
```

## 编译
```shell
cargo run --release
```

## 运行
```shell
./target/release/mdns-bridge --eth en0 utun1
```
其中 en0 是物理网卡名， utun1 是vpn虚拟网卡名。


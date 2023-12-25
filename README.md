## 安装RUST编译器
```shell
curl https://sh.rustup.rs -sSf | sh
```

## 编译
```shell
cargo run --release
```

## 查看网卡列表
```shell
ifconfig
```

## 运行
```shell
./target/release/mdns-bridge --eth en0 utun1
```
其中 en0 是物理网卡名， utun1 是vpn虚拟网卡名。  
如果提示错误: 
```
failed to make interface ...
```
可能是权限的问题，尝试在命令行前面加上sudo，会提示输入密码
```shell
sudo ./target/release/mdns-bridge --eth en0 utun1
```


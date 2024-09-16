# SandboxAttacher

SandboxAttacher是用于快速将沙箱规则并入二进制文件的一个工具脚本，有如下几点优点：
- 对原二进制程序的改动很小，在amd64情况下，基础占用0x4b字节，每多一条规则就多占用8字节
- 可以自由选择禁用掉哪些系统调用
- 可自动分析开始跳转的位置

缺点如下：
- 二进制程序必须以root权限运行，安全性不足，且在awd比赛中需要先进行提权
- 有时候需要自己将ehframe段增加可执行权限

## 安装
```bash
git clone https://github.com/collectcrop/SandboxAttacher.git
cd repository
pip3 install -r requirements.txt
```

## 使用说明
最基本的使用方式(默认架构为amd64)：
```bash
python3 SandboxAttacher.py -f yourBinary -d execve execveat
```
这将会在yourBinary这个二进制文件的main函数的起始处进行patch跳转，跳转到ehframe段禁用掉execve以及execveat系统调用，并在最后自动执行之前patch覆盖掉的指令。

你可以自己指定开始patch的位置以及最后跳转回来的位置，请注意自定义指定后还需要指定自己覆盖掉的指令,并且确保fr到to之间至少要有5字节
```
python3 SandboxAttacher.py -f yourBinary -d execve execveat --fr 0x4011F0 --to 0x4011F5 --asm 'call 0x40117A'
```

## 引用库

本项目使用了以下第三方库：

- [AwdPwnPatcher](https://github.com/aftern00n/AwdPwnPatcher)：该库用于实现 **将机器码写入目标二进制程序中**。

感谢这些开源项目的贡献！

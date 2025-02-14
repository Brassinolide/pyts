# pyts
A command line tool to create RFC-3161 timestamp signatures

https://crackme.net/articles/tsa/

本项目中的`openssl.exe`修复了在windows系统上无法加载`org.openssl.winstore://`的bug，sha256为`d5e638ac5e37e6bc6b292852b25d463875d188f67340063ca5cd10d6e9393bc7`，在windows系统上建议使用此openssl以加载系统证书

# 已测试的TSA

| 服务器 | 根证书 |
| ----------- | ----------- |
| http://timestamp.digicert.com | DigiCert Assured ID Root CA |
| http://rfc3161timestamp.globalsign.com/advanced | GlobalSign Root CA - R6 |
| https://timestamp.sectigo.com | USERTrust RSA Certification Authority |
| http://timestamp.apple.com/ts01 | Apple Root CA |

# 示例用法

安装库

```shell
pip install asn1crypto colorama
```

创建签名

```shell
pyts sign -i example.txt
```

![](1.png)

查看签名

```shell
pyts -d example.tsr
```

![](2.png)

验证签名

```shell
pyts verify -i example.tsr --ca r6.pem
```

![](3.png)

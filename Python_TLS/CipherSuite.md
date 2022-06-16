TLS_一定有
WITH_不一定有
没有WITH,TLS后可能有3个，4个：
- TLS_SHA384_SHA384
- TLS_SM4_GCM_SM3
- TLS_AES_128_GCM_SHA256


WITH_如果有，前面可能有1个，可能有2个,也可能有3个
- 一个比如ECCPWD,比如 NULL
- 更多的是两个，如DH_RSA
- 也有三个，如DH_RSA_EXPORT
WITH_如果有，后面可能3和，可能4个(加密，哈希) 
- 可能是3个，加密可能纯加密带模式无哈希 比如AES_128_CBC；可能是无模式，加密和哈希，如RC4_128_SHA；也可能有模式有哈希，如DES40_CBC_SHA
- 可能有2个，可能是NULL_SHA256

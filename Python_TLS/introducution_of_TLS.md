# 一.TLS

## 1.引言

虽然自己常用sina邮箱，但发现提交的请求中的password字段是经过特殊加密的。更有不少文章专门分析新浪网站登录密码的加解密。该解密密码的操作应该要耗费不少时间。因此在网络上寻找一个邮箱平台如下图所示1-1-1，测试发现提交的登录请求中的密码部分只是简单的md5哈希散列，因为一些免费的简单的md5解密网站的存在，对这个邮箱登录报文以及发送邮件报文的破解还是比较有研究价值。 (实际上没多大区别，最后python解密自己还是选择了hit邮箱，C++解密兜兜转转选择了tom邮箱)

![image-20220522145736034](C:\Users\lkrwz\AppData\Roaming\Typora\typora-user-images\image-20220522145736034.png)

图1-1 2980邮箱登录请求时的post数据部分

## 2.TLS的一些基本概念

下面根据几篇关于TLS通信的机制博客，描述分析https数据包的解密过程。作为知识铺垫。

TLS是在SSL的基础上标准化的产物，目前SSL3.0与TLS1.0保持一致，二者是并列关系。SSL/TLS位于传输层和应用层之间，应用层数据不再直接传递给传输层，而是传递给TLS层，TLS层对从应用层收到的数据进行加密，并增加自己的TLS头。

TLS的设计目标是构建一个安全传输层，在基于连接的传输层（如tcp）上提供的三个重要属性如下：

（1）保密性，保密通过加密encryption实现，所有信息都加密传输，第三方无法窃听

（2）完整性，通过MAC校验机制，一旦被篡改，通信双方会立刻发现 

（3）认证， 双方认证，双方都可以配备证书，防止身份被冒充 

这里参考[SSL/TLS协议详解](SSL/TLS协议详解)学习TLS会话建立过程。完整的TLS会话如下图1-2-1所示：

![协商过程](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/%E5%8D%8F%E5%95%86%E8%BF%87%E7%A8%8B.png)

图1-2-1 TLS会话完整过程图示

### 2.1 SSL建立第一阶段

1.客户端发送给服务器的Client Hello消息，这个消息里包含了一个客户端生成的随机数Client Random、客户端支持的加密套件（Support Ciphers）和 SSL Version 等信息。

一个Cipher Suite的结构大致如下图1-2-2所示，由Key Exchange,Signature,Bulk Encryption,Message Authentication等几个字段组成，分别指明密钥交换算法，签名算法，信息加密算法和消息认证算法：

![img](https://upload-images.jianshu.io/upload_images/14183383-11509ac9776fd111.jpg?imageMogr2/auto-orient/strip|imageView2/2/w/598/format/webp)

图1-2-2 一个加密套件(Cipher Suite)

需要注意的是Client Hello数据包附带的数据随机数Client Random，会在生成session key时使用(session key是会话密钥)，是32个字节，前4个字节是当前的时间戳，后28字节是随机数。Client Random信息如下图1-2-3所示：

![image-20220522151725041](C:\Users\lkrwz\AppData\Roaming\Typora\typora-user-images\image-20220522151725041.png)

图1-2-3 Client Hello数据包中的Client Random信息

另外还观察到Client Hello数据包的TLS层的头部，是很结构化的，如下图1-2-4所示，包括TLS数据包类型，版本和TLS数据长度：

![image-20220522150727442](C:\Users\lkrwz\AppData\Roaming\Typora\typora-user-images\image-20220522150727442.png)

图1-2-4 TLS层头部

2.如果服务器接受并支持Client的所有条件，服务器回送给客户端Server Hello消息，这个消息会从Client Hello传过来的Support Ciphers 里确定一份加密套件，这个套件决定了后续加密和生成摘要时具体使用哪些算法（如下图1-2-5所示的Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)，其具体含义为使用椭圆曲线迪菲赫尔曼密钥交换协议(ECDHE)，RSA的签名算法，GCM工作模式的AES_128加密算法和SHA256的消息认证算法）。

![image-20220522153542756](C:\Users\lkrwz\AppData\Roaming\Typora\typora-user-images\image-20220522153542756.png)

图1-2-5 Server Hello回送的Cipher Suite信息

另外还会生成一份随机数Server Random。注意，至此客户端和服务端都拥有了两个随机数，这两个随机数会在后续生成对称秘钥时用到。

### 2.2 SSL建立第二阶段

该阶段服务器向客户端发送消息。该阶段分为4步：

1. 证书(Certificate)：服务器将数字证书和到根CA整个链发给客户端，使客户端能用服务器证书中的服务器公钥认证服务器，第一次建立SSL必须要有证书，为了让客户端验证服务器自己的身份，客户端验证通过后取出证书中的公钥。
2. 服务器密钥交换(Server Key Exchange)（可选）：这里视密钥交换算法而定，例如RSA或者DH。在Server Key Exchange消息中便会包含完成密钥交换所需的一系列参数。

>在Diffie-Hellman中，客户端无法自行计算预主密钥; 双方都有助于计算它，因此客户端需要从服务器获取Diffie-Hellman公钥。
>
>DH密钥交换中也有签名保护。

3. 证书请求(Certificate Request)（可选）：服务端可能会要求客户自身进行验证，因此消息中包含一些服务器端支持的证书类型（RSA、DSA、ECDSA等）和服务器端所信任的所有证书发行机构的CA列表，客户端会用这些信息来筛选证书，并在SSL建立第三阶段回送相应消息。

4. 服务器握手完成(Server Hello Done)：第二阶段的结束，表示服务器已经将所有信息发送完毕，接下来等待客户端的消息，也是第三阶段开始的信号

### 2.3 SSL建立第三阶段

客户端收到服务器发送的一系列消息并解析后，将本端相应的消息发送给服务器。该阶段分为3步：

1. 证书(Certificate)（可选）：为了向服务器证明自身，客户要发送一个满足服务器Certificate Request要求的证书信息，如果没有证书，则发送一个no_certificate警告。
2. 客户机密钥交换(Client Key Exchange)（Pre-master key）：这里客户端将预备主密钥(Pre-master key)发送给服务端，注意这里会使用从服务端的证书中提取出的公钥进行加密，服务器用自己的私钥解密后才能得到Pre-master key。

>根据之前从服务器端收到的随机数，按照不同的密钥交换算法，算出一个pre-master key，发送给服务器，服务器端收到pre-master key算出master key。而客户端当然也能自己通过pre-master key算出master key。如此以来双方就算出了对称密钥。
>
>如果是RSA算法，会生成一个48字节的随机数，然后用server的公钥加密后再放入报文中。如果是DH算法，这时发送的就是客户端的DH参数，之后服务器和客户端根据DH算法，各自计算出相同的pre-master key.

3. 证书验证(Certificate Verify)（可选），客户端发送了自己证书到服务器端，这个消息才需要发送。其中包含一个签名，对从第一条消息以来的所有握手消息的HMAC值（用master key）进行签名。证明客户端自身拥有客户端证书的公钥。

### 2.4 SSL建立第四阶段

完成握手协议，建立SSL连接。该阶段分为4步，前2个消息来自客户机，后2个消息来自服务器。

建立起一个安全的连接，客户端发送一个Change Cipher Spec消息，并且把协商得到的Cipher Suite拷贝到当前连接的状态之中。然后，客户端用新的算法、密钥参数发送一个Finished消息，这条消息可以检查密钥交换和认证过程是否已经成功。其中包括一个校验值，对客户端整个握手过程的消息进行校验。服务器同样发送Change Cipher Spec消息和Finished消息。握手过程完成，客户端和服务器可以交换应用层数据进行通信。

1. Change Cipher Spec ：编码改变通知，表示随后的信息都将用双方商定好的加密方法和密钥发送。该消息是一个独立的协议，体现在数据包中就是一个字节的数据。是一条事件消息。

2. Clinet Finished:客户端握手结束通知, 表示客户端的握手阶段已经结束。这一项同时也是前面发送的所有内容的hash值，用来供服务器校验（使用HMAC算法计算收到和发送的所有握手消息的摘要，然后通过RFC5246中定义的一个伪函数[PRF](http://tools.ietf.org/html/rfc5246#section-5)计算出结果，加密后发送。此数据是为了在正式传输应用数据之前对刚刚握手建立起来的加解密通道进行验证。）

3. Server Finished:服务端握手结束通知。

   > 使用私钥解密加密的Pre-master key数据，基于之前(Client Hello 和 Server Hello)交换的两个明文随机数 Client Random和Server Random，计算得到协商密钥:enc_key=Fuc(Client Random, Server Random, Pre-Master key);
   >
   > 计算之前所有接收信息的 hash 值，然后解密客户端发送的 encrypted_handshake_message，验证数据和密钥正确性;
   >
   > 发送一个 ChangeCipherSpec（告知客户端已经切换到协商过的加密套件状态，**准备使用**加密套件和 Session Secret加密数据了）
   >
   > 服务端也会使用 Session key加密一段 Finish 消息发送给客户端，以验证之前通过握手建立起来的加解密通道是否成功。

根据之前的握手信息，如果客户端和服务端都能对Finish信息进行正常加解密且消息正确的被验证，则说明握手通道已经建立成功，接下来，双方可以使用上面产生的Session key对数据进行加密传输了。

### 2.5 总结SSL建立过程中的几个重要的secret key

Pre-Master key

Pre-Master key是在客户端使用RSA或者Diffie-Hellman等加密算法生成的。它将用来跟服务端和客户端在Hello阶段产生的随机数结合在一起生成 Master key。Pre-Master key前两个字节是TLS的版本号，这是一个比较重要的用来核对握手数据的版本号。

Master key

由于最后通过交换，客户端和服务端都会有Pre-Master key和随机数，这个随机数将作为后面产生Master key的种子，结合Pre-Master key，客户端和服务端将计算出同样的Master key。

为了保证信息的完整性和机密性，SSL需要**有六个加密密钥**：四个密钥和两个IV。如下图1-2-6所示：

![master](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/master.png)

图1-2-6 SSL通信过程中的四个密钥两个IV

为了信息的可信性，客户端需要一个密钥（HMAC），为了加密要有一个密钥，为了分组加密要一个初始向量IV，服务器也是如此。SSL需要的密钥是单向的，不同于那些在其他方向的密钥。如果在一个方向上有攻击，这种攻击在其他方向是没影响的。生成过程如下图1-2-7所示：

![1](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/1.png)

图1-2-7 从Pre-Master key计算Master key

主密钥(master key)是由一系列的Hash值组成。主密钥是由预备主密钥、ClientHello Random 和 ServerHello Random 通过 PRF 函数生成的。长度是 48 字节。

```
master_secret = PRF(pre_master_key, "master secret", ClientHello.random + ServerHello.random)[:48];
```

PRF的Python实现可以在Python scapy库中找到：[Github地址](https://github.com/secdev/scapy/blob/master/scapy/layers/tls/crypto/prf.py)。PRF 的前身是 P_hash 函数，如下是`_tls_P_hash`和`_tls_PRF`。

```python
def _tls_P_hash(secret, seed, req_len, hm):
    """
    Provides the implementation of P_hash function defined in
    section 5 of RFC 4346 (and section 5 of RFC 5246). Two
    parameters have been added (hm and req_len):
    - secret : the key to be used. If RFC 4868 is to be believed,
               the length must match hm.key_len. Actually,
               python hmac takes care of formatting every key.
    - seed : the seed to be used.
    - req_len : the length of data to be generated by iterating
               the specific HMAC function (hm). This prevents
               multiple calls to the function.
    - hm : the hmac function class to use for iteration (either
           Hmac_MD5 or Hmac_SHA1 in TLS <= 1.1 or
           Hmac_SHA256 or Hmac_SHA384 in TLS 1.2)
    """
    hash_len = hm.hash_alg.hash_len
    n = (req_len + hash_len - 1) // hash_len
    seed = bytes_encode(seed)

    res = b""
    a = hm(secret).digest(seed)  # A(1)

    while n > 0:
        res += hm(secret).digest(a + seed)
        a = hm(secret).digest(a)
        n -= 1

    return res[:req_len]

def _tls_PRF(secret, label, seed, req_len):
    """
    Provides the implementation of TLS PRF function as defined in
    section 5 of RFC 4346:
    PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
                               P_SHA-1(S2, label + seed)
    Parameters are:
    - secret: the secret used by the HMAC in the 2 expansion
              functions (S1 and S2 are the halves of this secret).
    - label: specific label as defined in various sections of the RFC
             depending on the use of the generated PRF keystream
    - seed: the seed used by the expansion functions.
    - req_len: amount of keystream to be generated
    """
    tmp_len = (len(secret) + 1) // 2
    S1 = secret[:tmp_len]
    S2 = secret[-tmp_len:]

    a1 = _tls_P_MD5(S1, label + seed, req_len)
    a2 = _tls_P_SHA1(S2, label + seed, req_len)

    return strxor(a1, a2)
```

 _tls_PRF函数中的label就是一个字符串，在计算不同secret时使用不同的label。比如当Server Hello中没有标记extended master secret时，计算master-secret时label为"master secret"，否则label为"extended master secret"，且用 session_hash 来替代ClientHello.random+ServerHello.random；而计算key_block时label为"key expansion"。

在[RFC 4346的关于tls的描述文档](https://www.rfc-editor.org/rfc/rfc4346)中，看到了一些设计好的结构，虽然只是伪代码描述，但其大致设计理念对我们后期开发还是很有启发意义：

```c++
enum { server, client } ConnectionEnd;
enum { null, rc4, rc2, des, 3des, des40, idea, aes }
BulkCipherAlgorithm;
enum { stream, block } CipherType;
enum { null, md5, sha } MACAlgorithm;
enum { null(0), (255) } CompressionMethod;
struct {
    ConnectionEnd          entity;
    BulkCipherAlgorithm    bulk_cipher_algorithm;
    CipherType             cipher_type;
    uint8                  key_size;
    uint8                  key_material_length;
    MACAlgorithm           mac_algorithm;
    uint8                  hash_size;
    CompressionMethod      compression_algorithm;
    opaque                 master_secret[48];
    opaque                 client_random[32];
    opaque                 server_random[32];
} SecurityParameters;
```

 SSL记录层可以使用上述代码中的SecurityParameters去生成以下四个参数:

1. client write MAC secret
2. server write MAC secret
3. client write key
4. server write key

而且这个SecurityParameters就是即可用作tcp_callback()函数的第二个参数。如课堂讲述的，其被定义为二级指针，是为了使其在函数内部被修改时能够生效。

由主密钥(master key)结合预主密钥，进一步生成密钥材料(Key Block)的示意图如下图1-2-8所示：

![2](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/2.png)

图1-2-8 由主密钥master key计算生成Key Block

从密钥材料Key Block中获取4个加密密钥和两个初始向量IV，如下图所示1-2-9所示：

![3](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/3.png)

图1-2-9 由密钥材料提取加密秘密

根据要求，有4个密钥用于加密和验证每个消息的完整性，他们是：

1. 客户端写入加密密钥(client write encryption key)：客户端用来加密数据，服务器用来解密数据。
2. 服务器写入加密密钥(server write encryption key)：服务器用来加密数据，客户端用来解密数据。
3. 客户端写入MAC密钥(client write mac key)：客户端用来创建MAC，服务器用来验证MAC。
4. 服务器写入MAC密钥(server write mac key)：服务器用来创建MAC，客户端用来验证MAC。

而两个初始向量Client IV和Server IV分别是客户端和服务端加密数据用的初始向量。

### 2.6 SSL会话恢复

会话恢复是指只要客户端和服务器已经通信过一次，它们就可以通过会话恢复的方式来跳过整个握手阶段二直接进行数据传输。其通信建立过程如下图所示1-2-10所示：

![会话恢复](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/%E4%BC%9A%E8%AF%9D%E6%81%A2%E5%A4%8D.png)

图1-2-10 SSL会话恢复过程

当服务器端接收到Client Hello，查看里面的Session ID值为空，表明双方是第一次握手，需要进行一次完整的握手阶段，然后生成一个新的Session ID，表示本次会话，并放到Server Hello子消息中回应给客户端。

在本次会话关闭，下一次再次访问相同的HTTPS网站时，客户端浏览器会在Client Hello子消息中附带这个Session ID值，服务器端接收到请求后，将Session ID与自己在Server Cache中保存的Session ID进行匹配，如果匹配成功，那么服务器端就会恢复上一次的TLS连接，使用之前协商过的密钥，不重新进行密钥协商，服务器收到带Session ID的Client Hello且匹配成功后，直接发送ChangeCipherSpec子协议，告诉TLS记录层将连接状态切换成可读和可写，最后发送Finished，会话恢复成功，本次握手为一次简短的握手，而不是完整的一次握手。

wireshark中捕获的一次SSL会话恢复的通信过程如下图1-2-11所示:：

![image-20220522163714689](C:\Users\lkrwz\AppData\Roaming\Typora\typora-user-images\image-20220522163714689.png)

图1-2-11 SSL会话恢复的Wireshark捕包结果

### 2.7 SSL记录协议

SSL记录协议主要用来实现对数据块的分块、加密解密、压缩与解压缩、完整性检查及封装各种高层协议。

每个SSL Record主要包含以下信息，结构图如下图1-2-12所示：

- 内容类型
- 协议版本号
- 记录数据的长度
- 数据由载荷
- 散列算法计算消息认证代码

![记录协议](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/%E8%AE%B0%E5%BD%95%E5%8D%8F%E8%AE%AE.png)

图1-2-12 SSL Record的结构组成

SSL记录协议工作过程主要如下，示意图如下图1-2-13所示：

- 将消息分割为多个片段；
- 对每个片段进行压缩
- 加上片段编号(防止重放攻击)计算消息验证码MAC值(保证数据完整性)，追加在压缩片段
- 对称密码加密；
- 加上数据类型、版本号、压缩后的长度组成的报头， 就是最终的报文数据；

![记录](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/%E8%AE%B0%E5%BD%95.png)

图1-2-13 SSL记录协议工作过程

### 2.8 应用数据传输

在所有的握手阶段都完成之后，就可以开始传送应用数据了。应用数据在传输之前，首先要附加上MAC secret，然后客户端再对这个数据包使用Client write encryption key进行加密。在服务端收到密文之后，使用Client write encryption key进行解密，客户端收到服务端的数据之后使用Server write encryption key进行解密，然后使用各自的write MAC key对数据的完整性包括是否被篡改进行验证。
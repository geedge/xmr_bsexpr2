# HTTPS 温故知新（五） —— TLS 中的密钥计算

本篇文章我们来对比对比 TLS 1.2 和 TLS 1.3 中的密钥计算。

## 一. TLS 1.2 中的密钥

在 TLS 1.2 中，有 3 种密钥：**预备主密钥（PreMasterSecret）**、**主密钥（Master Secret）**、**会话密钥(密钥块)**，这几个密钥都是有联系的。

```c
   struct {
         uint32 gmt_unix_time;
         opaque random_bytes[28];
   } Random;
   
   struct {
         ProtocolVersion client_version;
         opaque random[46];
   } PreMasterSecret;  

   struct {
         uint8 major;
         uint8 minor;
   } ProtocolVersion;       
```

握手阶段不同的密钥协商方式会生成不同的规格的密钥：
- 对于 RSA 握手协商算法，Client 会生成的一个 48 字节的 `PreMasterSecret`，其中前 2 个字节是 ProtocolVersion，后 46 字节是随机数，用 Server 的公钥加密之后通过 `Client Key Exchange` 子消息发给 Server，Server 用私钥来解密
- 对于 (EC)DHE 来说，`PreMasterSecret` 是双方通过椭圆曲线算法生成的，双方各自生成临时公私钥对，保留私钥，将公钥发给对方，然后就可以用自己的私钥以及对方的公钥通过椭圆曲线算法来生成 `PreMasterSecret`，`PreMasterSecret` 长度取决于 DH/ECDH 算法公钥、是 48 字节或者 X 字节


`Master Secret` 是由 `PreMasterSecret`、`ClientHello random` 和 `ServerHello random` 通过 PRF 函数生成的。**主密钥长度是 48 字节**。可以看出，只要我们知道 `PreMasterSecret` 或者 `Master Secret` 便可以解密抓包数据，所以 TLS 1.2 中抓包解密调试只需要一个 `Master Secret` 即可，SSLKEYLOG 就是将 `Master Secret` 导出来，在 Wireshark 里面导入就可以解密相应的抓包数据。 


会话密钥(密钥块)是由 `Master Secret` 、`SecurityParameters.server_random` 和 `SecurityParameters.client_random` 数通过 PRF 函数来生成，会话密钥里面包含对称加密密钥、消息认证和 CBC 模式的初始化向量，对于非 CBC 模式的加密算法来说，就没有用到这个初始化向量。

**Session ID 缓存和 Session Ticket 里面保存的也是 `Master Secret`**，而不是会话密钥，这样每次会话复用的时候再用双方的随机数和主密钥导出会话密钥，从而实现每次加密通信的会话密钥不一样，即使一个会话的主密钥泄露了或者被破解了也不会影响到另一个会话。


## 二. TLS 1.2 中的 HMAC 和伪随机函数

TLS 1.2 Record 子协议使用一个有密钥的信息验证码(MAC)来保护信息的完整性。密码算法族使用了一个被称为 HMAC 的 MAC 算法，它基于一个 hash 函数。如果必要的话其它密码算法族可以定义它们自己的 MAC 算法。

此外，为了进行密钥生成或验证，需要一个 MAC 算法对数据块进行扩展以增加机密性。这个伪随机函数（PRF）将**机密信息（secret），种子和身份标签**作为输入，并产生任意长度的输出。

在 TLS 1.2 中，基于 HMAC 定义了一个 PRF 函数。这个使用 `SHA-256 hash` 函数的 PRF 函数被用于所有的密码算法套件。新的密码算法套件必须显式指定一个 PRF，通常应该使用 SHA-256 或更强的标准 hash 算法与 TLS PRF 一同使用。

首先，我们定义一个数据扩展函数：`P_hash(secret, data)`，它使用一个 hash 函数扩展一个 secret 和种子，形成任意大小的输出：

```c
P_hash(secret, seed) =  HMAC_hash(secret, A(1) + seed) +
                        HMAC_hash(secret, A(2) + seed) +
                        HMAC_hash(secret, A(3) + seed) + ...                      
```

这里"+"是指串联。A()被定义为：

```c
   A(0) = seed
   A(i) = HMAC_hash(secret, A(i-1))
```

必要时 P_hash 需要经过多次迭代，以产生所需数量的数据。例如，如果 P_SHA256 被用于产生 80 字节的数据，它应该被迭代 3 次(通过 A(3))，SHA_256 每次输出 32 字节(256 bit)，迭代 3 次才能产生 96 字节的输出数据，最终迭代产生的最后 16 字节会被丢弃，留下 80 字节作为输出数据。

TLS 的 PRF 可以通过将 P_hash 运用与 secret 来实现：

```c
   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
```

label 是一个 ASCII 字符串。它应该以严格地按照它被给出的内容进行处理，不包含一个长度字节或结尾添加的空字符。例如，label "slithy toves" 应该通过 hash 下列字节的方式被处理：

```c
   // "slithy toves" 的十六进制格式
   73 6C 69 74 68 79 20 74 6F 76 65 73
```
         
PRF 使用的 Hash 算法取决于 `cipher suites` 和 TLS 版本，对应关系如下：

|PRF 算法 | Hash 算法 |
|:-----: |:-----: |
|prf_tls10 |TLS 1.0 和 TLS 1.1 协议，PRF 算法是结合 MD5 和 SHA_1 算法 |
|prf_tls12_sha256 |TLS 1.2 协议，默认是 SHA_256 算法(这是能满足最低安全的算法) |
|prf_tls12_sha384 |TLS 1.2 协议，如果加密套件指定的 HMAC 算法安全级别高于 SHA_256，则采用加密基元 SHA_384 算法 |

在 TLS 1.0 和 TLS 1.1 中，调用了两次 P_HASH，一次是 MD5 一次是 SHA1，两次的结果进行异或得到最后的结果。

```c
r1 = P_MD5(...);
r2 = P_SHA1(...);
r  = r1 xor r2
```

在 TLS 1.2 中，PRF 算法其实就是直接调用了 P_HASH 算法，默认是 SHA_256 算法。

## 三. TLS 1.2 中的密钥计算

TLS 1.2 中的密钥算法主要是上一章谈到的 PRF。PRF 主要用于导出 `Master Secret` 和会话密钥(密钥块)的。

### 1. 计算 Master Sercet

为了开始连接保护，TLS 记录协议要求指定一个算法套件，一个 `Master Secret` 和 Client 及 Server 端随机数。认证，加密和消息认证码算法由 `cipher_suite` 确定，`cipher_suite` 是由 Server 选定并在 ServerHello 消息中表明出来的。压缩算法在 hello 消息里协商出来，随机数也在 hello 消息中交换。所有这些都用于计算 `Master Secret`。

对于所有的密钥交换算法，相同的算法都会被用来将 `PreMasterSecret` 转化为 `Master Secret`。一旦 `Master Secret` 计算完毕，`PreMasterSecret` 就应当从内存中删除。避免攻击者获取 `PreMasterSecret`，如果攻击者获取到了 `PreMasterSecret`，加上 `ClientHello.random` 和 `ServerHello.random` 传输过程中是不加密的，也容易获取，那么攻击者就可以合成 `Master Secret` 并进一步导出会话密钥，这样整个加密过程就被完全破解了。

```c
    Master Secret = PRF( PreMasterSecret, "master secret",
                        ClientHello.random + ServerHello.random )
                        [0..47];
```

**`Master Secret` 的长度固定为 48 字节。`PreMasterSecret` 的长度根据密钥交换算法而变**。

### RSA

当 RSA 被用于身份认证和密钥交换时，Client 会产生一个 48 字节的 `PreMasterSecret`，用 Server 的公钥加密，然后发送给 Server。Server 用它自己的私钥解密 `PreMasterSecret`。然后双方按照前述方法将 `PreMasterSecret` 转换为 `Master Secret`。

```c
   struct {
         ProtocolVersion client_version;
         opaque random[46];
   } PreMasterSecret; 
```

### Diffie-Hellman

一个传统的 Diffie-Hellman 计算需要被执行。协商出来的密钥（Z）会被用做 `PreMasterSecret`，并按照前述方法将其转换为 `Master Secret`。在被用做 `PreMasterSecret` 之前，Z 开头所有的 0 位都会被压缩。

注：Diffie-Hellman 参数由 Server 指定，可能是临时的也可能包含在 Server 的证书中。


### 2. 计算增强型主密钥

在之前的文章中，我们看到了 ClientHello 的扩展中携带了 `extended_Master Secret` 扩展，这个扩展标识 Client 和 Server 使用增强型主密钥计算方式。   

Server 在 ServerHello 中响应该扩展，返回了一个空的 `extended_Master Secret` 扩展，表明会使用增强型主密钥计算方式。

那么增强型主密钥是如何计算的呢？计算方式如下：

```c
    Master Secret = PRF( PreMasterSecret, "extended master secret",
                          session_hash )
                          [0..47];
```

上面的计算方式和普通计算主密钥方式不同点在于：

- "extended master secret" 替代了 "master secret"
- session_hash 替代了 ClientHello.random + ServerHello.random

除了来自 Client 和 Server 的 `cipher suites`，密钥交换信息和证书(如果有的话)之外，"session_hash" 还取决于包括 "ClientHello.random" 和 "ServerHello.random" 的握手日志。因此，扩展主密钥取决于所有这些会话参数的选择。

此设计反映了密钥应该绑定到计算它们的安全上下文的建议 [SP800-108](https://tools.ietf.org/html/rfc7627#ref-SP800-108)。将密钥交换消息的散列混合到主密钥导出中的技术已经用于其他众所周知的协议，例如 Secure Shell（SSH）[RFC4251](https://tools.ietf.org/html/rfc4251)。Client 和 Server 不应接受不使用扩展主密钥的握手，特别是如果它们依赖于复合认证等功能。

> 对这块攻击感兴趣的读者可以看这篇文章 [《Triple Handshake Preconditions and Impact》](https://tools.ietf.org/html/rfc7627#section-6.1)

### 3. 计算会话密钥

会话密钥(密钥块)用于 TLS 记录层加密。记录协议需要一个算法从握手协议提供的安全参数中生成当前连接状态所需的密钥。

```c
   enum { null(0), (255) } CompressionMethod;
   enum { server, client } ConnectionEnd;
   enum { tls_prf_sha256 } PRFAlgorithm;
   enum { null, rc4, 3des, aes } BulkCipherAlgorithm;
   enum { stream, block, aead } CipherType;
   enum { null, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha384,
     hmac_sha512} MACAlgorithm;

   /* Other values may be added to the algorithms specified in
   CompressionMethod, PRFAlgorithm, BulkCipherAlgorithm, and
   MACAlgorithm. */

   struct {
       ConnectionEnd          entity;
       PRFAlgorithm           prf_algorithm;
       BulkCipherAlgorithm    bulk_cipher_algorithm;
       CipherType             cipher_type;
       uint8                  enc_key_length;
       uint8                  block_length;
       uint8                  fixed_iv_length;
       uint8                  record_iv_length;
       MACAlgorithm           mac_algorithm;
       uint8                  mac_length;
       uint8                  mac_key_length;
       CompressionMethod      compression_algorithm;
       opaque                 Master Secret[48];
       opaque                 client_random[32];
       opaque                 server_random[32];
   } SecurityParameters;
```

`Master Secret` 被扩张为一个安全字节序列，它被分割为一个 `client_write_MAC_key`，一个 `server_write_MAC_key`，一个 `client_write_key`，一个 `server_write_key`。它们中的每一个都是从字节序列中以上述顺序生成。未使用的值是空。一些 AEAD 加密可能会额外需要一个 `client_write_IV` 和一个 `server_write_IV`。生成加密密钥和 MAC 密钥时，`Master Secret` 被用作一个熵源。所以会话密钥(密钥块)的长度和个数取决于协商出来的 `cipher suites`，更准确的说是取决于加密参数 SecurityParameters，需要使用 PRF 函数扩展出足够长的密钥块，计算如下：

```c
  key_block = PRF(  SecurityParameters.Master Secret,
                    "key expansion",
                    SecurityParameters.server_random +
                    SecurityParameters.client_random );
```

注意：计算会话密钥和 `Master Secret` 时，PRF 的三个入参都不同，`PRF(secret, label, seed)`:
- 主密钥是 `( PreMasterSecret, "master secret", ClientHello.random + ServerHello.random )`
- 会话密钥是 `( SecurityParameters.Master Secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random )`，**seed 顺序有变化，Client 和 Server 随机数的组合顺序会调换**。

直到产生足够的输出。然后，`key_block` 会按照如下方式分开：

```c
client_write_MAC_key[SecurityParameters.mac_key_length]
server_write_MAC_key[SecurityParameters.mac_key_length]
client_write_key[SecurityParameters.enc_key_length]
server_write_key[SecurityParameters.enc_key_length]
client_write_IV[SecurityParameters.fixed_iv_length]
server_write_IV[SecurityParameters.fixed_iv_length]
```

`client_write_key`、`server_write_key`、`client_write_MAC_key` 和 `server_write_MAC_key` 是加密和消息验证码需要的密钥。Client 和 Server 分别拥有自己的一套密钥，使用的密钥是不同的。如果是分组加密方式，还需要初始化向量 `client_write_IV` 和 `server_write_IV`。如果是 AEAD 模式，`client_write_MAC_key` 和 `server_write_MAC_key` 可以不需要，使用 `client_write_IV` 和 `server_write_IV` 作为 nonce(随机值) 。


目前，`client_write_IV` 和 `server_write_IV` 只能由 AEAD 的隐式 nonce 技术生成。

当前定义的密码协议套件使用最多的是 `AES_256_CBC_SHA256`。它需要 2 x 32 字节密钥和 2 x 32 字节 MAC 密钥，它们从 128 字节的密钥数据中产生。

总结 TLS 1.2 密钥计算流程如下：

<p align='center'>
<img src='https://img.halfrost.com/Blog/ArticleImage/121_3_0.png'>
</p>



## 四. TLS 1.2 Finished 校验

在 TLS 1.2 握手的最后，会发送 Finished 子消息，这条消息是加密的第一条消息，Finished 消息的接收者必须要验证这条消息的内容是否正确。验证的内容是通过 PRF 算法计算出来的。

```c
      verify_data = PRF( Master Secret, 
      					finished_label, 
      					Hash(handshake_messages) )
            			[0..verify_data_length-1];
```

在计算 `verify_data` 的时候，`PRF(secret, label, seed)` 中 secret 是主密钥；label 是 `finished_label`、对于 Client 来说是 "client finished"、对于 Server 来说是 "server finished"；seed 是所有握手消息的 hash 值。对于 Client 来说，`handshake_messages` 内容包含所有发送的消息和接收的消息，但是不包括自己发送的 Finished 消息。对于 Server 来说，`handshake_messages` 内容包含从 `ClientHello` 消息开始截止到 Finished 消息之前的所有消息，也包括 Client 的 Finished 消息。

> handshake_messages 中只包含握手子消息，不包括 ChangeCipherSpec 子消息、 Alert 子消息、HelloRequest 消息。

早期 TLS 协议，`verify_data` 的长度是 12 字节，对于 TLS 1.2 协议来说，`verify_data` 的长度取决于密钥套件，如果 `cipher suites` 没有指定 `verify_data_length`，则默认长度也是 12 字节。

## 五. TLS 1.2 的无密钥交换
 
如果 CDN 厂商想支持 HTTPS，那么需要做哪些改动呢？国内的厂商的做法是：将自己 HTTPS 网站的私钥上传到 CDN 厂商提供的服务器上。某些对安全性要求非常高的客户（比如银行）想要使用第三方的 CDN，想加快自家网站的访问速度，但是出于安全考虑，不能把私钥交给 CDN 服务商。读者如果已经看懂了上面 TLS 的密钥计算的方法，完全没有必要把私钥上传到第三方 CDN 服务器上。

CloudFlare 很早就提供了 Keyless 服务，即你把网站放到它们的 CDN 上，不用提供自己证书的私钥，也能使用 TLS/SSL 加密链接。

在握手阶段，主要是协商出了 3 个随机数。这 3 个随机数产生了 TLS 记录层需要的会话密钥(密钥块)。握手完成以后，之后的加密都是对称加密。唯一需要用到非对称加密中的私钥。如果是 RSA 密钥协商，私钥的作用是解密 Client 传过来的预备主密钥。非对称加密中的公钥用来加密发给 Client 的密钥协商参数。但是 Server 的公钥可以从证书中获取。所以 CDN 唯一不能解决的问题是解密 Client 发过来的预备主密钥。如果是 ECDHE 密钥协商，私钥的作用是对 DH 参数做签名的。

解决办法比较简单：

如果是 RSA 密钥协商，在 CDN 厂商的服务器收到 Client 发来的预备主密钥的时候，把这个加密过的预备主密钥发给用户自己的 key server，让用户用自己的私钥解密预备主密钥，再发还给 CDN 厂商的服务器，这样 CDN 厂商就有解密之后的预备主密钥了，进而可以继续计算主密钥和会话密钥(密钥块)了。流程如下：   

<p align='center'>
<img src='https://img.halfrost.com/Blog/ArticleImage/121_1.png'>
</p>

如果是 DH 密钥协商算法，预备主密钥可以由 Server 和 Client 共同计算出来，但是 DH 相关的参数需要双方协商出来。Server 将 DH 相关参数发给 Client 的时候，需要用到证书的私钥。CDN 厂商会把 Client 随机数，Server 随机数和 DH 参数三者的 hash 发给用户的 key server，key server 就它们签名以后，发还给 CDN 厂商服务器。CDN 厂商将签名后的消息发给 Client。这样也就完成了密钥协商。CDN 和 Client 相互算出预备主密钥和主密钥还有会话密钥。流程如下：  

<p align='center'>
<img src='https://img.halfrost.com/Blog/ArticleImage/121_2.png'>
</p>


## 六. TLS 1.3 中的密钥

在 TLS 1.3 中，采用更安全的的 HKDF 算法而不是 PRF 算法来进行密钥的推导。TLS 1.3 对密钥进行了更细粒度的优化，TLS 1.3 会话每个阶段或者方向( c->s 以及 s->c )的加密使用不同的密钥。TLS 1.3 在 ServerHello 消息之后的数据都是加密的，在 ServerHello 消息之后的握手阶段：

- Server 给 Client 的握手消息是用 HKDF 算法导出的密钥 `server_handshake_traffic_secret` 加密
- Client 给 Server 的握手消息是用 HKDF 算法导出的密钥 `client_handshake_traffic_secret` 加密
 
这两个密钥是基于 `Handshake Secret` 密钥导出的，而 `Handshake Secret` 密钥又是基于 `PreMasterSecret` 和 `Early Secret` 密钥导出，然后通过 `Handshake Secret` 密钥导出主密钥 `Master Secret`。

<p align='center'>
<img src='https://img.halfrost.com/Blog/ArticleImage/121_4.png'>
</p>

再由主密钥 `Master Secret` 导出这 5 个密钥：   
- `client_application_traffic_secret`：用来给客户端发送给服务器应用数据加密的对称加密密钥
- `server_application_traffic_secret`：用来给服务器发送给客户端应用数据加密的对称加密密钥
- `client_handshake_traffic_secret`：用来给客户端发送给服务器握手数据加密的对称加密密钥
- `server_handshake_traffic_secret`：用来给服务器发送给客户端握手数据加密的对称加密密钥
- `resumption_Master Secret`：用来生成 PSK 的密钥。

其中前 4 个密钥会分别生成 4 套 `write_key` 和 `write_IV` 用于对称加密。如果用到 `early_data`，还需要 `client_early_traffic_secret`，它也会生成 1 套 `write_key` 和 `write_IV` 用于加密和解密 0-RTT 数据。

## 七. TLS 1.3 中的 HMAC 和伪随机函数

`Key Derivation Function(KDF)` 是密码学系统中必要的组件。它的目的是把一个 key 拓展成多个从密码学角度来上说是安全的 key。TLS 1.3 使用的是 `HMAC-based Extract-and-Expand Key Derivation Function(HKDF)`，HKDF 采用 `extract-then-expand` 模式，分为两个流程：
- `extract` 阶段：将输入的 `key material` 进行 `extracts`，得到固定长度的 key
- `expand` 阶段：基于指定的加密算法把 `extract` 阶段得到的 key `expands` 成多个伪随机的 key，输出的 key 的长度和个数

其中 `extract` 流程不是必须的，`expand` 流程可以独立的使用。

HMAC 有两个参数，第一个是 key，第二个是 data。data 可以由多几个元素组成，我们一般用 | 来表示，例如： 

```c
   HMAC(K, elem1 | elem2 | elem3)
```

### 1. Extract

```c
   HKDF-Extract(salt, IKM) -> PRK
```

- 变量:  
  - Hash 是 hash 函数;
  - HashLen 表示这个 hash 函数的输出字节数

- 输入:  
  - salt 是可选的值，如果没有指定，则使用 HashLen 个 0 代替
  - IKM 是初始密钥材料，IKM 是 Input Keying Material 的缩写

- 输出:  
  - PRK 是一个伪随机的 key (HashLen 字节大小)，PSK 是 PseudoRandom Key 的缩写
      
PRK 的计算方法如下:  

```c 
   PRK = HMAC-Hash(salt, IKM)      
```

为了兼容无法产生随机值 salt 的应用程序，`HKDF-Extract` 允许不使用 salt，但是为了保证 HKDF 算法的强度，`HKDF-Extract` 强烈建议使用 salt 。并且使用 salt 确保哈希函数的不同用途之间的独立性，支持 "源独立" extraction，并加强了支持 HKDF 设计的分析结果。

随机值 salt 与初始密钥材料 IKM 的根本在两个方面：
- 随机值 salt 是非加密的，可以重复使用。因此，随机 salt 值可用于许多应用。例如，通过将 HKDF 应用于可再生的熵池（例如，采样系统事件）而连续产生输出的伪随机数发生器（PRNG）
- 可以确定 salt 并将其用于 HKDF 的多个应用而无需保护 salt 的秘密性。在不同的应用程序域中，从 `Diffie-Hellman` 交换中导出加密密钥的密钥协商协议可以从通信方之间交换和验证的公共 nonce 中获取 salt 值，并把这种做法作为密钥协议的一部分（这是 [IKEv2](https://tools.ietf.org/html/rfc5869#ref-IKEv2) 中采用的方法）

理想情况下，salt 值是长度为 HashLen 的随机（或伪随机）字符串。然而，即使质量较低的 salt 值（较短的尺寸或有限的熵）仍然可能对输出密钥材料的安全性做出重大贡献；因此，如果应用程序可以获得这些值，鼓励应用程序设计者向 HKDF 提供 salt 值。

值得注意的是，虽然不是典型的情况，但某些应用甚至可能具有可供使用的加密 salt 值。在这种情况下，HKDF 提供更强大的安全保障。这种应用的一个例子是 IKEv1 在其“公钥加密模式”中，其中提取器的 salt 是从加密的 nonce 计算的。类似地，IKEv1 的预共享模式使用从预共享密钥导出的加密的 salt。

### 2. Expand

```c
   HKDF-Expand(PRK, info, L) -> OKM
```

- 变量:    
  - Hash 是 hash 函数
  - HashLen 表示这个 hash 函数的输出字节数。
- 输入:    
  - PRK 是至少 HashLen 字节长度的 `pseudorandom key` (通常由 `extract` 流程导出)。    
  - info 是可选的字符串，可以是""。    
  - L 是期望输出的字节数(长度 <= 255 * HashLen)。  

- 输出:  
  - OKM（Output keying material）是 HKDF 算法最终输出的扩展密钥 (L 字节)
      
OKM 的计算方法如下:  

```c 
   N = ceil(L/HashLen) // ceil 指向上取整
   T = T(1) | T(2) | T(3) | ... | T(N)
   OKM = first L octets of T

   where:
   T(0) = empty string (zero length)
   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
   ...    
```

虽然 info 值在 HKDF 的定义中是可选的，但它在应用程序中通常非常重要。其主要目标是将派生的密钥材料绑定到特定于应用程序和上下文的信息。例如，info 可以包含协议号，算法标识符，用户身份等。特别地，它可以防止针对不同的上下文导出相同的密钥材料（当在不同背景下使用相同的输入密钥材料(IKM)时）。如果需要，它还可以容纳对密钥扩展部分的附加输入（例如，应用程序可能想要将密钥材料绑定到其长度 L，从而使得 info 字段扩充至 L 长度）。info 有一个技术要求：它应该独立于输入密钥材料 IKM 的值。


对比 TLS 1.2 中的 PRF 计算方法：

```c
PRF(secret, label, seed) = P_<hash>(secret, label + seed)
P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                        HMAC_hash(secret, A(2) + seed) +
                        HMAC_hash(secret, A(3) + seed) + ...
                           
where:                            
A(0) = seed
A(i) = HMAC_hash(secret, A(i-1))
...                         
```

可以看到这两个算法的区别。


在一些应用中，输入密钥材料 IKM 可能已经作为密码强密钥的存在（例如，TLS RSA  `cipher suites` 中的 `PreMasterSecret` 是伪随机字符串，除了前两个字节）。在这种情况下，可以跳过 extract 提取部分并在 expand 扩展步骤中直接使用 IKM 作为 HMAC 的入参。另一方面，为了与一般情况兼容，应用程序仍然可以使用 extract 提取部分。特别是，如果 IKM 是随机的（或伪随机的）但长于 HMAC 密钥，则 extract 提取步骤可用于输出长度合适的 HMAC 密钥（在 HMAC 的情况下，通过 extractor 提取器的进行缩短不是严格必要的，因为 HMAC 也需要长度达到一定程度才能工作）。

但是请注意，如果 IKM 是 Diffie-Hellman 值，就像使用 Diffie-Hellman 的 TLS 一样，则不应跳过 extract 提取部分。这样做会导致使用 Diffie-Hellman 值 $g^{xy}$ 本身（它不是均匀随机或伪随机字符串）作为 HMAC 的关键 PRK。相反，HKDF 应该先将 $g^{xy}$ 进行 extract 提取步骤（优选具有 salt 值的），并把所得的 PRK 作为 HMAC expansion 部分的输入。

在所需的密钥位数 L 不大于 HashLen 的情况下，可以直接使用 PRK 作为 OKM。但是，这不是推荐的，特别是因为它会省略使用 info 作为推导过程的一部分（并且不建议在 extract 提取步骤中添加 info 作为输入 - 参见 [HKDF-paper](https://tools.ietf.org/html/rfc5869#ref-HKDF-paper)）


在 TLS 1.3 的密钥派生过程使用 HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [[RFC5869]](https://tools.ietf.org/html/rfc5869) 定义的 HKDF-Extract 和 HKDF-Expand 函数，使用方式如下:  

```c
HKDF-Expand-Label(Secret, Label, Context, Length) =
   HKDF-Expand(Secret, HkdfLabel, Length)

Where HkdfLabel is specified as:

struct {
   uint16 length = Length;
   opaque label<7..255> = "tls13 " + Label;
   opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Messages) =
   HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
```

`Transcript-Hash` 和 HKDF 使用的 Hash 函数是 `cipher suites` 指定的哈希算法。Hash.length 是其输出长度(以字节为单位)。Messages 是表示的握手消息的串联，包括握手消息类型和长度字段，但不包括记录层头。请注意，在某些情况下，零长度 context（由 "" 表示）传递给 HKDF-Expand-Label。labels 都是 ASCII 字符串，不包括尾随的 `'\0'` 字节。

由上面的函数调用关系，可以得到下面的结论：

```c
Derive-Secret(Secret, Label, Messages) = HKDF-Expand(Secret, HkdfLabel, Length)
```

**HKDF-Extract(salt, IKM) 就是 TLS 1.3 中 HKDF 的 Extract 过程；Derive-Secret(Secret, Label, Messages) 就是 TLS 1.3 中 HKDF 的 Expand 过程**。

### 3. Transcript-Hash

最后再来谈谈 `Transcript-Hash` 函数。TLS 中的许多加密计算都使用了哈希副本。这个值是通过串联每个包含的握手消息的方式进来哈希计算的，它包含握手消息头部携带的握手消息类型和长度字段，但是不包括记录层的头部。例如：

```c
   Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
```

作为此一般规则的例外，当 Server 用一条 HelloRetryRequest 消息来响应一条 ClientHello 消息时，ClientHello1 的值替换为包含 Hash(ClientHello1）的握手类型为 "message_hash" 的特殊合成握手消息。例如：

```c
   Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
      Hash(message_hash ||        /* Handshake type */
           00 00 Hash.length  ||  /* Handshake message length (bytes) */
           Hash(ClientHello1) ||  /* Hash of ClientHello1 */
           HelloRetryRequest  || ... || Mn)
```

设计这种结构的原因是允许 Server 通过在 cookie 中仅存储 ClientHello1 的哈希值来执行无状态 HelloRetryRequest，而不是要求它导出整个中间哈希状态。

具体而言，哈希副本始终取自于下列握手消息序列，从第一个 ClientHello 开始，仅包括已发送的消息：ClientHello, HelloRetryRequest, ClientHello, ServerHello, EncryptedExtensions, server CertificateRequest, server Certificate, server CertificateVerify, server Finished, EndOfEarlyData, client Certificate, client CertificateVerify, client Finished。

通常上，实现方可以下面的方法来实现哈希副本：根据协商的哈希来维持一个动态的哈希副本。请注意，随后的握手后认证不会相互包含，只是通过主握手结束的消息。

## 八. TLS 1.3 中的密钥计算

经过密钥协商得出来的密钥材料的随机性可能不够，协商的过程能被攻击者获知，需要使用一种 **密钥导出函数(KDF)** 来从**初始密钥材料（IKM）** 和 **随机值（salt）** 中获得安全性更强的密钥。

HKDF 正是 TLS 1.3 中所使用的这样一个算法，它包括 `extract` 和 `expand` 两个阶段:
- extract 过程增加 IKM 的随机性，在 TLS 1.3 中由 `HKDF-Extract(salt, IKM)` 表示
- 在 TLS 1.3 中由 `Derive-Secret(Secret, Label, Messages)` 表示

> TLS 1.2 中使用的 KDF，PRF，实际上只相当于 HKDF 的 expand 部分，并没有经过 extract，而直接假设密钥材料的随机性已经符合要求。PRF 也没有随机值 salt 作为输入，进一步提升安全性。

在 TLS 1.3 中，HKDF 两种可能的 IKM 是:
- PSK（外部建立的预共享密钥，或从先前连接的 `resumption_Master Secret` 值派生的）
- (EC)DHE 共享 secret

在 TLS 1.3 中，HKDF 两种可能的 salt 是:
- 全为 "0" 的字符串
- 握手阶段报文信息的哈希值

TLS 1.3 完整的密钥导出流程图如下：
```c
             0
             |
             v
   PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(Early Secret, "ext binder" | "res binder", "")
             |                     = binder_key
             |
             +-----> Derive-Secret(Early Secret, "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             +-----> Derive-Secret(Early Secret, "e exp master", ClientHello)
             |                     = early_exporter_Master Secret
             v
       Derive-Secret(Early Secret, "derived", "")
             |
             v
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(Handshake Secret, "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(Handshake Secret, "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(Master Secret, "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(Master Secret, "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
             +-----> Derive-Secret(Master Secret, "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_Master Secret
             |
             +-----> Derive-Secret(Master Secret, "res master",
                                   ClientHello...client Finished)
                                   = resumption_Master Secret
```

对图的几点说明：
1. `HKDF-Extract` 顶部的输入为 `Salt` 参数；左侧的输入为 `IKM` 参数；底部为输出；右侧为输出的密钥类型
2. `Derive-Secret` 中的 `ClientHello...server Finished` 表示这些报文中的一些信息
3. "0" 表示将 Hash.length 字节的、由 "0" 组成的字符串
4. 如果给定的 secret 不可用，则使用由 "0" 组成的、Hash.length 字节的字符串。请注意，这并不意味着要跳过轮次，比如若 PSK 未被使用，`Early Secret` 将是 `HKDF-Extract(0,0)`。
5. 对于 `binder_key` 的计算，label 是外部 PSK（在 TLS 之外提供的那些）的 "ext binder" 和用于恢复 PSK 的 "res binder"（提供为先前握手的恢复主密钥的那些）。不同的 labels 阻止了一种 PSK 替代另一种 PSK。


存在多个潜在的 `Early Secret` 值，具体取决于 Server 最终选择的 PSK。Client 需要为每个潜在的 PSK 都导出一个 `Early Secret`；如果没有选择 PSK，则在导出 `Early Secret` 时、对应的 IKM 为 "0"

注意：**一旦计算出了从给定 secret 派生出的所有值，就应该删除该 secret**。

TLS 1.3 中涉及到了 3 个 Secret 计算方法如下：

```c
Early Secret = HKDF-Extract(salt, IKM) = HKDF-Extract(0, PSK)

Handshake Secret = HKDF-Extract(salt, IKM) = 
      HKDF-Extract( Derive-Secret(Early Secret, "derived", ""), (EC)DHE )

Master Secret = HKDF-Extract(salt, IKM) = 
      HKDF-Extract( Derive-Secret(Handshake Secret, "derived", ""), 0 )
```

TLS 1.3 中涉及到了 8 个密钥计算方法如下：

```c
client_early_traffic_secret = 
   Derive-Secret(Early Secret, "c e traffic", ClientHello)

early_exporter_Master Secret = 
   Derive-Secret(Early Secret, "e exp master", ClientHello)
       
client_handshake_traffic_secret = 
   Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello)

server_handshake_traffic_secret = 
   Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello)
    
client_application_traffic_secret_0 = 
   Derive-Secret(Master Secret, "c ap traffic", ClientHello...server Finished)

server_application_traffic_secret_0 = 
   Derive-Secret(Master Secret, "s ap traffic", ClientHello...server Finished)

exporter_Master Secret = 
   Derive-Secret(Master Secret, "exp master", ClientHello...server Finished)

resumption_Master Secret = 
   Derive-Secret(Master Secret, "res master", ClientHello...client Finished)
```

`EXPORTER_SECRET` 是导出密钥，用于用户自定义的其他用途。

上面得到的 8 个密钥除去 2 个用户自定义需要的导出密钥，和会话恢复的 `resumption_Master Secret`，剩下的 5 个密钥使用加密传输数据，但是这 5 个密钥仍然只是“中间变量”，最后加密传输数据的密码还需要一次 HKDF-Expand 过程生成：

```c
  [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
  [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
```

[sender] 表示发送方，也就是 Client 或者 Server。每种密钥所用的 Secret 如下表所示：

```c
   +-------------------+---------------------------------------+
   | Record Type       | Secret                                |
   +-------------------+---------------------------------------+
   | 0-RTT Application | client_early_traffic_secret           |
   |                   |                                       |
   | Handshake         | [sender]_handshake_traffic_secret     |
   |                   |                                       |
   | Application Data  | [sender]_application_traffic_secret_N |
   +-------------------+---------------------------------------+
```

每当底层 Secret 更改时(例如，从握手更改为应用数据密钥或密钥更新时)，将重新计算所有流量密钥材料。`resumption_Master Secret` 密钥用于生成会话恢复使用的 PSK 的，计算方法如下：

```c
PskIdentity.identity = ticket = 
   HKDF-Expand-Label(resumption_Master Secret, "resumption", ticket_nonce, Hash.length)
```

Server 在 NewSessionTicket 中把 ticket 发送到 Client，Client 利用 ticket 生成 PskIdentity。再计算 PskBinderEntry：

```c
PskBinderEntry = HMAC(binder_key, Transcript-Hash(Truncate(ClientHello1))) = 
   HMAC( Derive-Secret( HKDF-Extract(0, PSK), "ext binder" | "res binder", "" ), 
         Transcript-Hash(Truncate(ClientHello1)) )  

binder_key = 
   Derive-Secret( HKDF-Extract(0, PSK), "ext binder" | "res binder", "")                   
```

Client 将 PskIdentity 和 PskBinderEntry 结合成 PSK，在需要会话恢复的时候把 PSK 作为 ClientHello 的扩展发给 Server。PSK 作为 Early Secret 的输入密钥材料 IKM。

```c
Early Secret = HKDF-Extract(salt, IKM) = HKDF-Extract(0, PSK)

client_early_traffic_secret = 
   Derive-Secret( Early Secret, "c e traffic", ClientHello )
```

由 `client_early_traffic_secret` 生成的 `write_key` 和 `write_iv` 最终用于 0-RTT 的加密和解密。

TLS 1.3 0-RTT 密钥计算流程如下：

<p align='center'>
<img src='https://img.halfrost.com/Blog/ArticleImage/121_5.png'>
</p>


## 九. TLS 1.3 Finished 校验

TLS 1.3 中的 Finished 并不算是整个握手中的第一条加密消息，作用和 TLS 1.2 是相同的，它对提供握手和计算密钥的身份验证起了至关重要的作用。

在 TLS 1.3 中 Authentication 消息的计算统一采用以下的输入方式：

- 要使用证书和签名密钥
- 握手上下文由哈希副本中的一段消息集组成
- Base key 用于计算 MAC 密钥

Finished 子消息根据 `Transcript-Hash( Handshake Context, Certificate, CertificateVerify )` 的值得出的 MAC 。使用从 Base key 派生出来的 MAC key 计算的 MAC 值。

对于每个场景，下表定义了握手上下文和 MAC Base Key    

```c
   +-----------+-------------------------+-----------------------------+
   | Mode      | Handshake Context       | Base Key                    |
   +-----------+-------------------------+-----------------------------+
   | Server    | ClientHello ... later   | server_handshake_traffic_   |
   |           | of EncryptedExtensions/ | secret                      |
   |           | CertificateRequest      |                             |
   |           |                         |                             |
   | Client    | ClientHello ... later   | client_handshake_traffic_   |
   |           | of server               | secret                      |
   |           | Finished/EndOfEarlyData |                             |
   |           |                         |                             |
   | Post-     | ClientHello ... client  | client_application_traffic_ |
   | Handshake | Finished +              | secret_N                    |
   |           | CertificateRequest      |                             |
   +-----------+-------------------------+-----------------------------+
```

用于计算 Finished 消息的密钥是使用 HKDF，Base Key 是 `server_handshake_traffic_secret` 和 `client_handshake_traffic_secret`。特别的:


```c
finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
```


这条消息的数据结构是:

```c
      struct {
          opaque verify_data[Hash.length];
      } Finished;
```

`verify_data` 按照如下方法计算:

```c
verify_data = HMAC( finished_key, Transcript-Hash(Handshake Context,
                   Certificate*, CertificateVerify*) )

      * Only included if present.
```


HMAC [[RFC2104]](https://tools.ietf.org/html/rfc2104) 使用哈希算法进行握手。如上所述，HMAC 输入通常是通过动态的哈希实现的，即，此时仅是握手的哈希。

在以前版本的 TLS 中，`verify_data` 的长度总是 12 个八位字节。在 TLS 1.3 中，它是用来表示握手的哈希的 HMAC 输出的大小。

**注意：警报和任何其他非握手记录类型不是握手消息，并且不包含在哈希计算中**。

Finished 消息之后的任何记录 `Post-Handshake` 都必须在适当的 `client_application_traffic_secret_N` 下加密。特别是，这包括 Server 为了响应 Client 的 Certificate 消息和 CertificateVerify 消息而发送的任何 alert。


## 十. TLS 1.3 KeyUpdate

看到这里读者可能会问，为什么在文章最后还会再讨论 TLS 1.3 的 KeyUpdate 消息？因为这条消息会触发 TLS 1.3 重新计算密钥。所以需要细究一下这条消息。

[研究表明](http://link.zhihu.com/?target=http%3A//www.isg.rhul.ac.uk/~kp/TLS-AEbounds.pdf) 如果使用同一个密钥加密大量的数据，攻击者有几率可以通过记录所有密文并找出特征，逆推出对称加密密钥。因此需要引进一个密钥同步更新的机制，该机制同时也使用 HKDF 算法，在旧密钥的基础上衍生出新一轮的密钥。

当加密的报文达到一定长度后，双方也需要发送 KeyUpdate 报文重新计算加密密钥。

KeyUpdate 握手消息用于表示发送方正在更新其自己的发送加密密钥。任何对等方在发送 Finished 消息后都可以发送此消息。在接收 Finished 消息之前接收 KeyUpdate 消息的，实现方必须使用 "unexpected_message" alert 消息终止连接。发送 KeyUpdate 消息后，发送方应使用新一代的密钥发送其所有流量。收到 KeyUpdate 后，接收方必须更新其密钥。


```c
   enum {
         update_not_requested(0), update_requested(1), (255)
   } KeyUpdateRequest;

   struct {
         KeyUpdateRequest request_update;
   } KeyUpdate;
```

- request_update:  
	这个字段表示 KeyUpdate 的收件人是否应使用自己的 KeyUpdate 进行响应。 如果实现接收到任何其他的值，则必须使用 "illegal_parameter" alert 消息终止连接。
	
如果 `request_update` 字段设置为 "update_requested"，则接收方必须在发送其下一个应用数据记录之前发送自己的 KeyUpdate，其中 `request_update` 设置为 "update_not_requested"。此机制允许任何一方强制更新整个连接，但会导致一个实现方接收多个 KeyUpdates，并且它还是静默的响应单个更新。请注意，实现方可能在发送 KeyUpdate (把 `request_update` 设置为 "update_requested") 与接收对等方的 KeyUpdate 之间接收任意数量的消息，因为这些消息可能早就已经在传输中了。但是，由于发送和接收密钥是从独立的流量密钥中导出的，因此保留接收流量密钥并不会影响到发送方更改密钥之前发送的数据的前向保密性。


如果实现方独立地发送它们自己的 KeyUpdates，其 `request_update` 设置为 "update_requested" 并且它们的消息都是传输中，结果是双方都会响应，双方都会更新密钥。

发送方和接收方都必须使用旧密钥加密其 KeyUpdate 消息。另外，在接受使用新密钥加密的任何消息之前，双方必须强制接收带有旧密钥的 KeyUpdate。如果不这样做，可能会引起消息截断攻击。


更新的密钥 `client_server_application_traffic_secret_N + 1` 从 `client_server_application_traffic_secret_N` 生成，然后按上一节所述方法重新导出流量密钥。生成方法如下：

```c
application_traffic_secret_N+1 = 
   HKDF-Expand-Label( application_traffic_secret_N,
                  "traffic upd", "", Hash.length )
```

一旦计算了 `client_server_application_traffic_secret_N + 1` 及其关联的流量密钥，实现方应该删除 `client_server_application_traffic_secret_N` 及其关联的流量密钥。

## 十一. TLS 1.3 中的密钥导出

在 TLS 1.3 中，有 2 个导出密钥 exporter：

```c
early_exporter_Master Secret = 
Derive-Secret( Early Secret, "e exp master", ClientHello )

exporter_Master Secret = 
Derive-Secret( Master Secret, "exp master", ClientHello...server Finished )
```

[RFC5705](https://tools.ietf.org/html/rfc5705) 根据 TLS 伪随机函数(PRF)定义 TLS 的密钥材料 exporter。TLS 1.3 用 HKDF 取代 PRF，因此需要新的结构。exporter 的接口保持不变。

exporter 的值计算方法如下:

```c
TLS-Exporter(label, context_value, key_length) = 
   HKDF-Expand-Label( Derive-Secret(Secret, label, ""),
      "exporter", Hash(context_value), key_length )
```

Secret 可以是 `early_exporter_Master Secret` 或 `exporter_Master Secret`。除非应用程序明确指定，否则实现方必须使用 `exporter_Master Secret`。`early_exporter_Master Secret` 被定义用来在 0-RTT 数据需要 exporter 的设置这种情况中使用。建议为 early exporter 提供单独的接口；这可以避免 exporter 用户在需要常规 exporter 时意外使用 early exporter，反之亦然。

如果未提供上下文，则 `context_value` 为零长度。因此，不提供上下文计算与提供空上下文得到的结果都是相同的。这是对以前版本的 TLS 的更改，以前的 TLS 版本中，空的上下文产生的输出与不提供的上下文的结果不同。截至 TLS 1.3，无论是否使用上下文，都不会使用已分配的 exporter 标签。未来的规范绝不能定义允许空上下文和没有相同标签的上下文的 exporter 的使用。exporter 的新用法应该是在所有 exporter 计算中提供上下文，尽管值可能为空。

exporter 标签格式的要求在 [[RFC5705] 第4节](https://tools.ietf.org/html/rfc5705#section-4) 中定义。


------------------------------------------------------

[RFC 5246](https://tools.ietf.org/html/rfc5246)  
[RFC 8466](https://tools.ietf.org/html/rfc8446)    
Keyless SSL: The Nitty Gritty Technical Details：https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details
Cryptographic Extraction and Key Derivation:The HKDF Scheme：https://eprint.iacr.org/2010/264.pdf


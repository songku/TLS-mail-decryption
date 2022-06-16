from Cryptodome.Cipher import AES
from Cryptodome.Hash import *

MAX_KEY_MATERIAL_LENGTH = 128  #


class MasterDecrypter:

    def __init__(self, cipher_size, cipher_mode, cipher_hash, master_secret, server_random, client_random):
        self.cipher_size = cipher_size # AES 256 means cipher_size is 256
        self.cipher_mode = cipher_mode # AES.MODE_GCM
        self.cipher_hash = cipher_hash # Hash.SHA384
        self.master_secret = master_secret  # 48bit master secret type:bytes
        self.server_random = server_random  # 32bit server random type:bytes
        self.client_random = client_random  # 32bit client random type:bytes
        self.key_size = int(cipher_size / 8)
        self.IV_size = 4  # TODO: This changes based on cipher mode (e.g., GCM, CBC, etc.)
        self.nonce_size = 8  # TODO: Only relevant in GCM mode, but is this constant for all GCM configurations?
        self.mac_size = 16  # TODO: is this guaranteed to always be the same across all cipher suites?

    class _OrderedKeyMaterial:
        def __init__(self):
            #  SSL记录层用security parameters生成client/server write mac secret and client/server write secret
            self.client_write_MAC_key = b''
            self.server_write_MAC_key = b''
            self.client_write_key = b''
            self.server_write_key = b''
            self.client_write_IV = b''  # 从key block(密钥材料)中提取出来，加密使用的初始向量
            self.server_write_IV = b''

    def decrypt_client(self, ciphertext):
        key_material = self._PRF(self.master_secret, b'key expansion',
                                 self.server_random + self.client_random)  # 生成密钥材料
        ordered_keys = self._get_keys(key_material)
        nonce = ciphertext[:self.nonce_size]  # nonce：随机数
        mac = ciphertext[-1 * self.mac_size:]
        ciphertext = ciphertext[self.nonce_size:-1 * self.mac_size]

        aes_decrypter = AES.new(ordered_keys.client_write_key, self.cipher_mode, ordered_keys.client_write_IV + nonce)  # 使用aes_decrypter解密
        return aes_decrypter.decrypt(ciphertext)

    def decrypt_server(self, ciphertext):
        key_material = self._PRF(self.master_secret, b'key expansion',
                                 self.server_random + self.client_random)  # 生成密钥材料
        ordered_keys = self._get_keys(key_material)  # 从密钥材料中提取各个密钥
        nonce = ciphertext[:self.nonce_size]  # nonce：随机数
        mac = ciphertext[-1 * self.mac_size]
        ciphertext = ciphertext[self.nonce_size:-1 * self.mac_size]

        aes_decrypter = AES.new(ordered_keys.server_write_key, self.cipher_mode, ordered_keys.server_write_IV + nonce)  # 使用aes_decrypter解密
        return aes_decrypter.decrypt(ciphertext)

    def _HMAC_hash(self, secret, seed):
        """
        keyed MAC；是一些受机密保护的数据的安全摘要。
        在不知道 MAC秘密的情况下伪造 MAC 是不可行的。我们用于此操作的构造称为 HMAC
        TLS在握手时使用两种不同的算法，MD5 和 SHA-1，分别表示为 HMAC_MD5(secret, data) 和 HMAC_SHA(secret,data)
        :param secret:
        :param seed:
        :return:
        """
        return HMAC.new(secret, seed, self.cipher_hash).digest()

    def _P_hash(self, secret, seed):
        """
        出于密钥生成或验证的目的，需要构建将秘密扩展为数据块。
        这个伪随机函数 (PRF) 将秘密、种子和识别标签作为输入，并产生任意长度的输出。
        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                              HMAC_hash(secret, A(2) + seed) +
                              HMAC_hash(secret, A(3) + seed) + ... 其中 + 表示串联。
        P_hash 可以被迭代多次，以产生所需数量的数据。例如，如果 P_SHA-1 用于创建
        64 字节的数据，必须迭代 4 次（通过A(4)），创建 80 字节的输出数据；最后一
        次迭代的最后 16 个字节将被丢弃，留下 64 个字节的输出数据。
        :param secret:
        :param seed:
        :return:
        """
        res = b''
        A_i = [seed]  # A[0]=seed

        while len(res) < MAX_KEY_MATERIAL_LENGTH:
            A_i.append(self._HMAC_hash(secret, A_i[-1]))  # A(i) = HMAC_hash(secret, A(i-1))

            # P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
            res += self._HMAC_hash(secret, A_i[-1] + seed)

        return res

    def _PRF(self, secret, label, seed):  # 对Phash函数的包装
        return self._P_hash(secret, label + seed)

    def _get_keys(self, key_material):  # GCM mode 生成密钥材料
        ret = self._OrderedKeyMaterial()  # 初始化一个OrderedKeyMaterial变量
        ret.client_write_MAC_key = b''
        ret.server_write_MAC_key = b''
        # 传来的key_material144字节，client_write_key取32字节，server_write_key取32字节,write_IV都各取4字节
        ret.client_write_key = key_material[0:self.key_size]  # 第一个key_size
        ret.server_write_key = key_material[self.key_size: 2 * self.key_size]  # 第二个key_size
        ret.client_write_IV = key_material[2 * self.key_size: 2 * self.key_size + self.IV_size]  # one IV_size
        ret.server_write_IV = key_material[2 * self.key_size + self.IV_size:2 * self.key_size + 2 * self.IV_size]  # two

        return ret

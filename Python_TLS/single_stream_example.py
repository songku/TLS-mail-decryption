import pyshark
import sys
import os
from Cryptodome import Hash
from Cryptodome.Hash import *
# 如上两个在一起才能找到SHA384,然而又没有调用到，显示为灰色，就很魔性
from Cryptodome.Cipher import AES

from Cryptodome.Hash import HMAC

MAX_KEY_MATERIAL_LENGTH = 128


class MasterDecrypter:

    def __init__(self, ciphersuite=None, cipher_size=None, cipher_mode=None, cipher_hash=None, master_secret=None,
                 server_random=None,
                 client_random=None, pcap_path=None, ssllog_path=None
                 ):
        self.ciphersuite = ciphersuite
        self.cipher_size = cipher_size  # AES 256 means cipher_size is 256
        self.cipher_mode = cipher_mode  # AES.MODE_GCM
        self.cipher_hash = cipher_hash  # Hash.SHA384
        self.master_secret = master_secret  # 48bit master secret type:bytes
        self.server_random = server_random  # 32bit server random type:bytes
        self.client_random = client_random  # 32bit client random type:bytes
        self.CLIENT_RANDOM = None  # client random所在的哪一行的字段
        self.client_addr = None  # 检索tls握手过程中再填充
        self.server_addr = None  # 检索tls握手过程中再填充
        self.pcap_path = pcap_path  # 要解析的pcap数据包路径
        self.ssllog_path = ssllog_path  # 解析pcap数据包所需要的ssllog文件的路径
        self.IV_size = 4  # TODO: This changes based on cipher mode (e.g., GCM, CBC, etc.)
        self.nonce_size = 8  # TODO: Only relevant in GCM mode, but is this constant for all GCM configurations?
        self.mac_size = 16  # TODO: is this guaranteed to always be the same across all cipher suites?
        self.application_datas_s2c = []
        self.application_datas_c2s = []
        if self.cipher_size:
            self.key_size = int(cipher_size / 8)
        else:
            self.key_size = None

    class _OrderedKeyMaterial:
        def __init__(self):
            #  SSL记录层用security parameters生成client/server write mac secret and client/server write secret
            self.client_write_MAC_key = b''
            self.server_write_MAC_key = b''
            self.client_write_key = b''
            self.server_write_key = b''
            self.client_write_IV = b''  # 从key block(密钥材料)中提取出来，加密使用的初始向量
            self.server_write_IV = b''

    def _HMAC_hash(self, secret, seed):
        """
        keyed MAC；是一些受机密保护的数据的安全摘要。
        在不知道 MAC秘密的情况下伪造 MAC 是不可行的。我们用于此操作的构造称为 HMAC
        TLS在握手时使用两种不同的算法，MD5 和 SHA-1，分别表示为 HMAC_MD5(secret, data) 和 HMAC_SHA(secret,data)
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

    def cs_name_to_values(self):
        if self.ciphersuite:
            # 举例:TLS_SM4_GCM_SM3 SM3/SM4是中国算法，不推荐使用
            # 举例:TLS_AES_128_GCM_SHA256 (0x1301)
            # 举例:TLS_DHE_RSA_WITH_SEED_CBC_SHA (0x009a)
            # 举例:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
            # 举例:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
            # 参考: https://ciphersuite.info/cs/
            enc_list = ['AES', 'ARC2', 'ARC4', 'Blowfish', 'CAST', 'ChaCha20', 'ChaCha20_Poly1305', 'DES', 'DES3',
                        'PKCS1_OAEP', 'PKCS1_V1_5', 'Salsa20']
            modes_list = ['CBC', 'CCM', 'CFB', 'CTR', 'EAX', 'ECB', 'GCM', 'OCB', 'OFB', 'OPENPGP', 'SIV']
            hash_list = ['BLAKE2b', 'BLAKE2s', 'CMAC', 'cSHAKE128', 'cSHAKE256', 'HMAC', 'KangarooTwelve', 'keccak',
                         'KMAC128',
                         'KMAC256', 'MD2', 'MD4', 'MD5', 'Poly1305', 'RIPEMD', 'RIPEMD160', 'SHA', 'SHA1', 'SHA3_224',
                         'SHA3_256',
                         'SHA3_384', 'SHA3_512', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHAKE128', 'SHAKE256',
                         'TupleHash128', 'TupleHash256']
            if "WITH_" in self.ciphersuite:
                symmetric_part = self.ciphersuite.split('WITH_')[1]  # 以加密套件中的WITH_做区分，取第二部分
            else:
                symmetric_part = self.ciphersuite.split("TLS_")[1]
            parts = symmetric_part.split('_')
            if len(parts) == 4:
                hash_algo = parts[3].split(" ")[0]  # 实际上这个hash算法表示符中间有空格(如'SHA256 (0xc02f)'),hash_raw仍带" "
                if parts[0] in enc_list and parts[2] in modes_list and hash_algo in hash_list:
                    enc_algo, size_raw, mode_raw, hash_raw = parts
                else:
                    print('Unsupported hash_algo: {}'.format(hash_algo))
                    return False
            elif len(parts) == 3 and parts[0] in enc_list:
                if parts[2] in modes_list:  # 无hash
                    enc_algo, size_raw, mode_raw = parts
                    hash_raw=None
                elif parts[2].split(" ")[0] in hash_list:
                    if parts[1] in modes_list:  # parts[1]是mode
                        enc_algo, mode_raw, hash_raw = parts
                        size_raw = '0'
                    else:  # parts[1]是size
                        enc_algo, size_raw, hash_raw = parts
                        mode_raw = None
                else:
                    print('Unsupported enc_algo or enc_mode or hash_algo in the cipher suite: {}'.format(
                        self.ciphersuite))
                    return False
            else:
                print('Unsupported Cipher Suite: {}'.format(self.ciphersuite))
                return False

            # enc_algo 加密算法(eg:AES)
            # size_raw 大小(eg:256)
            # mode_raw 加密算法的具体工作模式(eg:GCM)
            # hash_raw 签名算法(eg:SHA256)
            try:
                size = int(size_raw)
            except:
                print('Unsupported size: {}'.format(size_raw))  # 长度不符合规矩报错
                return False
            try:
                mode = getattr(AES, 'MODE_{}'.format(mode_raw))  # 获得AES的MODE_GCM属性，因为只有设计了AES加密格式，所以需要try except
            except Exception as e:
                print('Unsupported Encrypt_Algorithm: {}:{}'.format(enc_algo, mode_raw))  # 加密算法不支持报错
                return False
            hash_str = hash_raw.split()[0]
            try:
                if hash_str == 'SHA384':
                    hash_algo = Hash.SHA384
                elif hash_str == 'SHA256':
                    hash_algo = Hash.SHA256
                elif hash_str == 'SHA1':
                    hash_algo = Hash.SHA1
                elif hash_str == 'SHA224':
                    hash_algo = Hash.SHA224
                elif hash_str == 'SHA512':
                    hash_algo = Hash.SHA512
                else:
                    raise ValueError('Unsupported hash: {}'.format(hash_str))  # hash算法不支持报错
            except ValueError as e:
                print(e)
                return False
            self.cipher_size = size
            self.key_size = int(self.cipher_size / 8)
            self.cipher_mode = mode
            self.cipher_hash = hash_algo
            return True
        else:
            return False

    def append_datas(self, packet):
        if hasattr(packet, 'ssl'):
            ssl_layer = packet.ssl
        elif hasattr(packet, 'tls'):
            ssl_layer = packet.tls
        key_material = self._PRF(self.master_secret, b'key expansion',
                                 self.server_random + self.client_random)  # 生成密钥材料
        key_block = self._get_keys(key_material)
        nonce = ssl_layer.app_data.binary_value[:self.nonce_size]  # nonce：随机数
        mac = ssl_layer.app_data.binary_value[-1 * self.mac_size:]
        ciphertext = ssl_layer.app_data.binary_value[self.nonce_size:-1 * self.mac_size]  # HTTP加密部分
        if packet.ip.src_host == self.server_addr:  # 来自server的tls加密data，要用server端的write key和IV解密
            aes_decrypter = AES.new(key_block.server_write_key, self.cipher_mode,
                                    key_block.server_write_IV + nonce)  # 使用aes_decrypter解密
            self.application_datas_s2c.append(aes_decrypter.decrypt(ciphertext))
        elif packet.ip.src_host == self.client_addr:  # 来自client端的tls加密data，要用server端的write key和IV解密
            aes_decrypter = AES.new(key_block.client_write_key, self.cipher_mode,
                                    key_block.client_write_IV + nonce)  # 使用aes_decrypter解密
            self.application_datas_c2s.append(aes_decrypter.decrypt(ciphertext))
        else:
            raise ValueError("TLS data not target")

    def read_decrypt_pcap(self):
        """
        遍历解析pcap文件，将解析出的HTTP结果保存至application_datas列表中
        :return:
        """
        # 函数中的局部变量应该小写
        CONTENT_APPLICATION_DATA = b'\x17'  # 十进制下的23
        CONTENT_HANDSHAKE = b'\x16'  # 十进制下的22
        HANDSHAKE_CLIENT_HELLO = b'\x01'
        HANDSHAKE_SERVER_HELLO = b'\x02'
        packets = pyshark.FileCapture(self.pcap_path)  # 读取pcap文件
        for pack_id, packet in enumerate(packets):
            if hasattr(packet, 'ssl'):
                ssl_layer = packet.ssl
            elif hasattr(packet, 'tls'):
                ssl_layer = packet.tls
            else:
                print('Discarding non-ssl packet: #{}'.format(pack_id))
                continue
            if hasattr(ssl_layer, 'record_content_type'):
                # 如果ssl记录层有record_content_type属性
                # 可能的取值包括change_cipher_spec(20), alert(21), handshake(22),application_data(23)
                if hasattr(ssl_layer, 'handshake_type'):
                    # 如果ssl记录层有handshake_type属性，
                    # 可能的取值包括hello_request(0)、client_hello(1)、server_hello(2)、certificate(11)、
                    # server_key_exchange (12)、certificate_request(13)、server_hello_done(14)、
                    # certificate_verify(15)、client_key_exchange(16)、finished(20 )
                    if ssl_layer.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            ssl_layer.handshake_type.binary_value == HANDSHAKE_CLIENT_HELLO:
                        # 是handshake阶段的client_hello消息
                        self.client_random = ssl_layer.handshake_random.binary_value
                        self.client_addr = packet.ip.src_host
                        print('Reading client hello from {} packet #{}'.format(self.client_addr, pack_id))
                        print('Got Client Random: {}'.format(self.client_random))

                    # 是handshake阶段的server_hello消息
                    elif ssl_layer.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            ssl_layer.handshake_type.binary_value == HANDSHAKE_SERVER_HELLO:
                        self.server_random = ssl_layer.handshake_random.binary_value
                        self.ciphersuite = ssl_layer.handshake_ciphersuite.showname
                        if self.cs_name_to_values():  # 获得cipher suite后，就将其写入self对象中
                            print("Set Cipher Suite OK!")
                        else:
                            print("Set Cipher Suite Error!Cipher suite not ")
                        self.server_addr = packet.ip.src_host
                        print('Reading server hello from {} packet #{}'.format(self.server_addr, pack_id))
                        print('Got Server Random: {}'.format(self.server_random))
                        print('Got {}'.format(self.ciphersuite))

                # 如果不是handshake消息而是data,则根据是client还是server进行解密
                elif ssl_layer.record_content_type.binary_value == CONTENT_APPLICATION_DATA:
                    print('Reading {} bytes encrypted application data from packet: #{}'.format(
                        len(ssl_layer.app_data.binary_value),
                        pack_id
                    ))
                    if self.master_secret:
                        self.append_datas(packet)
                    else:
                        if self.search_masterkey(self.client_random):  # 没有master key，则应先根据client random查找得到master key
                            print("Find master key and set ok!")
                            self.append_datas(packet)
                        else:
                            print("No Find master key,couldn't decrypt")

    def search_masterkey(self, client_random: bytes):
        """
        根据client_random，从keylog中查找master_secret并返回
        """
        found = False
        with open(self.ssllog_path, "r") as keyfile:
            key_lists = keyfile.readlines()
        for key in key_lists:
            key = key.replace("\n", "")
            if "#" in key:  # 如果keylog中的这条记录包含#，则忽略这条记录
                pass
            else:
                key_parts = key.split(" ")
                key_random_bytes = bytes.fromhex(key_parts[1])
                if client_random == key_random_bytes:
                    found = True
                    self.CLIENT_RANDOM = key
                    break
        keyfile.close()
        if found:
            parts = self.CLIENT_RANDOM.split(" ")
            master_key_str = parts[-1]
            master_key = bytes.fromhex(master_key_str)
            self.master_secret = master_key  # 更新master_secret
            return True
        else:
            return False


if __name__ == "__main__":
    print("usage:python3 single_stream_example.py <pcap file path> <ssl log file path>")
    argv_len = len(sys.argv)
    if argv_len == 3:
        pcap_file_path = sys.argv[1]
        ssllog_file_path = sys.argv[2]
    else:
        print("as you didn't point out the file name it's name will be set as default")
        pcap_file_path = "singlestream_example/singlestream.openmrs.org.pcap"
        ssllog_file_path = "singlestream_example/single_keylog.txt"
    example_decrypter = MasterDecrypter(pcap_path=pcap_file_path, ssllog_path=ssllog_file_path)
    example_decrypter.read_decrypt_pcap()  # 顺序读取所有流数据并解密
    print('-' * 2 + "Client Records" + '-' * 2)
    for c2s_record in example_decrypter.application_datas_c2s:
        try:
            record_decoded = c2s_record.decode()  # 转为str
            print("decrypeted ok!and the plain text is:")
            print(record_decoded)
        except Exception as e:
            print(e)
            c2s_record_head = c2s_record[:100]
            print(c2s_record_head)
        print('-' * 20)
    print('-' * 2 + "Server Records" + '-' * 2)
    for s2c_record in example_decrypter.application_datas_s2c:
        try:
            record_decoded_head = s2c_record[
                                  :100].decode()  # server回送给客户端的有的数据包前面部分还可以解码出正常的HTTP头部数据，但后面数据部分就不一定了，所以提取前100字节解码
            print("decrypeted ok!and the plain text head 100 bytes are:")
            print(record_decoded_head)
        except Exception as e:
            print(e)
        print('-' * 20)

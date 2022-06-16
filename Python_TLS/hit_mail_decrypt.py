import pyshark
import socket  # 用以获取目标邮箱IP
import sys
import re
from Cryptodome import Hash
from Cryptodome.Hash import *
# 如上两个在一起才能找到SHA384,然而又没有调用到，显示为灰色，就很魔性
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC

MAX_KEY_MATERIAL_LENGTH = 128


class TcpStreamList:
    def __init__(self, pcap_path=None):
        self.pcap_path = pcap_path  # 要读取的pcap文件的路径
        self.tcpstreams = []  # 列表中每个元素都是一个TcpStream的packets数据包

    def read_pcap(self):
        """
        读取pcap文件，并将该文件包含的所有tls数据划分到不同的tcp stream当中
        """
        TcpTuple4List = []  # 记录目前pcap文件中所有的tls流的四元组信息
        packets = pyshark.FileCapture(self.pcap_path)  # 读取pcap文件
        for packet_id, packet in enumerate(packets):  # 我们都假设是客户端先和服务器交互，所以最初的Tuple4里面是client的ip作为src
            if not hasattr(packet, 'tls'):  # 只提取tls流数据
                # print('No tls/ssl layer in packet #{}'.format(packet_id))
                continue
            src_host = packet.ip.src_host
            src_port = packet.tcp.srcport
            dst_host = packet.ip.dst_host
            dst_port = packet.tcp.dstport
            packet_Quintuple = [src_host, src_port, dst_host, dst_port]  # 这个包的四元组
            packet_Quintuple_reverse = [dst_host, dst_port, src_host, src_port]  # 这个包的逆四元组
            # 如果是第一次遇到该packet，则其大概率来自client，此时应初始化一个TcpStream对象，并添加该packet到该对象，并将该TcpSteam对象添加到TcpSteamList对象的list中
            if packet_Quintuple not in TcpTuple4List and packet_Quintuple_reverse not in TcpTuple4List:
                newTcpStream = self.new_TcpStream(src_host, src_port, dst_host, dst_port)
                newTcpStream.append_packet(packet)
                TcpTuple4List.append(packet_Quintuple)  # 将新的四元组添加到对象中
                self.tcpstreams.append(newTcpStream)
            elif packet_Quintuple in TcpTuple4List:  # 来自客户端的数据
                index = TcpTuple4List.index(packet_Quintuple)  # 返回该流所在的索引
                targetTcpSteam = self.tcpstreams[index]
                targetTcpSteam.append_packet(packet)
            elif packet_Quintuple_reverse in TcpTuple4List:  # 来自服务器的数据
                index = TcpTuple4List.index(packet_Quintuple_reverse)
                targetTcpSteam = self.tcpstreams[index]
                targetTcpSteam.append_packet(packet)
            else:
                pass

    def new_TcpStream(self, src_ip, src_port, dst_ip, dst_port):
        """
        初始化一个tcp流，以连接四元组标识
        需要注意的是这个四元组是以tcp的一端为基础的(tls的client端)，但tcp连接的另一端也属于这个四元组(tls的server端)
        """
        newTcpSteam = self.TcpStream()
        newTcpSteam.src_ip = src_ip
        newTcpSteam.src_port = src_port
        newTcpSteam.dst_ip = dst_ip
        newTcpSteam.dst_port = dst_port
        newTcpSteam.packets = []
        return newTcpSteam

    class TcpStream:
        def __init__(self):
            self.src_ip = ""
            self.src_port = ""
            self.dst_ip = ""
            self.dst_port = ""
            self.packets = []  # 每个TcpStream下的packets

        def append_packet(self, packet):  # 为该tcp流追加一个数据包
            self.packets.append(packet)

        def read_packets(self):  # 返回该tcp流的所有数据包
            return self.packets


class MasterDecrypter:

    def __init__(self, ciphersuite=None, cipher_size=None, cipher_mode=None, cipher_hash=None, master_secret=None,
                 server_random=None,
                 client_random=None, packets=None, ssllog_path=None
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
        self.packets = packets  # 要解析的packets
        self.ssllog_path = ssllog_path  # 解析pcap数据包所需要的ssllog文件的路径
        self.IV_size = 4
        self.nonce_size = 8
        self.mac_size = 16
        self.application_datas_s2c = []
        self.application_datas_c2s = []
        self.applicaiton_datas_raw = {}  # {packet id:encrypted data}
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

    def ciphername2values(self):
        if self.ciphersuite:
            # 举例:TLS_SM4_GCM_SM3 SM3/SM4是中国算法，不推荐使用
            # 举例:TLS_AES_128_GCM_SHA256 (0x1301)
            # 举例:TLS_DHE_RSA_WITH_SEED_CBC_SHA (0x009a)
            # 举例:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
            # 举例:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
            # 参考: https://ciphersuite.info/cs/
            # enc_algo 加密算法(eg:AES)
            # size_raw 大小(eg:256)
            # mode_raw 加密算法的具体工作模式(eg:GCM)
            # hash_raw 签名算法(eg:SHA256)
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
                symmetric_part = self.ciphersuite.split("TLS_")[1]  # 以加密套件中的TLS_做区分，取第二部分
            parts = symmetric_part.split('_')
            if len(parts) == 4:
                hash_algo = parts[3].split(" ")[0]  # 实际上这个hash算法表示符中间有空格(如'SHA256 (0xc02f)')
                if parts[0] in enc_list and parts[2] in modes_list and hash_algo in hash_list:
                    enc_algo, size_raw, mode_raw, hash_raw = parts
                else:
                    print('Unsupported hash_algo: {}'.format(hash_algo))
                    return False
            elif len(parts) == 3 and parts[0] in enc_list:
                if parts[2] in modes_list:  # 无hash
                    enc_algo, size_raw, mode_raw = parts
                    hash_raw = None
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
            self.key_size = int(int(self.cipher_size) / 8)
            self.cipher_mode = mode
            self.cipher_hash = hash_algo
            return True
        else:
            return False

    def append_datas(self, packet):
        """
        读取packet，并根据当前self的client_random等参数，解密该数据包的encrypted app_data
        :param packet: 数据包

        """
        if hasattr(packet, 'ssl'):
            ssl_layer = packet.ssl
        elif hasattr(packet, 'tls'):
            ssl_layer = packet.tls
        else:
            print("packet has no ssl/tls layer")
            return
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
            # print('Discarding non-target packet')
            pass

    def read_and_decrypt_packets(self):
        """
        遍历解析pcap文件，将解析出的HTTP结果保存至application_datas列表中
        """
        # 函数中的局部变量应该小写
        CONTENT_APPLICATION_DATA = b'\x17'  # 十进制下的23
        CONTENT_HANDSHAKE = b'\x16'  # 十进制下的22
        HANDSHAKE_CLIENT_HELLO = b'\x01'
        HANDSHAKE_SERVER_HELLO = b'\x02'
        packets = self.packets
        for pack_id, packet in enumerate(packets):
            if hasattr(packet, 'ssl'):  # 有ssl层
                ssl_layer = packet.ssl
            elif hasattr(packet, 'tls'):  # 有tls层
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
                        # print('Reading client hello from {} packet #{}'.format(self.client_addr, pack_id))
                        # print('Got Client Random: {}'.format(self.client_random))

                    # 是handshake阶段的server_hello消息
                    elif ssl_layer.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                            ssl_layer.handshake_type.binary_value == HANDSHAKE_SERVER_HELLO:
                        self.server_random = ssl_layer.handshake_random.binary_value
                        self.ciphersuite = ssl_layer.handshake_ciphersuite.showname
                        if self.ciphername2values():  # 获得cipher suite后，就将其写入self对象中
                            # print("Set Cipher Suite OK!")
                            pass
                        else:
                            # print("Set Cipher Suite Error!Cipher suite not ")
                            pass
                        self.server_addr = packet.ip.src_host
                        # print('Reading server hello from {} packet #{}'.format(self.server_addr, pack_id))
                        # print('Got Server Random: {}'.format(self.server_random))
                        # print('Got {}'.format(self.ciphersuite))

                # 如果不是handshake消息而是data,则判断master_secret是否记录，并进一步调用append_datas基于是client还是server进行解密
                elif ssl_layer.record_content_type.binary_value == CONTENT_APPLICATION_DATA:
                    # print('Reading {} bytes encrypted application data from packet: #{}'.format(len(ssl_layer.app_data.binary_value),pack_id))
                    packet_details = {}  # 每一个数据包的当前相关变量都存储到这个字典中，为了debug
                    packet_details['client random'] = self.client_random
                    packet_details['server random'] = self.server_random
                    packet_details['master key'] = self.master_secret
                    packet_details['src addr'] = packet.ip.src_host
                    packet_details['raw data'] = ssl_layer.app_data.binary_value
                    packet_details['conversation'] = None
                    packet_details['ssl_session'] = None
                    self.applicaiton_datas_raw[pack_id] = packet_details
                    if self.master_secret:
                        self.append_datas(packet)
                    else:
                        if self.search_masterkey(self.client_random):  # 没有master key，则应先根据client random查找得到master key
                            # print("Find master key and set ok!")
                            self.append_datas(packet)
                        else:
                            # print("No Find master key,couldn't decrypt")
                            pass
                else:
                    # print('Discarding non-target ssl packet')
                    pass

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

    def set_server_addr(self, hostname: str):  # 注意ping获得的ip可能和数据包中的ip不一致
        try:
            ip = socket.gethostbyname(hostname)
            self.server_addr = ip
        except Exception as e:
            print(e)
            raise ValueError('Unknown hostname: {}'.format(hostname))


def print_mail_info(http_text: str):
    # login info:&uid=219111111&domain=stu.hit.edu.cn&password=2222224793ed9c324ea71bc6a4fc046b626d665ed125c3adbe294154204a1ef899c0acaaf7513fe7c2852f719d64a9d2984c1ab08afd898fc94e21e6a8f752d2&face=auto&faceName=%E8%87%AA%E5%8A%A8%E9%80%89%E6%8B%A9&action%3Alogin=
    matchLogin = re.search(r'&uid=(.*?)&domain=(.*?)&password=(.*?)&.*', http_text, re.M | re.I)
    matchSendMail = re.search(r'"account":"(.*?)","to":(.*?),.*"subject":"(.*?)",.*"content":"(.*?)",.*', http_text,
                              re.M | re.I)
    if matchLogin:  # 如果匹配到了login信息
        print("match login info ok!")
        print("username=", matchLogin.group(1), "@", matchLogin.group(2))
        print("password=", matchLogin.group(3))
        print("\n")
    elif matchSendMail:  # 如果匹配到了sendmail信息
        print("match send mail info ok!")
        print("from:", matchSendMail.group(1))
        print("to:", matchSendMail.group(2))
        print("subject:", matchSendMail.group(3))
        print("content:", matchSendMail.group(4))
        print("\n")


if __name__ == "__main__":
    print("usage:python3 hit_mail_decrypt.py <pcap file path> <ssl log file path>")
    argv_len = len(sys.argv)
    if argv_len == 3:
        pcap_file_path = sys.argv[1]
        ssllog_file_path = sys.argv[2]
    else:
        print("as you didn't point out the file name it's name will be set as default")
        pcap_file_path = "hit_mail/hit_mail.pcap"
        ssllog_file_path = "hit_mail/ssl.log"
    dst_mail_hostname = "mail.hit.edu.cn"
    TcpStreamList = TcpStreamList(pcap_path=pcap_file_path)  # 存放从此次数据包中读取到的tcp_stream
    print("start reading packets from pcap file")
    TcpStreamList.read_pcap()
    print("read tcp streams ok")
    for TcpStream in TcpStreamList.tcpstreams:  # 对每个TcpStream
        packets = TcpStream.read_packets()
        example_decrypter = MasterDecrypter(packets=packets, ssllog_path=ssllog_file_path)
        example_decrypter.set_server_addr(dst_mail_hostname)
        example_decrypter.read_and_decrypt_packets()  # 顺序读取所有流数据并解密
        # print('-' * 2 + "Client Records" + '-' * 2)
        for c2s_record in example_decrypter.application_datas_c2s:
            try:
                record_decoded = c2s_record.decode()  # 转为str
                # print("decrypeted ok!and the plain text is:")
                # print(record_decoded)
                print_mail_info(record_decoded)

            except Exception as e:
                # print(e)
                pass
            # print('-' * 20)
        # 实验提交，无需打印server端http解密data
        # print('*' * 20)
        # print('*' * 20)
        # print('-' * 2 + "Server Records" + '-' * 2)
        # for s2c_record in example_decrypter.application_datas_s2c:
        #     try:
        #         record_decoded_head = s2c_record[:100].decode()
        #         #print("decrypeted ok!and the plain text head 100 bytes are:")
        #         #print(record_decoded_head)
        #     except Exception as e:
        #         print(e)
        #     #print('-' * 20)

import pyshark
import MasterDecrypter
from Cryptodome.Cipher import AES
from Cryptodome import Hash

"""
Carve relevant TLS info out of pcap.

Assumptions:
- pcap contains only one tcp stream
- symmetric algorithm is AES
"""
CONTENT_APPLICATION_DATA = b'\x17'
CONTENT_HANDSHAKE = b'\x16'
HANDSHAKE_CLIENT_HELLO = b'\x01'
HANDSHAKE_SERVER_HELLO = b'\x02'

master_secret = b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'


def cs_name_to_values(ciphersuite_name):
    # 举例:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
    symmetric_part = ciphersuite_name.split('WITH_')[1]  # 以加密套件中的WITH_做区分，取第二部分

    enc_algo, size_raw, mode_raw, hash_raw = symmetric_part.split('_')
    # enc_algo 加密算法(e.g:AES)
    # size_raw 大小(e.g:256)
    # mode_raw 加密算法的具体工作模式(e.g:GCM)
    # hash_raw 签名算法(e.g:SHA256)
    size = int(size_raw)
    mode = getattr(AES, 'MODE_{}'.format(mode_raw))  # 获得AES的MODE_GCM属性
    hash_str = hash_raw.split()[0]

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

    return enc_algo, size, mode, hash_algo


packets = pyshark.FileCapture('singlestream_example/singlestream.openmrs.org.pcap')  # 读取pcap文件

# 只能针对一个通信流，不过既然是邮箱通信，这也足够了
client_random = None
server_random = None
ciphersuite = None
application_datas_c2s = list()  # 记录解密出的cient->server的消息
application_datas_s2c = list()  # 记录解密出的server->client的消息
client_addr = b''
server_addr = b''

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
                client_random = ssl_layer.handshake_random.binary_value
                client_addr = packet.ip.src_host
                print('Reading client hello from {} packet #{}'.format(client_addr, pack_id))
                print('Got Client Random: {}'.format(client_random))

            # 是handshake阶段的server_hello消息
            elif ssl_layer.record_content_type.binary_value == CONTENT_HANDSHAKE and \
                    ssl_layer.handshake_type.binary_value == HANDSHAKE_SERVER_HELLO:
                server_random = ssl_layer.handshake_random.binary_value
                ciphersuite = ssl_layer.handshake_ciphersuite.showname
                server_addr = packet.ip.src_host
                print('Reading server hello from {} packet #{}'.format(server_addr, pack_id))
                print('Got Server Random: {}'.format(server_random))
                print('Got {}'.format(ciphersuite))

        # 如果不是handshake消息而是data,则根据是client还是server进行解密
        elif ssl_layer.record_content_type.binary_value == CONTENT_APPLICATION_DATA:
            print('Reading {} bytes encrypted application data from packet: #{}'.format(
                len(ssl_layer.app_data.binary_value),
                pack_id
            ))

            if packet.ip.src_host == server_addr:
                application_datas_s2c.append(ssl_layer.app_data.binary_value)
            elif packet.ip.src_host == client_addr:
                application_datas_c2s.append(ssl_layer.app_data.binary_value)

# 遍历完所有数据包之后，如果client_random或server_random或ciphersuite还为None,则报错握手阶段不完整，无法解密
# 如果random值和ciphersuite值都有，但解密出的数据长度为0，则提示没有解密数据
if client_random is None or server_random is None or ciphersuite is None:
    print('Incomplete handshake, unable to decrypt')
    quit()
elif len(application_datas_c2s) + len(application_datas_s2c) < 1:
    print('No application data found to decrypt')
    quit()

enc_algo, size, mode, hash_algo = cs_name_to_values(ciphersuite)
# 从ciphersuite中提取套件
decrypter = MasterDecrypter.MasterDecrypter(size, mode, hash_algo, master_secret, server_random, client_random)
# 生成decrypter

# print('Client Records {}'.format('-' * 20))
# for record in application_datas_c2s:
#     print(decrypter.decrypt_client(record))

print('Server Records {}'.format('-' * 20))
for record in application_datas_s2c:
    print(decrypter.decrypt_server(record[:200]))

class OrderedKeyMaterial:
    def __init__(self):
        #  SSL记录层用security parameters生成client/server write mac secret and client/server write secret
        self.client_write_MAC_key = b''
        self.server_write_MAC_key = b''
        self.client_write_key = b''
        self.server_write_key = b''
        self.client_write_IV = b''  # 从key block(密钥材料)中提取出来，加密使用的初始向量
        self.server_write_IV = b''
        self.cipher_size=256
        self.key_size = int(self.cipher_size / 8)
        self.IV_size = 4  # TODO: This changes based on cipher mode (e.g., GCM, CBC, etc.)
        self.nonce_size = 8  # TODO: Only relevant in GCM mode, but is this constant for all GCM configurations?
        self.mac_size = 16  # TODO: is this guaranteed to always be the same across all cipher suites?

    def _get_keys(self, key_material):  # GCM mode 生成密钥材料
        ret = OrderedKeyMaterial()  # 初始化一个OrderedKeyMaterial变量
        # 传来的key_material144字节，client_write_key取32字节。
        ret.client_write_MAC_key = b''
        ret.server_write_MAC_key = b''

        ret.client_write_key = key_material[0:self.key_size]  # 第一个key_size
        ret.server_write_key = key_material[self.key_size: 2 * self.key_size]  # 第二个key_size
        ret.client_write_IV = key_material[2 * self.key_size: 2 * self.key_size + self.IV_size]  # one IV_size
        ret.server_write_IV = key_material[2 * self.key_size + self.IV_size:2 * self.key_size + 2 * self.IV_size]  # two

        return ret
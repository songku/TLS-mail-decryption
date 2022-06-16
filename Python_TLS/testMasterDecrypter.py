from Cryptodome.Cipher import AES
from Cryptodome import Hash

import MasterDecrypter
# use for Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030) 32bytes's secret
# TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
# AES_128 uses 16 bytes's secret

# client_cipher_text = b'\x00\x00\x00\x00\x00\x00\x00\x01\xa0\x07\x89\xd4\xb6\x27\x79\x55\x4c\x6f\x34\x75\x69\x93\xe1\x10\x94\x93\x1b\x54\x9f\x92\xcb\xef\x6c\xa7\x38\x5e\x09\x92\x37\x09\x28\xd1\x86\x5b\x64\xea\x43\x44\x1b\xd8\xa6\xd4\xd6\x96\xa8\xf4\xef\xfb\x73\x63\x1d\x64\x00\xea\xaf\x82\xcf\x2e\x17\xac\x8b\x2a\x15\x16\x49\x2b\x0d\xbc\xe7\xa7\xea\x4e\xe2\x44\x0b\x39\xb0\x7c\x98\x27\xfa\xad\x48\xce\xb7\xba\xdb\x57\x17\x4d\xd6\xb1\x3b\x1d\x86\x17\x77\xc8\x7e\x28\x77\xb6\xf5\xe1\xae\xb8\x09\xaf\x1e\xa8\x80\x5e\xca\x47\x2e\xe2\x44\x85\x46\x5d\x33\xe7\xe5\xbb\x82\x8a\xf1\x90\xeb\x3a\x4e\x85\x69\x39\x25\x71\xe0\xce\x14\xe8\x7c\x40\xfb\xf8\xc4\xec\x56\x5a\x8c\x76\x75\x50\x6f\xea\xc0\x0e\xc1\x05\xf0\x43\x20\x53\x38\xe7\x79\x89\xc4\x68\xcf\x2c\x82\x4b\x9b\x9b\x05\x3f\xd4\xa8\x41\xe3\xa9\xc4\x14\x1a\xfb\x3e\xc0\xd7\xe5\x57\x33\xd3\x94\xdb\xbf\xc4\xec\x31\x27\x5c\x58\x20\xf0\x00\xb0\xf3\x94\xc5\xfc\x8b\x19\x88\xe6\x78\xa1\xf0\xe2\x75\xff\xd7\x7c\x15\xbb\xd5\x2d\x29\x73\x2b\xed\x95\xa7\xd1\xb6\xa3\x66\xbb\x5b\x6f\x19\x93\x54\x31\x5f\xfa\xff\xec\x72\xc7\x3b\x73\x0f\x24\x1e\xbb\xea\x26\x13\x35\xc5\x82\x06\xda\xc5\x18\x44\x87\xe5\x1a\x09\x6b\x1d\x02\x10\x3b\x82\xe2\x4d\x91\xe6\xab\x24\x06\xcc\x51\x7e\x55\x86\x1d\xb3\x65\x72\x13\x1a\x09\x93\xb4\x20\x0f\x56\x99\x90\x9b\x07\xa6\x27\xe9\x86\x5f\xc8\x8a\xb2\x78\x46\xd7\x0b\x36\x77\xc6\x6e\x44\x3b\x73\x6f\xaa\xe2\xb3\x46\x11\xdf\x96\xab\x68\xd2\xc6\xa8\x88\x4f\x4d\x60\xdc\x80\x84\xbb'
# server_random = b'\xe3\xc8\x89\xda\x5d\xf4\xa0\xfd\xfa\x35\x65\xa8\x5b\x5d\xfd\x12\xa9\xf7\x84\x54\x15\x4a\xc1\x85\xd4\x32\x67\xee\x33\x90\x08\x40'
# client_random = b'\x91\xc6\x36\x47\x1b\xfe\x58\xea\x21\x5d\x0f\x69\x3a\x1a\xd1\x78\xf1\x38\xf3\xc0\x60\x6d\x30\x72\xf2\xaf\xf1\xad\x24\x86\x6a\x87'
# master_secret = b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'

client_cipher_text_str='00000000000000017342178f6c449aa23ffbf370ec2cad773d95d13ebb19c2ff490bab46ebf91d9b562ffe565a991dc6f1b37c760c8cc6befe87417853f9629db92180d942ec2a60614610bb2dc8974ee62ae3d51c288d95671d91a561b08b0c127ed88e7f97375a05467c893e28e10eb69f4bc72e4ca94b5957eb44dd19cb2e92d9d35ef7073c186918d652bed2379cd8f7a7ec2352c6f796bb72eeafb0014ed4c30b8eba80295ce66e2e880cacf477a2cc04d5718e3ee071ce0c9e86ce2d74ba8f124cb48be4a9f6a188732765799397f4bc7f35f9ce44b0d277c6c65846715a65f9179020f80365db21fe9bae2e1e15d8c71312b8e24a998f935e0a64a7d92f7787b8ff3e0402ae77c1f0df6ab6a1c4f11b564b4e212fc47ec9edcac40611a134ad6e9df450e67a8f0080d1d0244b75cb8de425c699be0054d3c330f3b8181b1cdf1a0fdb5f99952cc280c5aec2d6b5c6ef55c4c63efb3e65994d542b27b33d0e22fcef447bccde9fa58dbf419a2e89fd90cbdf22999dda956a20cb7c9f18a2635ba4acd01c07fb005883252e28d0ad165539f2ce161e4eed7bfc3bd579a84b653ed5053e20e9faf93f3262d720d00d744fb8bdabacd266c148b1479e71d92422e9f465df7670c33f128af1bf5d54f6e341213a5cc38d0da7690a03a24c940993fa16d78ba21a813058cd0d7e57b37470b5f32df1105977991195bf11d8e42fc7394a1fe135fa73c4279b8b43748c853bec8ce967cd0ad8a8f471ec16c24d5dc752b45f4060ee2209c4e15ac9668f9955a212a6bcc96feeed65eb1ec6646660b13689d521b1bcf0938129ccc35cfd89357c12faa66b3552cf69c77aeba4d59c9d54edaa117412eaacaf6c9c21ae1bc238d5a0e4d28adf045e9e56cf16c2923a9f773c66f001a33115627de52ef08dfd308a3c7ab8409361930a984134d8d7cc904fcbbad98ae393fb8bf7cf26022219345656d6d6e899b0604e011484dc15bf87c1c7b5a443058e18cfa3c681176fd8b8b9fce6b30d87ba6fc630d6d20029d239585f346549bcf973f98464a7cced98d44df1dc850d88cc7585e2bd85da048e1c5df5143eeef2268e058b73c4ea6768aeb771bee80b043e7bb2db18b7da9899c81029c016534e7f11329d7f8ac229f0c18d92dafaf789570f73b82932f1b1789995597cf778c0aea69d164748bb7a41543b5db3b3c0bc6ab2db96d3803a325f71f99ee99706e642811ab6938cd112909f11b1d40e34d3fff3a09bde195ee85fab7422014d0c3ccc748590192c9cf747c8bc424a53533e5369cb9adb0f251fe7e43c961c25061ef88b92547d7ef6f56512051a3e11ad9416c427e8e7c5884671967a062e331146e56ac5f94641a05c6223489bfa1a3c38ee1db96229b82868be03e597179ba7eef40ef82f741c749633df70011a725d9f6100078256a81cde0301b04a5e88323e010d119b972e6628013c6cfcb7027d9c2d13a14612a3171c1f4be2f2ab6662c2a1a75ae1703cedfb189fd049cb36be0e56c52400ad637713aeea02b6fa119d28757e48d5f19478fb601d95004986b6de74233fbf982f32425c1263ce6f51d24926307a843b1f6b03c11906cce6178a71265f344c76eae57ffc3d0e2ae2d4006fc019aeb6384815f21dd0918b5825913efeddf6f3944c6154afddb620cfa3e56960fbf7ee8c1357a33f95f2fdcab2ae95d3fe62e5796593c2154405bbc37c166392533719149d5c31d33954b14f7df529e9e7b82eb37e7a6cfcf281f9c42106f151212341fb5e8292edd9499082202c19e5131bfc6872a35f2b54c8bb2bd267e51ad2ee7286d594fef1251efc57a3cf6de0409d94a6435b5a68183ad3ef6c13cdf655e7cb46dd6be5a314f462136b4e2627c85e9769184d8d41c1c476a9af16e066c500f1beb35e736dd1c4ff631ba41459be7526e12bf0a44f9810208f2a5e625597099e996fc7faaa1cc7ab2bb11799d45b64bd223969c1e51a2eac28f168db482ccc62'
client_cipher_text = bytes.fromhex(client_cipher_text_str)
# server_random_str='5b0dc83fba9a219e31ad380467693c85431a3faf8b04e6eada8276b28947898f'
server_random_str = 'a407923fac0e212a969e101b04edb2b0e69e8193d781b47f92bd199bf56131b7'
server_random = bytes.fromhex(server_random_str)
client_random_str = 'ed5fa4ee72fd71ffbb913eadb2252541cdbbd0c86e314fd8912214de4783d9e3'
# 如上这条client_random有对应的master key
client_random = bytes.fromhex(client_random_str)
master_secret_str='6160477fc1afce504f6185fcd79382dd4cc1dc0103b507760936fa86e0214d6b425b59e7c2635109ef88a355f803d6f4'
master_secret=bytes.fromhex(master_secret_str)
tls_decrypter = MasterDecrypter.MasterDecrypter(
    128,
    AES.MODE_GCM,
    Hash.SHA256,
    master_secret,
    server_random,
    client_random
)

print(tls_decrypter.decrypt_client(client_cipher_text))
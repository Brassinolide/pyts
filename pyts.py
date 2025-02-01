import hashlib, random, requests, argparse, os, time, shutil
from asn1crypto import tsp, core

def sha256_file(file_path:str) -> bytes:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(50 * 1024 * 1024), b""):
            sha256_hash.update(byte_block)

    print(f"    sha256 {sha256_hash.hexdigest()}")
    return sha256_hash.digest()

def get_file_tsq(file_path:str, set_nonce:bool = False, require_cert:bool=False) -> bytes:
    print(f"处理 {file_path}")
    return tsp.TimeStampReq({
        'version': 1,
        'message_imprint': tsp.MessageImprint({
            'hash_algorithm': {'algorithm': 'sha256'},
            'hashed_message': sha256_file(file_path)
        }),
        'nonce': core.Integer(random.getrandbits(64)) if set_nonce else None,
        'cert_req': require_cert
    }).dump()

def requests_tsa(tsa:str, tsq:bytes) -> bytes:
    response = requests.post(tsa, headers={"Content-Type":"application/timestamp-query"}, data=tsq)
    response.raise_for_status()
    tsr = tsp.TimeStampResp.load(response.content)['status'].native
    if(tsr['status'] != "granted"):
        print(f"    签名失败（{tsr['status']}）：{tsr['fail_info']}")
    else:
        print("    签名成功")
    return response.content

def hexdump(data, indent=0):
    offset = 0
    while offset < len(data):
        line = data[offset:offset+16]
        hex_str = ' '.join(f'{byte:02x}' for byte in line)
        ascii_str = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in line)
        print('  ' * indent + f'{offset:08x}: {hex_str:<48} {ascii_str}')
        offset += 16

def dictdump(item, indent=0):
    if isinstance(item, dict):
        for key, value in item.items():
            print('  ' * indent + str(key) + ':', end=' ')
            if isinstance(value, (dict, list, bytes)):
                print()
                dictdump(value, indent + 1)
            else:
                print(value)
    elif isinstance(item, list):
        for index, value in enumerate(item):
            print('  ' * indent + f'[{index}]:', end=' ')
            if isinstance(value, (dict, list, bytes)):
                print()
                dictdump(value, indent + 1)
            else:
                print(value)
    elif isinstance(item, bytes):
        hexdump(item, indent)

def tsrdump(tsr:str):
    with open(tsr, "rb") as f:
        dictdump(tsp.TimeStampResp.load(f.read()).native)

def enum_files(directory, no_recurse=False):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for name in files:
            file_list.append(os.path.join(root, name))
        if no_recurse:
            break
    return file_list

parser = argparse.ArgumentParser(description='A command line tool to create RFC-3161 timestamp signatures')
group = parser.add_mutually_exclusive_group(required=True)
tsa_group = parser.add_argument_group('tsa选项')
tsa_group.add_argument('--tsa', type=str, default='http://rfc3161timestamp.globalsign.com/advanced', help = '服务器地址（默认为globalsign）')
tsa_group.add_argument('--set_nonce', action='store_true', help='tsq设置一次性随机数')
tsa_group.add_argument('--strip_cert', action='store_true', help='tsr剥离签名者公钥')
group.add_argument('-i', '--input', type=str ,help = "输入文件或文件夹")
parser.add_argument('--no_recurse', action='store_true', help = "不枚举子目录")
group.add_argument('-d','--dump', type=str, help = "查看tsr文件内容")
args = parser.parse_args()

if args.dump:
    tsrdump(args.dump)
    exit(0)

def get_file_tsr(file:str):
    tsr = requests_tsa(args.tsa, get_file_tsq(file, args.set_nonce,not args.strip_cert))
    save = file + ".tsr"
    print(f"    保存至 {save}")
    with open(save,"wb") as f:
        f.write(tsr)

if not os.path.exists(args.input):
    raise ValueError("路径不存在")
if os.path.isfile(args.input):
    get_file_tsr(args.input)
elif os.path.isdir(args.input):
    for f in enum_files(args.input, args.no_recurse):
        get_file_tsr(f)
        time.sleep(3)
else:
    raise ValueError("未知路径")

import hashlib, random, requests, argparse, os, time, sys, ctypes
from asn1crypto import tsp, core
from colorama import init, Fore, Style
from datetime import timedelta, datetime

class libts_ReturnCode():
    UNDEFINED = 0
    VERIFICATION_OK = 1
    VERIFICATION_FAIL = 2
    INVALID_PARAM = 3
    OPENSSL_ERROR = 4

class libts_CA_TYPE():
    CA_SYSTEM = 0
    CA_FILE = 1
    CA_PATH = 2
    CA_STORE = 3

class libts_caller:
    def __init__(self):
        self.loaded = False

    def load_dll(self):
        if not self.loaded:
            if sys.platform.startswith('linux'):
                self.libts = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libts.so'))
            elif sys.platform.startswith('win32'):
                self.libts = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libts.dll'))
            else:
                raise RuntimeError('Unsupported operating systems')
            
            self.libts.ts_verify_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_bool]
            self.libts.ts_verify_file.restype = ctypes.c_int

            self.libts.ts_get_last_openssl_error.argtypes = []
            self.libts.ts_get_last_openssl_error.restype = ctypes.c_char_p

            self.libts.resp_get_signing_time.argtypes = []
            self.libts.resp_get_signing_time.restype = ctypes.c_uint64

            self.loaded = True

    def verify_file(self, data_file:str, sign_file:str, parse_resp = True, ca_type:int = libts_CA_TYPE.CA_SYSTEM, ca:str = "") -> int:
        self.load_dll()
        return self.libts.ts_verify_file(ctypes.c_char_p(bytes(data_file, 'utf-8')), ctypes.c_char_p(bytes(sign_file, 'utf-8')), ca_type, ctypes.c_char_p(bytes(ca, 'utf-8')), parse_resp)

    def get_sign_time(self) -> int:
        self.load_dll()
        return self.libts.resp_get_signing_time()

    def get_error_msg(self, code: int) -> str:
        self.load_dll()
        if code == libts_ReturnCode.UNDEFINED:
            return "程序出现了未定义行为（笑"
        if code == libts_ReturnCode.VERIFICATION_OK:
            return "验证成功"
        if code == libts_ReturnCode.VERIFICATION_FAIL:
            return f"验证失败 {self.libts.ts_get_last_openssl_error().decode('utf-8')}"
        if code == libts_ReturnCode.INVALID_PARAM:
            return "参数错误"
        if code == libts_ReturnCode.OPENSSL_ERROR:
            return self.libts.ts_get_last_openssl_error().decode('utf-8')
libts = libts_caller()

def sha256_file(file_path:str) -> bytes:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(50 * 1024 * 1024), b""):
            sha256_hash.update(byte_block)

    print(f"    sha256 {sha256_hash.hexdigest()}")
    return sha256_hash.digest()

def get_file_tsq(file_path:str, set_nonce:bool = False, no_cert:bool=False) -> bytes:
    return tsp.TimeStampReq({
        'version': 1,
        'message_imprint': tsp.MessageImprint({
            'hash_algorithm': {'algorithm': 'sha256'},
            'hashed_message': sha256_file(file_path)
        }),
        'nonce': core.Integer(random.getrandbits(64)) if set_nonce else None,
        'cert_req': not no_cert
    }).dump()

def requests_tsa(tsa:str, tsq:bytes) -> bytes:
    response = requests.post(tsa, headers={"Content-Type":"application/timestamp-query"}, data=tsq)
    response.raise_for_status()
    tsr = tsp.TimeStampResp.load(response.content)['status'].native
    if(tsr['status'] != "granted"):
        print(Fore.RED + f"    签名失败（{tsr['status']}）：{tsr['fail_info']}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "    签名成功" + Style.RESET_ALL)
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

def tsrdump(tsr_path:str):
    with open(tsr_path, "rb") as f:
        dictdump(tsp.TimeStampResp.load(f.read()).native)

def enumfile(directory:str, no_recurse:bool=False):
    file_list = []
    for root, _, files in os.walk(directory):
        for name in files:
            if not name.endswith('.tsr'):
                file_list.append(os.path.join(root, name))
        if no_recurse:
            break
    return file_list

def signfile(tsa:str, file_path:str, set_nonce:bool = False, no_cert:bool = False):
    print(f"签名 {file_path}")
    tsr = requests_tsa(tsa, get_file_tsq(file_path, set_nonce, no_cert))
    save_path = file_path + ".tsr"
    print(f"    保存至 {save_path}")
    with open(save_path, "wb") as f:
        f.write(tsr)

def verifyfile(file_path:str, ca_type:libts_CA_TYPE = libts_CA_TYPE.CA_SYSTEM, ca:str = ""):
    if file_path.endswith('.tsr'):
        file_path = file_path[:-4]

    print(f"验证 {file_path}")

    tsr_path = file_path + ".tsr"
    if not (os.path.exists(tsr_path) and os.path.isfile(tsr_path)):
        print(Fore.RED + "    未找到对应的tsr文件" + Style.RESET_ALL)
        return
    
    code = libts.verify_file(file_path, tsr_path, True, ca_type, ca)
    if code == libts_ReturnCode.VERIFICATION_OK:
        utc_time = datetime.fromtimestamp(libts.get_sign_time())
        print(Fore.GREEN + f"    验证成功\n    UTC时间：{utc_time}\n    北京时间：{(utc_time + timedelta(hours=8))}" + Style.RESET_ALL)
    else:
        print(Fore.RED + f"    {libts.get_error_msg(code)}" + Style.RESET_ALL)

parser = argparse.ArgumentParser(description = 'A command line tool to create RFC-3161 timestamp signatures')
parser.add_argument('-d','--dump', type=str, help='查看签名内容（TSR文件）')

subparsers = parser.add_subparsers(dest="mode", help="模式")

parser_sign = subparsers.add_parser('sign', aliases=['s'], help='签名')
parser_sign.add_argument('-i', '--input',required=True, type=str ,help = "输入路径（文件或文件夹）")
parser_sign.add_argument('--no_recurse', action='store_true', help='不枚举子目录')
parser_sign.add_argument('--tsa', type=str, default='http://rfc3161timestamp.globalsign.com/advanced', help = 'TSA服务器地址（默认为globalsign）')
parser_sign.add_argument('--set_nonce', action='store_true', help='设置一次性随机数')
parser_sign.add_argument('--no_cert', action='store_true', help='不请求签名者公钥')

parser_verify = subparsers.add_parser('verify', aliases=['v'], help='验证（需安装openssl且已配置环境变量）')
parser_verify.add_argument('-i','--input', required=True, type=str, help = "输入路径（文件或文件夹）")
parser_verify.add_argument('--no_recurse', action='store_true', help='不枚举子目录')
parser_verify.add_argument('-c','--ca', type=str, default="", help = "CA文件（文件，文件夹，URI）(默认为系统证书)")

args = parser.parse_args()

if args.dump:
    tsrdump(args.dump)
    exit(0)

if not os.path.exists(args.input):
    raise ValueError("路径不存在")

if args.mode == "sign" or args.mode == "s":
    print(f"TSA服务器：{args.tsa}",end="\n\n")
    if os.path.isfile(args.input):
        signfile(args.tsa, args.input, args.set_nonce, args.no_cert)
    elif os.path.isdir(args.input):
        for f in enumfile(args.input, args.no_recurse):
            signfile(args.tsa, f, args.set_nonce, args.no_cert)
            time.sleep(3)
    else:
        raise ValueError("未知路径类型")
elif args.mode == "verify" or args.mode == "v":
    if args.ca == "":
        ca_type = libts_CA_TYPE.CA_SYSTEM
        print("使用系统证书\n\n")
    else:
        if os.path.isfile(args.ca):
            ca_type = libts_CA_TYPE.CA_FILE
            print(f"使用文件证书 {args.ca}\n\n")
        elif os.path.isdir(args.ca):
            ca_type = libts_CA_TYPE.CA_PATH
            print(f"使用文件夹证书 {args.ca}\n\n")
        else:
            ca_type = libts_CA_TYPE.CA_STORE
            print(f"使用URI证书 {args.ca}\n\n")

    if os.path.isfile(args.input):
        verifyfile(args.input, ca_type, args.ca)
    elif os.path.isdir(args.input):
        for f in enumfile(args.input, args.no_recurse):
            verifyfile(f, ca_type, args.ca)
    else:
        raise ValueError("未知路径类型")
else:
    raise ValueError("未知模式")

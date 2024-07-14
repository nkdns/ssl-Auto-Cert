import os
import time
from typing import Any, Tuple,Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import josepy.jwk as jose
import OpenSSL
from acme import challenges, crypto_util, client, messages
import dns.rdatatype
import dns.resolver
import dnspod_add
import dnspod_del
import requests

import datetime
import OpenSSL.crypto

# 帐户密钥大小
ACC_KEY_BITS = 2048
# 证书私钥大小
CERT_PKEY_BITS = 2048
# UA
USER_AGENT = 'python-acme'

class Cert:
    """证书类, 包含证书的申请, 挑战的实现过程"""

    def __init__(self, _email: str, _mode: Union[str, None]= None, _CryptoType:str= 'RSA') -> None:
        """
        构造一个Cert对象
        :param _email 电子邮件地址
        :param _mode 'formal'或者None选一, 分别代表生产模式和测试模式
        """
        self.rger,self.client_acme = _newacccilent(_email,_mode)
        self.CryptoType = _CryptoType
        self.fullchain_pem = None
        self.CertKeyPem = None
        self.order = None
        self.cert_end_time = None
        self.cert_start_time = None

    def new_order(self, domain_name:list, pkey_pem: Union[bytes, None]= None) -> None:
        """
        创建或者更新域名签名证书
        :param domain_name 需要签名的域名列表
        :param pkey_pem 域名对应的私钥, 不填代表生成一个新的
        """
        # 如果pkey_pem没有生成, 那么生成一个
        if pkey_pem is None:
            if(self.CryptoType=='ECC'):
                pkey_pem = GetEccPem()
            else:
                pkey = OpenSSL.crypto.PKey()
                pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
                pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)

        csr_pem = crypto_util.make_csr(pkey_pem, domain_name)
        # 申请证书订单
        orderr = self.client_acme.new_order(csr_pem)
        self.CertKeyPem = pkey_pem.decode('utf-8')
        self.order = orderr

    def select_dns01_chall(self) -> 'list[Tuple[messages.ChallengeBody, challenges.KeyAuthorizationChallengeResponse,Any]]':
        """
        搜寻dns挑战信息
        :return: 返回一个包含挑战对象、挑战内容、挑战内容txt值的元组
        """

        # 获取 DNS 挑战对象列表
        dns_challenges: list[messages.ChallengeBody] = []
        for authorization in self.order.authorizations:
            authorization:messages.AuthorizationResource = authorization
            for challenge in authorization.body.challenges:
                challenge: messages.ChallengeBody = challenge
                if isinstance(challenge.chall, challenges.DNS01):
                    dns_challenges.append(challenge)

        # 获取 DNS 挑战的验证信息
        dns_challenge_validations: list[Tuple[messages.ChallengeBody, challenges.KeyAuthorizationChallengeResponse,Any] ] = []
        for dns_challenge in dns_challenges:
            chall: challenges.KeyAuthorizationChallenge = dns_challenge.chall
            Res,vali=chall.response_and_validation(self.client_acme.net.key)
            dns_challenge_validations.append((dns_challenge,Res,vali))

        return dns_challenge_validations

    def perform_dns01(self, challbs: list, _hostname: str) -> None:
        """回传挑战资源对象进行挑战检查与提交"""
        PROXY_DOMAIN = os.environ.get('PROXY_DOMAIN')
        textdomain = _hostname + f'.{PROXY_DOMAIN}'
        dnspod_del.dnsdel([_hostname,PROXY_DOMAIN])
        for _index,i in enumerate(challbs):
            index = _index + 1
            allchall = len(challbs)
            print(f'{index}/{allchall}:请添加主机名：{_hostname}，记录类型:txt,记录值：{i[2]}')
            dnspod_add.add([_hostname,PROXY_DOMAIN,i[2]])
            _vaildnum=0
            while 1:
                _vaildnum += 1
                print(f'{index}/{allchall}:正在进行第：{_vaildnum}次dns验证')
                _yn = validate_dns_record(textdomain,'txt',i[2])
                if _yn:
                    print(f'{index}/{allchall}:dns记录验证通过，等待提交挑战')
                    break
                time.sleep(1)
            _waittime = 60
            while 1:
                print(f'{index}/{allchall}:等待{_waittime}秒提交挑战',end="\r")
                time.sleep(1)
                _waittime-=1
                if _waittime == 0:
                    break
            print('\n开始验证挑战')
            self.client_acme.answer_challenge(i[0], i[1])
            select_c_s = 0
            _status = ''
            while 1:
                select_c_s += 1
                _url = i[0].uri
                res=requests.get(_url)
                resJson = res.json()
                _status = resJson['status']
                print(f'{index}/{allchall}-{select_c_s}:正在查询挑战状态：{_status}')
                if _status in ['pending','processing']:
                    pass
                else:
                    break
                time.sleep(2)
            dnspod_del.dnsdel([_hostname,PROXY_DOMAIN])
            if _status == 'valid':
                print(f'{index}/{allchall}:本次挑战结束')
            else:
                print('挑战异常:' + _status)
                raise RuntimeError(f'挑战异常:{_status}')

        print('全部挑战已经完成')

        assert self.order is not None
        finalized_orderr = self.client_acme.poll_and_finalize(self.order)
        print('证书已经生成')
        self.fullchain_pem = finalized_orderr.fullchain_pem
        certbytes = self.fullchain_pem.encode()
        self.cert_start_time,self.cert_end_time = GetCertTime(certbytes)

    def reset(self) -> None:
        """重置状态"""
        self.fullchain_pem = None
        self.CertKeyPem = None
        self.order = None
        self.cert_start_time = None
        self.cert_end_time = None

def _newacccilent(_email, _type: Union[str,None]= None) -> Tuple[messages.RegistrationResource, client.ClientV2]:
    if _type is None:
        DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    elif _type == 'formal':
        DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
    # 创建账户密钥
    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                    key_size=ACC_KEY_BITS,
                                    backend=default_backend()))
    # 注册帐户并接受tos
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(DIRECTORY_URL, net)
    client_acme = client.ClientV2(directory, net=net)
    # 服务条款URL位于client_acme.directory.meta.Terms_of_Service中
    # 注册资源：regr
    # 使用联系人信息创建帐户。
    regr = client_acme.new_account(
        messages.NewRegistration.from_data(
            email=_email, terms_of_service_agreed=True))
    return regr,client_acme

def validate_dns_record(hostname: str, record_type:Union[str,int], expected_value) -> bool:
    """在申请挑战鉴定之前, 先测试dns挑战是否生效"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['112.80.181.45']
        if isinstance(record_type, str):
            record_type = dns.rdatatype.from_text(record_type)
        answers = resolver.query(hostname, record_type)
        for answer in answers:
            print('本次dns应答：' + answer.to_text())
            if answer.to_text().replace('"', '') == expected_value:
                return True
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        print(f'dnspod未找到{hostname}的记录')
        try:
            resolver.nameservers = ['114.114.114.114']
            if isinstance(record_type, str):
                record_type = dns.rdatatype.from_text(record_type)
            answers = resolver.query(hostname, record_type)
            for answer in answers:
                print('本次dns应答：' + answer.to_text())
                if answer.to_text().replace('"', '') == expected_value:
                    return True
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f'114未找到{hostname}的记录')
    return False

def GetCertTime(_cert: bytes) -> Tuple[datetime.datetime, datetime.datetime]:
    """获取证书的有效日期"""
    certificate = x509.load_pem_x509_certificate(_cert, default_backend())
    cert_start = certificate.not_valid_before
    cert_end = certificate.not_valid_after
    return cert_start,cert_end

def GetEccPem() -> bytes:
    """生成ECC384r1密钥"""
    # 选择一个ECC曲线，例如：secp256r1，secp384r1，secp521r1等
    CURVE = ec.SECP384R1()
    # 生成ECC私钥
    private_key = ec.generate_private_key(CURVE, backend=default_backend())
    # 将私钥序列化为PEM格式
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_pem
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import OpenSSL
import OpenSSL.crypto
import dns.resolver
import time
from acme import challenges
from acme import client
from acme import crypto_util
from acme import messages

# 常量:

# This is the staging point for ACME-V2 within Let's Encrypt.
# DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'

USER_AGENT = 'python-acme-example'

# 帐户密钥大小
ACC_KEY_BITS = 2048

# 证书私钥大小
CERT_PKEY_BITS = 2048

# 证书的域名。
DOMAIN = ['*.examples.cn','examples.cn']

def new_csr_comp(domain_name, pkey_pem=None):
    """创建证书签名请求。"""
    if pkey_pem is None:
        # Create private key.
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                  pkey)
    csr_pem = crypto_util.make_csr(pkey_pem, domain_name)
    return pkey_pem, csr_pem

def select_dns01_chall(orderr,client_acme):
    # 获取 DNS 挑战对象列表
    dns_challenges = []
    for authorization in orderr.authorizations:
        for challenge in authorization.body.challenges:
            if isinstance(challenge.chall, challenges.DNS01):
                dns_challenges.append(challenge)
    # 获取 DNS 挑战的验证信息
    dns_challenge_validations = []
    for dns_challenge in dns_challenges:
        Res,vali=dns_challenge.chall.response_and_validation(client_acme.net.key)
        dns_challenge_validations.append([dns_challenge,Res,vali])
    return dns_challenge_validations

def validate_dns_record(hostname, record_type, expected_value):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['112.80.181.45']
        answers = resolver.query(hostname, record_type)
        for answer in answers:
            print('本次dns应答：' + answer.to_text())
            if answer.to_text().replace('"', '') == expected_value:
                return True
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        print(f'未找到{hostname}的记录')
    return False

def perform_dns01(client_acme, challbs, orderr):
    for i in challbs:
        print(f'请添加主机名：_acme-challenge，记录类型:txt,记录值{i[2]}')
        input()
        vaildnum=0
        while 1:
            time.sleep(5)
            vaildnum += 1
            print(f'正在进行第{vaildnum}次验证')
            _yn=validate_dns_record('_acme-challenge.abbajhjhj.proxyexamples.cn','txt',i[2])
            if _yn ==True:
                print('本次验证通过')
                break
        print('等待60s提交挑战')
        time.sleep(60)
        client_acme.answer_challenge(i[0], i[1])
    print('全部挑战已经完成')
    finalized_orderr = client_acme.poll_and_finalize(orderr)
    return finalized_orderr.fullchain_pem

# 主要示例:
def example_http():
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
    email = ('examples@examples.cn')
    regr = client_acme.new_account(
        messages.NewRegistration.from_data(
            email=email, terms_of_service_agreed=True))

    # 创建域私钥和CSR
    pkey_pem, csr_pem = new_csr_comp(DOMAIN)

    # 颁发证书
    orderr = client_acme.new_order(csr_pem)

    # 在CA服务器提供的挑战中选择HTTP-01
    #challbs [[挑战，验证信息],[挑战，验证信息]……]
    challbs = select_dns01_chall(orderr,client_acme)

    # 该证书已准备好在变量“fullchain_pem”中使用。
    fullchain_pem = perform_dns01(client_acme, challbs, orderr)
    key_pem=pkey_pem.decode('utf-8')
    print(f'申请完成，证书：{fullchain_pem}\n密钥：{key_pem}')

    # # 续订证书

    # _, csr_pem = new_csr_comp(DOMAIN, pkey_pem)

    # orderr = client_acme.new_order(csr_pem)

    # challb = select_dns01_chall(orderr)

    # # 表演挑战
    # fullchain_pem = perform_dns01(client_acme, challb, orderr)

    # # 吊销证书

    # fullchain_com = jose.ComparableX509(
    #     OpenSSL.crypto.load_certificate(
    #         OpenSSL.crypto.FILETYPE_PEM, fullchain_pem))

    # try:
    #     client_acme.revoke(fullchain_com, 0)  # revocation reason = 0
    # except errors.ConflictError:
    #     # 证书已被吊销。
    #     pass

    # 查询注册状态。
    # client_acme.net.account = regr
    # try:
    #     regr = client_acme.query_registration(regr)
    # except errors.Error as err:
    #     if err.typ == messages.ERROR_PREFIX + 'unauthorized':
    #         # 状态已停用。
    #         pass
    #     raise

    # # 更改联系信息

    # email = 'cert1@nkdns.cn'
    # regr = client_acme.update_registration(
    #     regr.update(
    #         body=regr.body.update(
    #             contact=('mailto:' + email,)
    #         )
    #     )
    # )

    # # 停用帐户/注册

    # regr = client_acme.deactivate_registration(regr)


if __name__ == "__main__":
    example_http()
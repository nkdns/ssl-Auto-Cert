from Cert import Cert
import Cert as ccert
import mysql
from dotenv import load_dotenv
import os
import datetime
import sys

load_dotenv()
HOSTNAME = os.environ.get('DB_HOSTNAME')
PORT = os.environ.get('DB_PORT')
USER = os.environ.get('DB_USER')
PASSWORD = os.environ.get('DB_PASSWORD')
PROXY_DOMAIN = os.environ.get('PROXY_DOMAIN')
DB = os.environ.get('DB_DB')
ENVIRONMENT = os.environ.get('ENVIRONMENT')

if __name__=='__main__':
    #获取数据库对象，自动执行初始化检查
    if sys.version_info >= (3, 7):
        print(f"Python 版本{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}")
        pass
    else:
        print(f"Python 版本{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}小余3.7,请升级。")
        sys.exit()

    sqlc = mysql.init(HOSTNAME,USER,PASSWORD,DB)

    if(ENVIRONMENT=='formal'):
        current_time = datetime.datetime.now()
        thirty_days_ago = current_time + datetime.timedelta(days=30)
        query = "SELECT * FROM certbase WHERE lastexpiredTime <= %s OR lastexpiredTime IS NULL"
        certificate_list = sqlc.Select(query,(thirty_days_ago,))
    else:
        query = "SELECT * FROM certbase WHERE domain = %s"
        certificate_list = sqlc.Select(query,("",))

    if not certificate_list:
        print('证书申请列表为空，退出程序')
        exit

    for i in certificate_list:
        _docname = False
        for _domain in eval(i['domain']):
            if _domain.startswith('*'):
                _domain = '_acme-challenge' + _domain[1:]
                pass
            else:
                _domain = '_acme-challenge.' + _domain
            _docname = ccert.validate_dns_record(_domain,'cname',i['proxydomain'] + f'.{PROXY_DOMAIN}.')
            if _docname==False:
                print(f'请先为{_domain}添加值为{i['proxydomain'] + PROXY_DOMAIN}的cname解析')
                break

        if _docname:
            cert = Cert(i['email'],ENVIRONMENT,i['CryptoType'])
            cert.new_order(eval(i['domain']))
            challbs = cert.select_dns01_chall()
            cert.perform_dns01(challbs,i['proxydomain'])

            if(ENVIRONMENT=='formal'):
                insert_query = "INSERT INTO certinfo (cert_group_id, domain, createTime, expiredTime, fullchain, certKey, CryptoType) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                sqlc.IORUnsert(insert_query,(i['id'], i['domain'], cert.cert_start_time, cert.cert_end_time, cert.fullchain_pem, cert.CertKeyPem, i['CryptoType']))
                update_query = "UPDATE certbase SET updateTime = %s ,lastexpiredTime = %s WHERE id = %s"
                sqlc.IORUnsert(update_query,(datetime.datetime.now(), cert.cert_end_time, i['id']))
            else:
                insert_query = "INSERT INTO certinfo_test (cert_group_id, domain, createTime, expiredTime, fullchain, certKey, CryptoType) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                sqlc.IORUnsert(insert_query,(i['id'], i['domain'], cert.cert_start_time, cert.cert_end_time, cert.fullchain_pem, cert.CertKeyPem, i['CryptoType']))
        else:
            print(f'{_domain}CNAME验证不通过，请检查后再试')
            print('参考值应为：'+i['proxydomain'] + f'.{PROXY_DOMAIN}.\n')
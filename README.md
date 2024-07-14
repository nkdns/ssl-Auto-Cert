# 关于部署环境
> 要求python版本>3.7
> 引用模块版本
> 在根目录使用 pip install -r requirements.txt 安装依赖

    acme==2.7.4
    cryptography==3.2.1
    josepy==1.13.0
    pyOpenSSL==19.1.0
    dnspython==2.3.0
    PyMySQL==1.0.2
    python-dotenv==0.21.0
    requests==2.28.1

---

# 关于.env文件需要的参数
    DB_HOSTNAME = ''
    DB_PORT = 3306
    DB_USER = ''
    DB_PASSWORD = ''
    DB_DB = ''
    DNS_DNSPOD_SECRET_ID = ''
    DNS_DNSPOD_SECRET_KEY = ''
    PROXY_DOMAIN = 'examples.cn'
    ENVIRONMENT = 'formal'
### 解释上述内容
* DB_系列
    > 用于配置保存证书的各项信息的mysql数据库的连接内容
    * DB_HOSTNAME
        > mysql的ip/域名
    * DB_PORT
        > mysql使用的端口，默认3306
    * DB_USER
    * DB_PASSWORD
        > 登录mysql使用的用户名和密码
    * DB_DB
        > 连接到具体的数据库
* DNS_系列
    * DNS_DNSPOD_SECRET_ID
    * DNS_DNSPOD_SECRET_KEY
        > 腾讯云dnspod密钥
        > [点击这里申请](https://console.dnspod.cn/account/token/token)
* PROXY_DOMAIN
    > 用于代理dns挑战
    ```
    ssl证书允许用其他域名代理申请，例如我有A.com这个域名，
    其他用户的B.cn想申请证书，但是他不会配置dns，也不会获取dns配置的api，
    我们就可以用自己的域名代理他的挑战，他只要想办法配置一次cname到我们的域名上就可以了。
    我使用的结构是_acme-challenge.[标识].A.com
    也就是说他需要将他申请证书的域名cname到这个域名上
    例如：
    *.B.cn 则将 _acme-challenge.B.cn cname到我的代理上
    我就可以通知CA机构在我方域名上为他的域名做挑战
    ```
    >关于代理详情可以参考官方文档
    [利用Let's Encrypt和ACME自动化吸引客户](https://letsencrypt.org/2019/10/09/onboarding-your-customers-with-lets-encrypt-and-acme)
* ENVIRONMENT
    > 用于标识环境，为'formal'时则是正式环境，由于letsencrypt有[速率限制](https://letsencrypt.org/zh-cn/docs/rate-limits/)，如果想测试签发证书，请将此处留空,程序会自动使用[测试环境](https://letsencrypt.org/zh-cn/docs/staging-environment/)。签发正式证书请设置为'formal'

---

# 关于数据库结构介绍
> 本系统会在DB_DB中指定的数据库中创建如下三个表，并且每次执行都会检查格式，如果格式与预设不符，会直接删除重建，所以请确保库区干净，或自行修改表名称

* certbase
    > 记录要申请证书的域名、代理域名、时间节点、证书加密类型
* certinfo
    > 记录生成的证书、私钥、起止时间
* certinfo_test
    > 结构与certinfo相同，用于存储测试环境生成的证书

---

# 关于测试模式的介绍
> 请在index.py中找到以下代码

    '''python
    if(ENVIRONMENT=='formal'):
            current_time = datetime.datetime.now()
            thirty_days_ago = current_time + datetime.timedelta(days=30)
            query = "SELECT * FROM certbase WHERE lastexpiredTime <= %s OR lastexpiredTime IS NULL"
            certificate_list = sqlc.Select(query,(thirty_days_ago,))
        else:
            query = "SELECT * FROM certbase WHERE domain = %s"
            certificate_list = sqlc.Select(query,("",))
    '''
> 在 certificate_list = sqlc.Select(query,("[domain]",))中配置domain，该值对应数据库certbase表中的domain，这将指定测试环境中所使用的域名
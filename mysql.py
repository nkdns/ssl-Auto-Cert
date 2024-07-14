import pymysql
# 连接数据库
class mysql:
    def __init__(self,_host:str,_user:str,_password:str,_db:str,_port:int=3306):
        self.conn = pymysql.connect(host = _host,port = _port,user = _user,password = _password,db=_db,charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor)
        self.cursor = self.conn.cursor()

    def tablealive(self,_table_name):
        print('检查数据表是否存在')
        table_exists_query = f"SHOW TABLES LIKE '{_table_name}'"
        self.cursor.execute(table_exists_query)
        result = self.cursor.fetchone()
        if result:
            print(f"数据表 '{_table_name}' 存在.")
            return True
        else:
            print(f"数据表 '{_table_name}' 不存在.")
            return False
    
    def CheckTableFields(self,_table_name,_table_fields):
        print('检查数据表字段是否合格')
        _status = True
        table_fields_query = f"DESCRIBE {_table_name}"
        self.cursor.execute(table_fields_query)
        table_structure = self.cursor.fetchall()
        # 将表字段名称和类型存储到字典中
        table_columns = {column['Field']: column['Type'] for column in table_structure}
        for field in _table_fields:
            field_parts = field.split()
            field_name = field_parts[0]
            field_type = field_parts[1].lower()
            if field_name not in table_columns:
                print(f"字段 '{field_name}' 不存在于数据表中")
                _status = False
                break
            else:
                if field_type != table_columns[field_name]:
                    print(f"字段 '{field_name}' 的类型不符合要求")
                    _status = False
                    break
                else:
                    print(f"字段 '{field_name}' 符合要求")
        if _status:
            print(f'表{_table_name}所有字段检查合格')
        return _status

    def AddTable(self,_table_name,_required_fields):
        create_table_query = f"CREATE TABLE {_table_name} ({', '.join(_required_fields)})"
        self.cursor.execute(create_table_query)
        print(f"表 '{_table_name}' 已创建.")
        self.conn.commit()

    def DelTable(self,_table_name):
        self.cursor.execute(f"DROP TABLE {_table_name}")
        print(f"表 '{_table_name}' 已删除.")
        self.conn.commit()

    def Select(self,query,body):
        self.cursor.execute(query,body)
        results = self.cursor.fetchall()
        return results

    def IORUnsert(self,query,body):
        self.cursor.execute(query,body)
        self.conn.commit()

    def __del__(self):
        self.cursor.close()
        self.conn.close()

def init(HOSTNAME,USER,PASSWORD,DB,port:int=3306):
    sqlc = mysql(HOSTNAME,USER,PASSWORD,DB,port)
    _tablestatus = sqlc.tablealive('certbase')
    certbase_fields = [
        'id INT(11) AUTO_INCREMENT PRIMARY KEY',
        'domain VARCHAR(255)',
        'email VARCHAR(255)',
        'proxydomain VARCHAR(255)',
        'createTime DATETIME',
        'updateTime DATETIME',
        'lastexpiredTime DATETIME',
        'CryptoType TINYTEXT'
    ]
    if _tablestatus:
        _fieldsstatus = sqlc.CheckTableFields('certbase',certbase_fields)
        if _fieldsstatus:
            pass
        else:
            sqlc.DelTable('certbase')
            sqlc.AddTable('certbase',certbase_fields)
    else:
        sqlc.AddTable('certbase',certbase_fields)
    
    _tablestatus = sqlc.tablealive('certinfo')
    cert_fields = [
        'id INT(11) AUTO_INCREMENT PRIMARY KEY',
        'cert_group_id INT(11)',
        'domain VARCHAR(255)',
        'createTime DATETIME',
        'expiredTime DATETIME',
        'fullchain LONGTEXT',
        'certKey LONGTEXT',
        'CryptoType TINYTEXT'
    ]
    if _tablestatus:
        _fieldsstatus = sqlc.CheckTableFields('certinfo',cert_fields)
        if _fieldsstatus:
            pass
        else:
            sqlc.DelTable('certinfo')
            sqlc.AddTable('certinfo',cert_fields)
    else:
        sqlc.AddTable('certinfo',cert_fields)

    _tablestatus = sqlc.tablealive('certinfo_test')
    cert_fields = [
        'id INT(11) AUTO_INCREMENT PRIMARY KEY',
        'cert_group_id INT(11)',
        'domain VARCHAR(255)',
        'createTime DATETIME',
        'expiredTime DATETIME',
        'fullchain LONGTEXT',
        'certKey LONGTEXT',
        'CryptoType TINYTEXT'
    ]
    if _tablestatus:
        _fieldsstatus = sqlc.CheckTableFields('certinfo_test',cert_fields)
        if _fieldsstatus:
            pass
        else:
            sqlc.DelTable('certinfo_test')
            sqlc.AddTable('certinfo_test',cert_fields)
    else:
        sqlc.AddTable('certinfo_test',cert_fields)

    return sqlc

